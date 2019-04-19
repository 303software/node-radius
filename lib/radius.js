const fs = require('fs');
const util = require('util');
const crypto = require('crypto');
const path = require('path');

const {
  code_map,
  uses_random_authenticator,
  is_request_code,
  common_attributes,
} = require('./common');

const {
  NOT_LOADED,
  LOADED,
  NO_VENDOR,
  ATTR_ID,
  ATTR_NAME,
  ATTR_TYPE,
  ATTR_ENUM,
  ATTR_REVERSE_ENUM,
  ATTR_MODIFIERS,
  AUTH_START,
  AUTH_END,
  AUTH_LENGTH,
  MESSAGE_AUTHENTICATOR_LENGTH,
} = require('./constants');

let attributes_map = {};
let vendor_name_to_id = {};
const dictionary_locations = [path.normalize(`${__dirname}/../dictionaries`)];

let dictionaries_state = NOT_LOADED;

function calculate_message_authenticator(packet, secret) {
  const hmac = crypto.createHmac('md5', secret);
  hmac.update(packet);
  return Buffer.from(hmac.digest('binary'), 'binary');
}

function calculate_packet_checksum(packet, secret) {
  const hasher = crypto.createHash('md5');
  hasher.update(packet);
  hasher.update(secret);
  return Buffer.from(hasher.digest('binary'), 'binary');
}

function InvalidSecretError(msg, decoded, constr) {
  Error.captureStackTrace(this, constr || this);
  this.message = msg || 'Error';
  this.decoded = decoded;
}

util.inherits(InvalidSecretError, Error);
InvalidSecretError.prototype.name = 'Invalid Secret Error';

function add_dictionary(file) {
  dictionary_locations.push(path.resolve(file));
}

function load_dictionaries() {
  if (dictionaries_state == LOADED) {
    return;
  }

  dictionary_locations.forEach((file) => {
    if (!fs.existsSync(file)) {
      throw new Error(`Invalid dictionary location: ${file}`);
    }

    if (fs.statSync(file).isDirectory()) {
      const files = fs.readdirSync(file);
      for (let j = 0; j < files.length; j++) {
        this.load_dictionary(`${file}/${files[j]}`);
      }
    } else {
      this.load_dictionary(file);
    }
  });

  dictionaries_state = LOADED;
}

function load_dictionary(file, seen_files) {
  file = path.normalize(file);

  if (seen_files === undefined) {
    seen_files = {};
  }

  if (seen_files[file]) {
    return;
  }

  seen_files[file] = true;

  const includes = this._load_dictionary(fs.readFileSync(file, 'ascii'));
  includes.forEach((i) => {
    this.load_dictionary(path.join(path.dirname(file), i), seen_files);
  });
}

function init_entry(vendor, attr_id) {
  if (!attributes_map[vendor]) {
    attributes_map[vendor] = {};
  }

  if (!attributes_map[vendor][attr_id]) {
    attributes_map[vendor][attr_id] = [null, null, null, {}, {}, {}];
  }
}

function _load_dictionary(content) {
  const lines = content.split('\n');

  let vendor = NO_VENDOR; const includes = [];
  let attr_vendor;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    line = line.replace(/#.*/, '').replace(/\s+/g, ' ');

    let match = line.match(/^\s*VENDOR\s+(\S+)\s+(\d+)/);
    if (match) {
      vendor_name_to_id[match[1]] = match[2];
      continue;
    }

    if ((match = line.match(/^\s*BEGIN-VENDOR\s+(\S+)/))) {
      vendor = vendor_name_to_id[match[1]];
      continue;
    }

    if (line.match(/^\s*END-VENDOR/)) {
      vendor = NO_VENDOR;
      continue;
    }

    match = line.match(/^\s*(?:VENDORATTR\s+(\d+)|ATTRIBUTE)\s+(\S+)\s+(\d+)\s+(\S+)\s*(.+)?/);
    if (match) {
      attr_vendor = vendor;
      if (match[1] !== undefined) {
        attr_vendor = match[1];
      }

      const modifiers = {};
      if (match[5] !== undefined) {
        match[5].replace(/\s*/g, '').split(',').forEach((m) => {
          modifiers[m] = true;
        });
      }

      init_entry(attr_vendor, match[3]);

      attributes_map[attr_vendor][match[3]][ATTR_ID] = match[3];
      attributes_map[attr_vendor][match[3]][ATTR_NAME] = match[2];
      attributes_map[attr_vendor][match[3]][ATTR_TYPE] = match[4].toLowerCase();
      attributes_map[attr_vendor][match[3]][ATTR_MODIFIERS] = modifiers;

      const by_name = attributes_map[attr_vendor][match[2]];
      if (by_name !== undefined) {
        const by_index = attributes_map[attr_vendor][match[3]];
        [ATTR_ENUM, ATTR_REVERSE_ENUM].forEach((field) => {
          Object
            .keys(by_name[field])
            .forEach((name) => {
              by_index[field][name] = by_name[field][name];
            });
        });
      }
      attributes_map[attr_vendor][match[2]] = attributes_map[attr_vendor][match[3]];

      continue;
    }

    match = line.match(/^\s*(?:VENDOR)?VALUE\s+(\d+)?\s*(\S+)\s+(\S+)\s+(\d+)/);
    if (match) {
      attr_vendor = vendor;
      if (match[1] !== undefined) {
        attr_vendor = match[1];
      }

      init_entry(attr_vendor, match[2]);

      attributes_map[attr_vendor][match[2]][ATTR_ENUM][match[4]] = match[3];
      attributes_map[attr_vendor][match[2]][ATTR_REVERSE_ENUM][match[3]] = match[4];

      continue;
    }

    if ((match = line.match(/^\s*\$INCLUDE\s+(.*)/))) {
      includes.push(match[1]);
    }
  }

  return includes;
}

function unload_dictionaries() {
  attributes_map = {};
  vendor_name_to_id = {};
  dictionaries_state = NOT_LOADED;
}

function attr_name_to_id(attr_name, vendor_id) {
  return this._attr_to(attr_name, vendor_id, ATTR_ID);
}

function attr_id_to_name(attr_name, vendor_id) {
  return this._attr_to(attr_name, vendor_id, ATTR_NAME);
}

function _attr_to(attr, vendor_id, target) {
  if (vendor_id === undefined) {
    vendor_id = NO_VENDOR;
  }

  return (attributes_map[vendor_id] && attributes_map[vendor_id][attr])
    ? attributes_map[vendor_id][attr][target]
    : undefined;
}

const reverse_code_map = Object.keys(code_map)
  .reduce((reverse_map, code) => {
    reverse_map[code_map[code]] = code;
    if (code_map[code].match(/Request/)) {
      is_request_code[code_map[code]] = true;
    }
    return reverse_map;
  }, {});

function error(error_msg) {
  let err = error_msg;
  if (typeof (error_msg) === 'string') {
    err = new Error(error_msg);
  }

  return err;
}

// this is a convenience method, "decode({..., no_secret: true})" will also do the job
function decode_without_secret(args) {
  // copy args' fields without modifiying the orginal
  const nargs = {
    no_secret: true,
    ...args,
  };
  return this.decode(nargs, this._decode);
}

function decode(args) {
  this.load_dictionaries();

  const { packet } = args;
  if (!packet || packet.length < 4) {
    throw error('decode: packet too short');
  }

  const ret = {};

  ret.code = code_map[packet.readUInt8(0)];

  if (!ret.code) {
    throw error(`decode: invalid packet code '${packet.readUInt8(0)}'`);
  }

  ret.identifier = packet.readUInt8(1);
  ret.length = packet.readUInt16BE(2);

  if (packet.length < ret.length) {
    throw error('decode: incomplete packet');
  }

  ret.authenticator = packet.slice(AUTH_START, AUTH_END);
  this.authenticator = ret.authenticator;
  this.no_secret = args.no_secret;
  this.secret = args.secret;

  const attrs = packet.slice(AUTH_END, ret.length);
  ret.attributes = {};
  ret.raw_attributes = [];

  this.decode_attributes(attrs, ret.attributes, NO_VENDOR, ret.raw_attributes);

  if (!uses_random_authenticator[ret.code] && is_request_code[ret.code] && !args.no_secret) {
    const orig_authenticator = Buffer.alloc(AUTH_LENGTH);
    packet.copy(orig_authenticator, 0, AUTH_START, AUTH_END);
    packet.fill(0, AUTH_START, AUTH_END);

    const checksum = calculate_packet_checksum(packet, args.secret);
    orig_authenticator.copy(packet, AUTH_START);

    if (checksum.toString() != this.authenticator.toString()) {
      throw error(new InvalidSecretError('decode: authenticator mismatch (possible shared secret mismatch)', ret));
    }
  }

  if (is_request_code[ret.code]
    && ret.attributes[common_attributes.MESSAGE_AUTHENTICATOR]
    && !args.no_secret) {
    this._verify_request_message_authenticator(args, ret);
  }

  return ret;
}

function zero_out_message_authenticator(attributes) {
  const ma_id = this.attr_name_to_id(common_attributes.MESSAGE_AUTHENTICATOR);
  const new_attrs = attributes.slice(0);
  for (let i = 0; i < new_attrs.length; i++) {
    const attr = new_attrs[i];
    if (attr[0] == ma_id) {
      new_attrs[i] = [ma_id, Buffer.alloc(MESSAGE_AUTHENTICATOR_LENGTH)];
      new_attrs[i][1].fill(0x00);
      break;
    }
  }
  return new_attrs;
}

function _verify_request_message_authenticator(args, request) {
  const reencoded = this.encode({
    code: request.code,
    attributes: this.zero_out_message_authenticator(request.raw_attributes),
    identifier: request.identifier,
    secret: args.secret,
  });

  request.authenticator.copy(reencoded, AUTH_START);

  const orig_ma = request.attributes[common_attributes.MESSAGE_AUTHENTICATOR];
  const expected_ma = calculate_message_authenticator(reencoded, args.secret);

  if (orig_ma.toString() != expected_ma.toString()) {
    throw error(new InvalidSecretError('decode: Message-Authenticator mismatch (possible shared secret mismatch)', request));
  }
}

function verify_response(args) {
  this.load_dictionaries();

  if (!args || !Buffer.isBuffer(args.request) || !Buffer.isBuffer(args.response)) {
    throw error('verify_response: must provide raw request and response packets');
  }

  if (args.secret == null) {
    throw error('verify_response: must specify shared secret');
  }

  // first verify authenticator
  const got_checksum = Buffer.alloc(AUTH_LENGTH);
  args.response.copy(got_checksum, 0, AUTH_START, AUTH_END);
  args.request.copy(args.response, AUTH_START, AUTH_START, AUTH_END);

  const expected_checksum = calculate_packet_checksum(args.response, args.secret);
  got_checksum.copy(args.response, AUTH_START);

  if (expected_checksum.toString() != args.response.slice(AUTH_START, AUTH_END).toString()) {
    return false;
  }

  return this._verify_response_message_authenticator(args);
}

function _verify_response_message_authenticator(args) {
  const parsed_request = this.decode({
    packet: args.request,
    secret: args.secret,
  });

  if (parsed_request.attributes[common_attributes.MESSAGE_AUTHENTICATOR]) {
    const parsed_response = this.decode({
      packet: args.response,
      secret: args.secret,
    });

    const got_ma = parsed_response.attributes[common_attributes.MESSAGE_AUTHENTICATOR];
    if (!got_ma) {
      return false;
    }

    const expected_response = this.encode({
      secret: args.secret,
      code: parsed_response.code,
      identifier: parsed_response.identifier,
      attributes: this.zero_out_message_authenticator(parsed_response.raw_attributes),
    });
    parsed_request.authenticator.copy(expected_response, AUTH_START);
    const expected_ma = calculate_message_authenticator(expected_response, args.secret);
    if (expected_ma.toString() != got_ma.toString()) {
      return false;
    }
  }

  return true;
}

function decode_attributes(data, attr_hash, vendor, raw_attrs) {
  let type;
  let length;
  let value;
  let tag;
  while (data.length > 0) {
    type = data.readUInt8(0);
    length = data.readUInt8(1);
    value = data.slice(2, length);
    tag = undefined;

    if (length < 2) {
      throw new Error(`invalid attribute length: ${length}`);
    }

    if (raw_attrs) {
      raw_attrs.push([type, value]);
    }

    data = data.slice(length);
    const attr_info = attributes_map[vendor] && attributes_map[vendor][type];
    if (!attr_info) {
      continue;
    }

    if (attr_info[ATTR_MODIFIERS].has_tag) {
      const first_byte = value.readUInt8(0);
      if (first_byte <= 0x1F) {
        tag = first_byte;
        value = value.slice(1);
      }
    }

    if (attr_info[ATTR_MODIFIERS]['encrypt=1']) {
      value = this.decrypt_field(value);
    } else {
      switch (attr_info[ATTR_TYPE]) {
        case 'string':
        case 'text':
        // assumes utf8 encoding for strings
          value = value.toString('utf8');
          break;
        case 'ipaddr': {
          const octets = [];
          for (let i = 0; i < value.length; i++) {
            octets.push(value[i]);
          }
          value = octets.join('.');
          break;
        }
        case 'date':
          value = new Date(value.readUInt32BE(0) * 1000);
          break;
        case 'time':
        case 'integer':
          if (attr_info[ATTR_MODIFIERS].has_tag) {
            const buf = Buffer.from([0, 0, 0, 0]);
            value.copy(buf, 1);
            value = buf;
          }

          value = value.readUInt32BE(0);
          value = attr_info[ATTR_ENUM][value] || value;
          break;
        default:
          break;
      }

      if (attr_info[ATTR_NAME] == common_attributes.VENDOR_SPECIFIC) {
        if (value[0] !== 0x00) {
          throw new Error('Invalid vendor id');
        }

        let vendor_attrs = attr_hash[common_attributes.VENDOR_SPECIFIC];
        if (!vendor_attrs) {
          attr_hash[common_attributes.VENDOR_SPECIFIC] = {};
          vendor_attrs = attr_hash[common_attributes.VENDOR_SPECIFIC];
        }

        this.decode_attributes(value.slice(4), vendor_attrs, value.readUInt32BE(0));
        continue;
      }
    }

    if (tag !== undefined) {
      value = [tag, value];
    }

    if (attr_hash[attr_info[ATTR_NAME]] !== undefined) {
      if (!(attr_hash[attr_info[ATTR_NAME]] instanceof Array)) {
        attr_hash[attr_info[ATTR_NAME]] = [attr_hash[attr_info[ATTR_NAME]]];
      }

      attr_hash[attr_info[ATTR_NAME]].push(value);
    } else {
      attr_hash[attr_info[ATTR_NAME]] = value;
    }
  }
}

function decrypt_field(field) {
  if (this.no_secret) {
    return null;
  }

  if (field.length < 16) {
    throw new Error('Invalid password: too short');
  }

  if (field.length > 128) {
    throw new Error('Invalid password: too long');
  }

  if (field.length % 16 != 0) {
    throw new Error('Invalid password: not padded');
  }

  const decrypted = this._crypt_field(field, true);
  if (decrypted === null) return null;
  return decrypted.toString('utf8');
}

function encrypt_field(field) {
  const len = Buffer.byteLength(field, 'utf8');
  const buf = Buffer.alloc(len + 15 - ((15 + len) % 16));
  buf.write(field, 0, len);

  // null-out the padding
  for (let i = len; i < buf.length; i++) {
    buf[i] = 0x00;
  }

  return this._crypt_field(buf, false);
}

function _crypt_field(field, is_decrypt) {
  let ret = Buffer.alloc(0);
  let second_part_to_be_hashed = this.authenticator;

  if (this.secret === undefined) {
    throw new Error('Must provide RADIUS shared secret');
  }

  for (let i = 0; i < field.length; i += 16) {
    const hasher = crypto.createHash('md5');
    hasher.update(this.secret);
    hasher.update(second_part_to_be_hashed);
    const hash = Buffer.from(hasher.digest('binary'), 'binary');

    let xor_result = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) {
      xor_result[j] = field[i + j] ^ hash[j];
      if (is_decrypt && xor_result[j] == 0x00) {
        xor_result = xor_result.slice(0, j);
        break;
      }
    }
    ret = Buffer.concat([ret, xor_result]);
    second_part_to_be_hashed = is_decrypt ? field.slice(i, i + 16) : xor_result;
  }

  return ret;
}

function encode_response(args) {
  this.load_dictionaries();

  const { packet } = args;
  if (!packet) {
    throw error('encode_response: must provide packet');
  }

  if (!args.attributes) {
    args.attributes = [];
  }

  const proxy_state_id = this.attr_name_to_id('Proxy-State');
  for (let i = 0; i < packet.raw_attributes.length; i++) {
    const attr = packet.raw_attributes[i];
    if (attr[0] == proxy_state_id) {
      args.attributes.push(attr);
    }
  }

  const response = this.encode({
    code: args.code,
    identifier: packet.identifier,
    authenticator: packet.authenticator,
    attributes: args.attributes,
    secret: args.secret,
    add_message_authenticator: packet.attributes[common_attributes.MESSAGE_AUTHENTICATOR] != null,
  });

  return response;
}

function encode(args) {
  this.load_dictionaries();

  if (!args || args.code === undefined) {
    throw error('encode: must specify code');
  }

  if (args.secret === undefined) {
    throw error('encode: must provide RADIUS shared secret');
  }

  const packet = Buffer.alloc(4096);
  let offset = 0;

  const code = reverse_code_map[args.code];
  if (code === undefined) {
    throw error(`encode: invalid packet code '${args.code}'`);
  }

  packet.writeUInt8(+code, offset++);

  let { identifier } = args;
  if (identifier === undefined) {
    identifier = Math.floor(Math.random() * 256);
  }
  if (identifier > 255) {
    throw error('encode: identifier too large');
  }
  packet.writeUInt8(identifier, offset++);

  // save room for length
  offset += 2;

  let { authenticator } = args;

  if (!authenticator) {
    if (uses_random_authenticator[args.code]) {
      authenticator = crypto.randomBytes(AUTH_LENGTH);
    } else {
      authenticator = Buffer.alloc(AUTH_LENGTH);
      authenticator.fill(0x00);
    }
  }

  return this._encode_with_authenticator(args, packet, offset, authenticator);
}

function _encode_with_authenticator(args, packet, offset, authenticator) {
  authenticator.copy(packet, offset);
  offset += AUTH_LENGTH;

  this.secret = args.secret;
  this.no_secret = false;
  this.authenticator = authenticator;

  args.attributes = this.ensure_array_attributes(args.attributes);

  let { add_message_authenticator } = args;
  if (add_message_authenticator == null) {
    const eap_id = this.attr_name_to_id(common_attributes.EAP_MESSAGE);
    const ma_id = this.attr_name_to_id(common_attributes.MESSAGE_AUTHENTICATOR);
    for (let i = 0; i < args.attributes.length; i++) {
      const attr_id = args.attributes[i][0];
      if (attr_id == eap_id || attr_id == common_attributes.EAP_MESSAGE) {
        add_message_authenticator = true;
      } else if (attr_id == ma_id || attr_id == common_attributes.MESSAGE_AUTHENTICATOR) {
        add_message_authenticator = false;
        break;
      }
    }
    if (add_message_authenticator == null && args.code == 'Status-Server') {
      add_message_authenticator = true;
    }
  }

  if (add_message_authenticator) {
    const empty_authenticator = Buffer.alloc(MESSAGE_AUTHENTICATOR_LENGTH);
    empty_authenticator.fill(0x00);
    args.attributes.push([common_attributes.MESSAGE_AUTHENTICATOR, empty_authenticator]);
  }

  offset += this.encode_attributes(packet.slice(offset), args.attributes, NO_VENDOR);

  // now write the length in
  packet.writeUInt16BE(offset, 2);

  packet = packet.slice(0, offset);

  let message_authenticator;
  if (add_message_authenticator && !is_request_code[args.code]) {
    message_authenticator = calculate_message_authenticator(packet, args.secret);
    message_authenticator.copy(packet, offset - MESSAGE_AUTHENTICATOR_LENGTH);
  }

  if (!uses_random_authenticator[args.code]) {
    calculate_packet_checksum(packet, args.secret).copy(packet, AUTH_START);
  }

  if (add_message_authenticator && is_request_code[args.code]) {
    message_authenticator = calculate_message_authenticator(packet, args.secret);
    message_authenticator.copy(packet, offset - MESSAGE_AUTHENTICATOR_LENGTH);
  }

  return packet;
}

function ensure_array_attributes(attributes) {
  if (!attributes) {
    return [];
  }

  if (typeof (attributes) === 'object' && !Array.isArray(attributes)) {
    return Object
      .keys(attributes)
      .map((name) => {
        const val = attributes[name];
        if (typeof (val) === 'object') {
          throw new Error('Cannot have nested attributes when using hash syntax. Use array syntax instead');
        }
        return [name, val];
      });
  }

  return attributes;
}

function encode_attributes(packet, attributes, vendor) {
  let offset = 0;
  for (let i = 0; i < attributes.length; i++) {
    const attr = attributes[i];
    const attr_info = attributes_map[vendor] && attributes_map[vendor][attr[0]];
    if (!attr_info && !(attr[1] instanceof Buffer)) {
      throw new Error(`${'encode: invalid attributes - must give Buffer for '
        + "unknown attribute '"}${attr[0]}'`);
    }

    let out_value;
    let has_tag;
    let in_value = attr[1];
    if (in_value instanceof Buffer) {
      out_value = in_value;
    } else {
      has_tag = attr_info[ATTR_MODIFIERS].has_tag && attr.length == 3;

      if (has_tag) {
        in_value = attr[2];
      }

      if (attr_info[ATTR_MODIFIERS]['encrypt=1']) {
        out_value = this.encrypt_field(in_value);
      } else {
        switch (attr_info[ATTR_TYPE]) {
          case 'string':
          case 'text':
            if (in_value.length == 0) {
              continue;
            }
            out_value = Buffer.from(`${in_value}`, 'utf8');
            break;
          case 'ipaddr':
            out_value = Buffer.from(in_value.split('.'));
            if (out_value.length != 4) {
              throw new Error(`encode: invalid IP: ${in_value}`);
            }
            break;
          case 'date':
            in_value = Math.floor(in_value.getTime() / 1000);
          case 'time':
          case 'integer':
            out_value = Buffer.alloc(4);

            in_value = attr_info[ATTR_REVERSE_ENUM][in_value] || in_value;
            if (isNaN(in_value)) {
              throw new Error(`envode: invalid attribute value: ${in_value}`);
            }

            out_value.writeUInt32BE(+in_value, 0);

            if (has_tag) {
              out_value = out_value.slice(1);
            }

            break;
          default:
            if (attr_info[ATTR_NAME] != common_attributes.VENDOR_SPECIFIC) {
              throw new Error(`encode: must provide Buffer for attribute '${attr_info[ATTR_NAME]}'`);
            }
        }

        // handle VSAs specially
        if (attr_info[ATTR_NAME] == common_attributes.VENDOR_SPECIFIC) {
          const vendor_id = isNaN(attr[1]) ? vendor_name_to_id[attr[1]] : attr[1];
          if (vendor_id === undefined) {
            throw new Error(`encode: unknown vendor '${attr[1]}'`);
          }

          // write the attribute id
          packet.writeUInt8(+attr_info[ATTR_ID], offset++);

          const length = this.encode_attributes(packet.slice(offset + 5), attr[2], vendor_id);

          // write in the length
          packet.writeUInt8(2 + 4 + length, offset++);
          // write in the vendor id
          packet.writeUInt32BE(+vendor_id, offset);
          offset += 4;

          offset += length;
          continue;
        }
      }
    }

    // write the attribute id
    packet.writeUInt8(attr_info ? +attr_info[ATTR_ID] : +attr[0], offset++);

    // write in the attribute length
    packet.writeUInt8(2 + out_value.length + (has_tag ? 1 : 0), offset++);

    if (has_tag) {
      packet.writeUInt8(attr[1], offset++);
    }

    // copy in the attribute value
    out_value.copy(packet, offset);
    offset += out_value.length;
  }

  return offset;
}

const Radius = {
  InvalidSecretError,
  add_dictionary,
  load_dictionaries,
  load_dictionary,
  _load_dictionary,
  unload_dictionaries,
  attr_name_to_id,
  attr_id_to_name,
  _attr_to,
  decode_without_secret,
  decode,
  calculate_message_authenticator,
  zero_out_message_authenticator,
  _verify_request_message_authenticator,
  verify_response,
  _verify_response_message_authenticator,
  decode_attributes,
  decrypt_field,
  encrypt_field,
  _crypt_field,
  encode_response,
  encode,
  _encode_with_authenticator,
  ensure_array_attributes,
  encode_attributes,
  vendor_name_to_id: vendor_name => vendor_name_to_id[vendor_name],
};

module.exports = Radius;
