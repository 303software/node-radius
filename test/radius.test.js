const { testCase } = require('nodeunit');
const fs = require('fs');
const crypto = require('crypto');
const radius = require('../lib/radius');

let secret;

let test_args = {};

module.exports = testCase({
  setUp(callback) {
    secret = 'nearbuy';
    callback();
  },
  tearDown(callback) {
    radius.unload_dictionaries();
    callback();
  },

  test_decode_mac_auth(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/aruba_mac_auth.packet`);

    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.aruba`);

    const decoded = radius.decode({ packet: raw_packet, secret });

    test.equal(decoded.code, 'Access-Request');
    test.equal(decoded.identifier, 58);
    test.equal(decoded.length, 208);

    const expected_attrs = {
      'NAS-IP-Address': '10.0.0.90',
      'NAS-Port': 0,
      'NAS-Port-Type': 'Wireless-802.11',
      'User-Name': '7c:c5:37:ff:f8:af',
      'User-Password': '7c:c5:37:ff:f8:af',
      'Calling-Station-Id': '7CC537FFF8AF',
      'Called-Station-Id': '000B86F02068',
      'Service-Type': 'Login-User',
      'Vendor-Specific': {
        'Aruba-Essid-Name': 'muir-aruba-guest',
        'Aruba-Location-Id': '00:1a:1e:c6:b0:ca',
        'Aruba-AP-Group': 'cloud-cp',
      },
      'Message-Authenticator': Buffer.from('f8a12329c7ed5a6e2568515243efb918', 'hex'),
    };
    test.deepEqual(decoded.attributes, expected_attrs);

    test.done();
  },

  test_decode_mac_auth_without_secret(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/aruba_mac_auth.packet`);

    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.aruba`);

    let decoded = radius.decode_without_secret({ packet: raw_packet });

    test.equal(decoded.code, 'Access-Request');
    test.equal(decoded.identifier, 58);
    test.equal(decoded.length, 208);

    const expected_attrs = {
      'NAS-IP-Address': '10.0.0.90',
      'NAS-Port': 0,
      'NAS-Port-Type': 'Wireless-802.11',
      'User-Name': '7c:c5:37:ff:f8:af',
      'User-Password': null, // this is an encrypted field, and so cannot be read without the password
      'Calling-Station-Id': '7CC537FFF8AF',
      'Called-Station-Id': '000B86F02068',
      'Service-Type': 'Login-User',
      'Vendor-Specific': {
        'Aruba-Essid-Name': 'muir-aruba-guest',
        'Aruba-Location-Id': '00:1a:1e:c6:b0:ca',
        'Aruba-AP-Group': 'cloud-cp',
      },
      'Message-Authenticator': Buffer.from('f8a12329c7ed5a6e2568515243efb918', 'hex'),
    };
    test.deepEqual(decoded.attributes, expected_attrs);

    decoded = radius.decode({
      secret,
      packet: radius.encode({
        secret,
        code: 'Access-Request',
        attributes: {
          'User-Name': 'Caenogaean-asphyxia',
          'User-Password': 'barratry-Wertherism',
        },
      }),
    });

    test.equal(decoded.attributes['User-Password'], 'barratry-Wertherism');

    test.done();
  },

  // make sure everthing is fine with no dictionaries
  test_decode_no_dicts(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/aruba_mac_auth.packet`);

    radius.unload_dictionaries();
    const orig_load = radius.load_dictionary;
    radius.load_dictionary = function load_dictionary() { };

    const decoded = radius.decode({ packet: raw_packet, secret });

    test.equal(decoded.code, 'Access-Request');
    test.equal(decoded.identifier, 58);
    test.equal(decoded.length, 208);

    // no pretty attributes
    test.deepEqual(decoded.attributes, {});

    const expected_raw_attrs = [
      [4, Buffer.from([10, 0, 0, 90])],
      [5, Buffer.from([0, 0, 0, 0])],
      [61, Buffer.from([0, 0, 0, 19])],
      [1, Buffer.from('7c:c5:37:ff:f8:af')],
      [2, Buffer.from('eb2ef7e83ec1a05e04fb5c6d91e088569a990fa2b1b2dc6a0f048596081164cd', 'hex')],
      [31, Buffer.from('7CC537FFF8AF')],
      [30, Buffer.from('000B86F02068')],
      [6, Buffer.from([0, 0, 0, 1])],
      [26, Buffer.from('000039e705126d7569722d61727562612d6775657374', 'hex')],
      [26, Buffer.from('000039e7061330303a31613a31653a63363a62303a6361', 'hex')],
      [26, Buffer.from('000039e70a0a636c6f75642d6370', 'hex')],
      [80, Buffer.from('f8a12329c7ed5a6e2568515243efb918', 'hex')],
    ];

    test.deepEqual(decoded.raw_attributes, expected_raw_attrs);

    radius.load_dictionary = orig_load;

    test.done();
  },

  // can make a "naked" packet
  test_encode_access_request(test) {
    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.aruba`);

    const attributes = [
      ['User-Name', 'ornithopter-aliptic'],
      ['User-Password', 'nucleohistone-overwilily'],
      ['Service-Type', 'Login-User'],
      ['NAS-IP-Address', '169.134.68.136'],

      ['Vendor-Specific', 14823, [
        ['Aruba-User-Role', 'cracked-tylote'],
        [2, 825],
      ]],
      ['Vendor-Specific', 14823, [['Aruba-Essid-Name', 'phene-dentinalgia']]],
    ];
    const packet = radius.encode({
      code: 'Access-Request',
      identifier: 123,
      attributes,
      secret,
    });

    const decoded = radius.decode({ packet, secret });
    test.equal(decoded.code, 'Access-Request');
    test.equal(decoded.identifier, 123);

    const expected_attrs = {
      'User-Name': 'ornithopter-aliptic',
      'User-Password': 'nucleohistone-overwilily',
      'Service-Type': 'Login-User',
      'NAS-IP-Address': '169.134.68.136',
      'Vendor-Specific': {
        'Aruba-User-Role': 'cracked-tylote',
        'Aruba-User-Vlan': 825,
        'Aruba-Essid-Name': 'phene-dentinalgia',
      },
    };
    test.deepEqual(decoded.attributes, expected_attrs);

    test.done();
  },

  test_decode_hash_attributes(test) {
    const attrs = {
      'User-Name': 'ornithopter-aliptic',
      'User-Password': 'nucleohistone-overwilily',
      'Service-Type': 'Login-User',
      'NAS-IP-Address': '169.134.68.136',
    };
    const packet = radius.encode({
      code: 'Access-Request',
      identifier: 123,
      attributes: attrs,
      secret,
    });

    const decoded = radius.decode({ packet, secret });
    test.equal(decoded.code, 'Access-Request');
    test.equal(decoded.identifier, 123);
    test.deepEqual(decoded.attributes, attrs);

    test.done();
  },

  test_throws_on_nested_hash_attributes(test) {
    const attrs = {
      'User-Name': 'ornithopter-aliptic',
      'User-Password': 'nucleohistone-overwilily',
      'Service-Type': 'Login-User',
      'NAS-IP-Address': '169.134.68.136',
      'Vendor-Specific': {
        'Aruba-User-Role': 'cracked-tylote',
        'Aruba-User-Vlan': 825,
        'Aruba-Essid-Name': 'phene-dentinalgia',
      },
    };

    test.throws(() => {
      radius.encode({
        code: 'Access-Request',
        identifier: 123,
        attributes: attrs,
        secret,
      });
    });
    test.done();
  },

  // test that our encoded packet matches bit-for-bit with a "real"
  // RADIUS packet
  test_encode_bit_for_bit(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/aruba_mac_auth.packet`);

    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.aruba`);

    const encoded = radius.encode({
      code: 'Access-Request',
      identifier: 58,
      authenticator: Buffer.from('4a45fae086d9e114286b37b5f371ec6c', 'hex'),
      attributes: [
        ['NAS-IP-Address', '10.0.0.90'],
        ['NAS-Port', 0],
        ['NAS-Port-Type', 'Wireless-802.11'],
        ['User-Name', '7c:c5:37:ff:f8:af'],
        ['User-Password', '7c:c5:37:ff:f8:af'],
        ['Calling-Station-Id', '7CC537FFF8AF'],
        ['Called-Station-Id', '000B86F02068'],
        ['Service-Type', 'Login-User'],
        ['Vendor-Specific', 14823, [['Aruba-Essid-Name', 'muir-aruba-guest']]],
        ['Vendor-Specific', 14823, [['Aruba-Location-Id', '00:1a:1e:c6:b0:ca']]],
        ['Vendor-Specific', 14823, [['Aruba-AP-Group', 'cloud-cp']]],
      ],
      secret,
      add_message_authenticator: true,
    });

    test.equal(encoded.toString('hex'), raw_packet.toString('hex'));

    test.done();
  },

  // encode will choose a random identifier for you if you don't provide one
  test_encode_random_identifer(test) {
    let decoded = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        secret,
      }),
      secret,
    });
    test.ok(decoded.identifier >= 0 && decoded.identifier < 256);

    const starting_id = decoded.identifier;

    // if you are unlucky this is an infinite loop
    while (decoded.identifier != starting_id) {
      decoded = radius.decode({
        packet: radius.encode({
          code: 'Access-Request',
          secret,
        }),
        secret,
      });
    }

    test.ok(true);

    test.done();
  },

  // given a previously decoded packet, prepare a response packet
  test_packet_response(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/cisco_mac_auth.packet`);

    const decoded = radius.decode({ packet: raw_packet, secret });

    const response = radius.encode_response({
      packet: decoded,
      code: 'Access-Reject',
      secret,
    });

    const raw_response = fs.readFileSync(`${__dirname}/captures/cisco_mac_auth_reject.packet`);
    test.equal(response.toString('hex'), raw_response.toString('hex'));

    test.done();
  },

  // response needs to include proxy state
  test_response_include_proxy_state(test) {
    const request_with_proxy = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        secret,
        attributes: [
          ['User-Name', 'ascribe-despairer'],
          ['Proxy-State', Buffer.from('womanhouse-Pseudotsuga')],
          ['User-Password', 'ridiculous'],
          ['Proxy-State', Buffer.from('regretfully-unstability')],
        ],
      }),
      secret,
    });

    const decoded_response = radius.decode({
      packet: radius.encode_response({
        packet: request_with_proxy,
        code: 'Access-Reject',
        secret,
      }),
      secret,
    });

    const expected_raw_attributes = [
      [radius.attr_name_to_id('Proxy-State'), Buffer.from('womanhouse-Pseudotsuga')],
      [radius.attr_name_to_id('Proxy-State'), Buffer.from('regretfully-unstability')],
    ];

    test.deepEqual(decoded_response.raw_attributes, expected_raw_attributes);

    test.done();
  },

  // dont accidentally strip null bytes when encoding
  test_password_encode(test) {
    const decoded = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        authenticator: Buffer.from('426edca213c1bf6e005e90a64105ca3a', 'hex'),
        attributes: [['User-Password', 'ridiculous']],
        secret,
      }),
      secret,
    });

    test.equal(decoded.attributes['User-Password'], 'ridiculous');

    test.done();
  },

  accounting_group: {
    setUp(cb) {
      radius.load_dictionary(`${__dirname}/dictionaries/dictionary.airespace`);

      test_args = {};
      test_args.raw_acct_request = fs.readFileSync(`${__dirname}/captures/cisco_accounting.packet`);
      test_args.expected_acct_attrs = {
        'User-Name': 'user_7C:C5:37:FF:F8:AF_134',
        'NAS-Port': 1,
        'NAS-IP-Address': '10.0.3.4',
        'Framed-IP-Address': '10.2.0.252',
        'NAS-Identifier': 'Cisco 4400 (Anchor)',
        'Vendor-Specific': {
          'Airespace-Wlan-Id': 2,
        },
        'Acct-Session-Id': '4fecc41e/7c:c5:37:ff:f8:af/9',
        'Acct-Authentic': 'RADIUS',
        'Tunnel-Type': [0x00, 'VLAN'],
        'Tunnel-Medium-Type': [0x00, 'IEEE-802'],
        'Tunnel-Private-Group-Id': 5,
        'Acct-Status-Type': 'Start',
        'Calling-Station-Id': '7c:c5:37:ff:f8:af',
        'Called-Station-Id': '00:22:55:90:39:60',
      };
      cb();
    },

    test_accounting(test) {
      const { raw_acct_request } = test_args;
      const decoded = radius.decode({ packet: raw_acct_request, secret });

      const expected_attrs = test_args.expected_acct_attrs;

      test.deepEqual(decoded.attributes, expected_attrs);

      // test we can encode the same packet
      let encoded = radius.encode({
        code: 'Accounting-Request',
        identifier: decoded.identifier,
        secret,
        attributes: [
          ['User-Name', 'user_7C:C5:37:FF:F8:AF_134'],
          ['NAS-Port', 1],
          ['NAS-IP-Address', '10.0.3.4'],
          ['Framed-IP-Address', '10.2.0.252'],
          ['NAS-Identifier', 'Cisco 4400 (Anchor)'],
          ['Vendor-Specific', 'Airespace', [['Airespace-Wlan-Id', 2]]],
          ['Acct-Session-Id', '4fecc41e/7c:c5:37:ff:f8:af/9'],
          ['Acct-Authentic', 'RADIUS'],
          ['Tunnel-Type', 0x00, 'VLAN'],
          ['Tunnel-Medium-Type', 0x00, 'IEEE-802'],
          ['Tunnel-Private-Group-Id', '5'],
          ['Acct-Status-Type', 'Start'],
          ['Calling-Station-Id', '7c:c5:37:ff:f8:af'],
          ['Called-Station-Id', '00:22:55:90:39:60'],
        ],
      });
      test.equal(encoded.toString('hex'), raw_acct_request.toString('hex'));

      const raw_acct_response = fs.readFileSync(`${__dirname
      }/captures/cisco_accounting_response.packet`);
      encoded = radius.encode_response({
        packet: decoded,
        secret,
        code: 'Accounting-Response',
      });
      test.equal(encoded.toString('hex'), raw_acct_response.toString('hex'));

      test.done();
    },

    test_invalid_accounting_packet_authenticator(test) {
      const { raw_acct_request } = test_args;
      const expected_attrs = test_args.expected_acct_attrs;

      // detect invalid accounting packets
      test.throws(() => {
        radius.decode({ packet: raw_acct_request, secret: 'not-secret' });
      });

      try {
        radius.decode({ packet: raw_acct_request, secret: 'not-secret' });
      } catch (err) {
        test.deepEqual(err.decoded.attributes, expected_attrs);
      }
      test.done();
    },
  },

  test_no_empty_strings(test) {
    const decoded = radius.decode({
      secret,
      packet: radius.encode({
        code: 'Access-Request',
        attributes: [['User-Name', '']],
        secret,
      }),
    });

    // don't send empty strings (see RFC2865)
    test.deepEqual(decoded.attributes, {});

    test.done();
  },

  test_repeated_attribute(test) {
    const decoded = radius.decode({
      secret,
      packet: radius.encode({
        secret,
        code: 'Access-Reject',
        attributes: [
          ['Reply-Message', 'message one'],
          ['Reply-Message', 'message two'],
        ],
      }),
    });

    const expected_attrs = {
      'Reply-Message': ['message one', 'message two'],
    };
    test.deepEqual(decoded.attributes, expected_attrs);

    test.done();
  },

  test_dictionary_include(test) {
    radius.unload_dictionaries();
    radius.add_dictionary(`${__dirname}/dictionaries/dictionary.test1`);

    const decoded = radius.decode({
      secret,
      packet: radius.encode({
        secret,
        code: 'Access-Request',
        attributes: [['Attribute-Test1', 'foo'], ['Attribute-Test2', 'bar']],
      }),
    });

    const expected_attrs = {
      'Attribute-Test1': 'foo',
      'Attribute-Test2': 'bar',
    };
    test.deepEqual(decoded.attributes, expected_attrs);

    test.done();
  },

  // make sure we can load the dicts in any order
  test_dictionary_out_of_order(test) {
    const dicts = fs.readdirSync(`${__dirname}/../dictionaries`);

    // make sure we can load any dictionary first
    for (let i = 0; i < dicts.length; i++) {
      radius.unload_dictionaries();
      radius.load_dictionary(`${__dirname}/../dictionaries/${dicts[i]}`);
    }

    // and spot check things actually work loaded out of order
    radius.unload_dictionaries();
    radius.load_dictionary(`${__dirname}/../dictionaries/dictionary.rfc2867`);
    radius.load_dictionary(`${__dirname}/../dictionaries/dictionary.rfc2866`);

    let decoded = radius.decode({
      secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret,
        attributes: [
          ['Acct-Status-Type', 'Tunnel-Reject'],
        ],
      }),
    });

    test.equal(decoded.attributes['Acct-Status-Type'], 'Tunnel-Reject');

    radius.unload_dictionaries();
    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.test_tunnel_type`);
    radius.load_dictionaries();

    decoded = radius.decode({
      secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret,
        attributes: [
          ['Tunnel-Type', 0x00, 'TESTTUNNEL'],
        ],
      }),
    });

    const expected_attrs = { 'Tunnel-Type': [0x00, 'TESTTUNNEL'] };
    test.deepEqual(decoded.attributes, expected_attrs);

    test.done();
  },

  test_zero_identifer(test) {
    const decoded = radius.decode({
      packet: radius.encode({
        secret,
        code: 'Access-Request',
        identifier: 0,
      }),
      secret,
    });

    test.equal(decoded.identifier, 0);
    test.done();
  },

  test_date_type(test) {
    const raw_packet = fs.readFileSync(`${__dirname}/captures/motorola_accounting.packet`);

    const decoded = radius.decode({
      packet: raw_packet,
      secret,
    });

    const epoch = 1349879753;

    test.equal(decoded.attributes['Event-Timestamp'].getTime(), epoch * 1000);

    const encoded = radius.encode({
      code: 'Accounting-Request',
      identifier: decoded.identifier,
      attributes: [
        ['User-Name', '00-1F-3B-8C-3A-15'],
        ['Acct-Status-Type', 'Start'],
        ['Acct-Session-Id', '1970D5A4-001F3B8C3A15-0000000001'],
        ['Calling-Station-Id', '00-1F-3B-8C-3A-15'],
        ['Called-Station-Id', 'B4-C7-99-77-59-D0:muir-moto-guest-site1'],
        ['NAS-Port', 1],
        ['NAS-Port-Type', 'Wireless-802.11'],
        ['NAS-IP-Address', '10.2.0.3'],
        ['NAS-Identifier', 'ap6532-70D5A4'],
        ['NAS-Port-Id', 'radio2'],
        ['Event-Timestamp', new Date(epoch * 1000)],
        ['Tunnel-Type', 0x00, 'VLAN'],
        ['Tunnel-Medium-Type', 0x00, 'IEEE-802'],
        ['Tunnel-Private-Group-Id', '30'],
        ['Acct-Authentic', 'RADIUS'],
      ],
      secret,
    });

    test.equal(encoded.toString('hex'), raw_packet.toString('hex'));

    test.done();
  },

  test_date_type_non_mult_1000_ms(test) {
    let encoded;
    test.doesNotThrow(() => {
      encoded = radius.encode({
        code: 'Accounting-Request',
        identifier: 123,
        attributes: [
          ['Event-Timestamp', new Date(1403025894009)],
        ],
        secret,
      });
    });

    // truncates ms
    const decoded = radius.decode({ packet: encoded, secret });
    test.equal(decoded.attributes['Event-Timestamp'].getTime(), 1403025894000);

    test.done();
  },

  test_disconnect_request(test) {
    const encoded = radius.encode({
      code: 'Disconnect-Request',
      identifier: 54,
      secret,
      attributes: [
        ['User-Name', 'mariticide-inquietation'],
        ['NAS-Identifier', 'Aglauros-charioted'],
      ],
    });

    // check we did the non-user-password authenticator
    const got_authenticator = Buffer.alloc(16);
    encoded.copy(got_authenticator, 0, 4);
    encoded.fill(0, 4, 20);

    const expected_authenticator = Buffer.alloc(16);
    const hasher = crypto.createHash('md5');
    hasher.update(encoded);
    hasher.update(secret);
    expected_authenticator.write(hasher.digest('binary'), 0, 16, 'binary');

    test.equal(got_authenticator.toString('hex'), expected_authenticator.toString('hex'));

    // and make sure we check the authenticator when decoding
    test.throws(() => {
      radius.decode({
        packet: encoded,
        secret,
      });
    });

    expected_authenticator.copy(encoded, 4, 0);
    test.doesNotThrow(() => {
      radius.decode({
        packet: encoded,
        secret,
      });
    });

    test.done();
  },

  test_verify_response(test) {
    const request = radius.encode({
      secret,
      code: 'Accounting-Request',
      attributes: {
        'User-Name': '00-1F-3B-8C-3A-15',
        'Acct-Status-Type': 'Start',
      },
    });

    let response = radius.encode_response({
      secret,
      code: 'Accounting-Response',
      packet: radius.decode({ packet: request, secret }),
    });

    test.ok(radius.verify_response({
      request,
      response,
      secret,
    }));

    test.ok(!radius.verify_response({
      request,
      response,
      secret: 'Calliopsis-misbeholden',
    }));

    // response encoded with wrong secret
    response = radius.encode_response({
      secret: 'moyenne-paraboliform',
      code: 'Accounting-Response',
      packet: radius.decode({ packet: request, secret }),
    });
    test.ok(!radius.verify_response({
      request,
      response,
      secret,
    }));

    test.done();
  },

  test_server_request(test) {
    const encoded1 = radius.encode({
      code: 'Status-Server',
      identifier: 54,
      secret,
      attributes: [
        ['NAS-Identifier', 'symphilism-dicentrine'],
      ],
    });

    const encoded2 = radius.encode({
      code: 'Status-Server',
      identifier: 54,
      secret,
      attributes: [
        ['NAS-Identifier', 'symphilism-dicentrine'],
      ],
    });

    // check we are doing a random authenticator
    const got_authenticator1 = Buffer.alloc(16);
    encoded1.copy(got_authenticator1, 0, 4);

    const got_authenticator2 = Buffer.alloc(16);
    encoded2.copy(got_authenticator2, 0, 4);

    test.notEqual(got_authenticator1.toString(), got_authenticator2.toString());

    const response = radius.encode_response({
      code: 'Access-Accept',
      secret,
      packet: radius.decode({ packet: encoded1, secret }),
    });

    test.ok(radius.verify_response({
      request: encoded1,
      response,
      secret,
    }));

    test.done();
  },

  test_vendor_names_with_numbers(test) {
    radius.load_dictionary(`${__dirname}/dictionaries/dictionary.number_vendor_name`);

    const encoded = radius.encode({
      code: 'Access-Request',
      secret,

      attributes: [
        ['Vendor-Specific', '123Foo', [
          ['1Integer', 478],
          ['1String', 'Zollernia-fibrovasal'],
          ['12345', 'myrmecophagoid-harn'],
        ]],
      ],
    });

    const decoded = radius.decode({
      packet: encoded,
      secret,
    });

    test.equal(radius.vendor_name_to_id('123Foo'), 995486);

    test.deepEqual(decoded.attributes, {
      'Vendor-Specific': {
        '1Integer': 478,
        '1String': 'Zollernia-fibrovasal',
        12345: 'myrmecophagoid-harn',
      },
    });

    test.done();
  },

  message_authenticator_group: {
    setUp(cb) {
      secret = 'testing123';

      test_args = {
        raw_request: fs.readFileSync(`${__dirname}/captures/eap_request.packet`),
      };
      test_args.parsed_request = radius.decode({
        packet: test_args.raw_request,
        secret,
      });
      cb();
    },

    // make sure we calculate the same Message-Authenticator
    test_calculate(test) {
      const attrs_without_ma = test_args.parsed_request.raw_attributes.filter(a => a[0] != radius.attr_name_to_id('Message-Authenticator'));

      const encoded = radius.encode({
        code: test_args.parsed_request.code,
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: attrs_without_ma,
        secret,
      });

      test.equal(encoded.toString('hex'), test_args.raw_request.toString('hex'));

      test.done();
    },

    // encode_response should calculate the appropriate Message-Authenticator
    test_encode_response(test) {
      const response = radius.encode_response({
        code: 'Access-Accept',
        secret,
        packet: test_args.parsed_request,
      });

      const parsed_response = radius.decode({
        packet: response,
        secret,
      });

      // calculate expected Message-Authenticator

      const empty = Buffer.alloc(16);
      empty.fill(0);

      const expected_response = radius.encode({
        code: 'Access-Accept',
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: [['Message-Authenticator', empty]],
        secret,
      });

      // expected_response's authenticator is correct, but Message-Authenticator is wrong
      // (it's all 0s). make sure verify_response checks both
      test.ok(!radius.verify_response({
        request: test_args.raw_request,
        response: expected_response,
        secret,
      }));

      // put back the request's authenticator
      test_args.parsed_request.authenticator.copy(expected_response, 4);

      const expected_ma = radius.calculate_message_authenticator(expected_response, secret);
      test.equal(
        parsed_response.attributes['Message-Authenticator'].toString('hex'),
        expected_ma.toString('hex'),
      );

      test.ok(radius.verify_response({
        request: test_args.raw_request,
        response,
        secret,
      }));

      test.done();
    },

    // response is missing Message-Authenticator, not okay
    test_response_missing_ma(test) {
      const bad_response = radius.encode({
        code: 'Access-Accept',
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: [],
        secret,
      });

      test.ok(!radius.verify_response({
        request: test_args.raw_request,
        response: bad_response,
        secret,
      }));

      test.done();
    },

    // make sure we verify Message-Authenticator when decoding requests
    test_decode_verify(test) {
      test.throws(() => {
        radius.decode({
          packet: test_args.raw_request,
          secret: 'wrong secret',
        });
      });

      test.done();
    },
  },

  test_utf8_strings(test) {
    const encoded = radius.encode({
      secret: '密码',
      code: 'Access-Request',
      attributes: {
        'User-Name': '金庸先生',
        'User-Password': '降龙十八掌',
      },
    });

    const decoded = radius.decode({
      packet: encoded,
      secret: '密码',
    });

    test.deepEqual({
      'User-Name': '金庸先生',
      'User-Password': '降龙十八掌',
    }, decoded.attributes);

    test.done();
  },

  test_invalid_packet_attribute_length(test) {
    const invalid_packet = fs.readFileSync(`${__dirname}/captures/invalid_register.packet`);
    const raw_packet = fs.readFileSync(`${__dirname}/captures/aruba_mac_auth.packet`);

    // should fail decode packet attributes
    test.throws(() => {
      radius.decode_without_secret({ packet: invalid_packet });
    });

    // should decode packet attributes
    test.doesNotThrow(() => {
      radius.decode_without_secret({ packet: raw_packet });
    });

    test.done();
  },

  test_tag_fields(test) {
    const decoded = radius.decode({
      secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret,
        attributes: [
          ['Tunnel-Type', 0x01, 'VLAN'],
          ['User-Name', 'honeymooner-hitched'],
        ],
      }),
    });

    test.deepEqual({
      'Tunnel-Type': [1, 'VLAN'],
      'User-Name': 'honeymooner-hitched',
    }, decoded.attributes);
    test.done();
  },
});
