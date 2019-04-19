const code_map = {
  1: 'Access-Request',
  2: 'Access-Accept',
  3: 'Access-Reject',
  4: 'Accounting-Request',
  5: 'Accounting-Response',
  6: 'Interim-Accounting',
  7: 'Password-Request',
  8: 'Password-Ack',
  9: 'Password-Reject',
  10: 'Accounting-Message',
  11: 'Access-Challenge',
  12: 'Status-Server',
  13: 'Status-Client',
  21: 'Resource-Free-Request',
  22: 'Resource-Free-Response',
  23: 'Resource-Query-Request',
  24: 'Resource-Query-Response',
  25: 'Alternate-Resource-Reclaim-Request',
  26: 'NAS-Reboot-Request',
  27: 'NAS-Reboot-Response',
  29: 'Next-Passcode',
  30: 'New-Pin',
  31: 'Terminate-Session',
  32: 'Password-Expired',
  33: 'Event-Request',
  34: 'Event-Response',
  40: 'Disconnect-Request',
  41: 'Disconnect-ACK',
  42: 'Disconnect-NAK',
  43: 'CoA-Request',
  44: 'CoA-ACK',
  45: 'CoA-NAK',
  50: 'IP-Address-Allocate',
  51: 'IP-Address-Release',
};

const uses_random_authenticator = {
  'Access-Request': true,
  'Status-Server': true,
};

const is_request_code = {
  'Status-Server': true,
};

const common_attributes = {
  MESSAGE_AUTHENTICATOR: 'Message-Authenticator',
  VENDOR_SPECIFIC: 'Vendor-Specific',
  EAP_MESSAGE: 'EAP-Message',
};

module.exports = {
  code_map,
  uses_random_authenticator,
  is_request_code,
  common_attributes,
};
