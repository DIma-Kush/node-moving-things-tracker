function _toConsumableArray(arr) {
  return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread();
}

function _arrayWithoutHoles(arr) {
  if (Array.isArray(arr)) return _arrayLikeToArray(arr);
}

function _iterableToArray(iter) {
  if (typeof Symbol !== 'undefined' && iter[Symbol.iterator] != null || iter['@@iterator'] != null) return Array.from(iter);
}

function _unsupportedIterableToArray(o, minLen) {
  if (!o) return;
  if (typeof o === 'string') return _arrayLikeToArray(o, minLen);
  let n = Object.prototype.toString.call(o).slice(8, -1);
  if (n === 'Object' && o.constructor) n = o.constructor.name;
  if (n === 'Map' || n === 'Set') return Array.from(o);
  if (n === 'Arguments' || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
}

function _arrayLikeToArray(arr, len) {
  if (len == null || len > arr.length) len = arr.length;

  for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i];

  return arr2;
}

function _nonIterableSpread() {
  throw new TypeError('Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.');
}

const commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

const tracker = {};

const ItemTracked$1 = {};

const commonjsBrowser = {};

const v1$1 = {};

const rng$1 = {};

Object.defineProperty(rng$1, '__esModule', {
  value: true,
});

rng$1.default = rng; // Unique ID creation requires a high quality random # generator. In the browser we therefore
// require the crypto API and do not support built-in fallback to lower quality random number
// generators (like Math.random()).

let getRandomValues;
const rnds8 = new Uint8Array(16);

function rng() {
  // lazy load so that environments that need to polyfill have a chance to do so
  if (!getRandomValues) {
    // getRandomValues needs to be invoked in a context where "this" is a Crypto implementation.
    getRandomValues = typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto);

    if (!getRandomValues) {
      throw new Error('crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported');
    }
  }

  return getRandomValues(rnds8);
}

const stringify$1 = {};

const validate$1 = {};

const regex = {};

Object.defineProperty(regex, '__esModule', {
  value: true,
});
regex.default = void 0;
const _default$c = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
regex.default = _default$c;

Object.defineProperty(validate$1, '__esModule', {
  value: true,
});
validate$1.default = void 0;

const _regex = _interopRequireDefault$8(regex);

function _interopRequireDefault$8(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

const _default$b = validate;
validate$1.default = _default$b;

Object.defineProperty(stringify$1, '__esModule', {
  value: true,
});
stringify$1.default = void 0;
stringify$1.unsafeStringify = unsafeStringify;

const _validate$2 = _interopRequireDefault$7(validate$1);

function _interopRequireDefault$7(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}
/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  return (`${byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]]}-${byteToHex[arr[offset + 4]]}${byteToHex[arr[offset + 5]]}-${byteToHex[arr[offset + 6]]}${byteToHex[arr[offset + 7]]}-${byteToHex[arr[offset + 8]]}${byteToHex[arr[offset + 9]]}-${byteToHex[arr[offset + 10]]}${byteToHex[arr[offset + 11]]}${byteToHex[arr[offset + 12]]}${byteToHex[arr[offset + 13]]}${byteToHex[arr[offset + 14]]}${byteToHex[arr[offset + 15]]}`).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate$2.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

const _default$a = stringify;
stringify$1.default = _default$a;

Object.defineProperty(v1$1, '__esModule', {
  value: true,
});
v1$1.default = void 0;

const _rng$1 = _interopRequireDefault$6(rng$1);

const _stringify$2 = stringify$1;

function _interopRequireDefault$6(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
} // **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html

let _nodeId;

let _clockseq; // Previous uuid creation time

let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng$1.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.

  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval

  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested

  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify$2.unsafeStringify)(b);
}

const _default$9 = v1;
v1$1.default = _default$9;

const v3$1 = {};

const v35$1 = {};

const parse$1 = {};

Object.defineProperty(parse$1, '__esModule', {
  value: true,
});
parse$1.default = void 0;

const _validate$1 = _interopRequireDefault$5(validate$1);

function _interopRequireDefault$5(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

function parse(uuid) {
  if (!(0, _validate$1.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

const _default$8 = parse;
parse$1.default = _default$8;

Object.defineProperty(v35$1, '__esModule', {
  value: true,
});
v35$1.URL = v35$1.DNS = void 0;

v35$1.default = v35;

const _stringify$1 = stringify$1;

const _parse = _interopRequireDefault$4(parse$1);

function _interopRequireDefault$4(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
v35$1.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
v35$1.URL = URL;

function v35(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    let _namespace;

    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (((_namespace = namespace) === null || _namespace === void 0 ? void 0 : _namespace.length) !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`

    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify$1.unsafeStringify)(bytes);
  } // Function#name is not settable on some platforms (#270)

  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support

  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

const md5$1 = {};

Object.defineProperty(md5$1, '__esModule', {
  value: true,
});
md5$1.default = void 0;
/*
 * Browser-compatible JavaScript MD5
 *
 * Modification of JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

function md5(bytes) {
  if (typeof bytes === 'string') {
    const msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = new Uint8Array(msg.length);

    for (let i = 0; i < msg.length; ++i) {
      bytes[i] = msg.charCodeAt(i);
    }
  }

  return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
}
/*
 * Convert an array of little-endian words to an array of bytes
 */

function md5ToHexEncodedArray(input) {
  const output = [];
  const length32 = input.length * 32;
  const hexTab = '0123456789abcdef';

  for (let i = 0; i < length32; i += 8) {
    const x = input[i >> 5] >>> i % 32 & 0xff;
    const hex = parseInt(hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f), 16);
    output.push(hex);
  }

  return output;
}
/**
 * Calculate output length with padding and bit length
 */

function getOutputLength(inputLength8) {
  return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
}
/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */

function wordsToMd5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << len % 32;
  x[getOutputLength(len) - 1] = len;
  let a = 1732584193;
  let b = -271733879;
  let c = -1732584194;
  let d = 271733878;

  for (let i = 0; i < x.length; i += 16) {
    const olda = a;
    const oldb = b;
    const oldc = c;
    const oldd = d;
    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  return [a, b, c, d];
}
/*
 * Convert an array bytes to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */

function bytesToWords(input) {
  if (input.length === 0) {
    return [];
  }

  const length8 = input.length * 8;
  const output = new Uint32Array(getOutputLength(length8));

  for (let i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input[i / 8] & 0xff) << i % 32;
  }

  return output;
}
/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */

function safeAdd(x, y) {
  const lsw = (x & 0xffff) + (y & 0xffff);
  const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return msw << 16 | lsw & 0xffff;
}
/*
 * Bitwise rotate a 32-bit number to the left.
 */

function bitRotateLeft(num, cnt) {
  return num << cnt | num >>> 32 - cnt;
}
/*
 * These functions implement the four basic operations the algorithm uses.
 */

function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5ff(a, b, c, d, x, s, t) {
  return md5cmn(b & c | ~b & d, a, b, x, s, t);
}

function md5gg(a, b, c, d, x, s, t) {
  return md5cmn(b & d | c & ~d, a, b, x, s, t);
}

function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

const _default$7 = md5;
md5$1.default = _default$7;

Object.defineProperty(v3$1, '__esModule', {
  value: true,
});
v3$1.default = void 0;

const _v$1 = _interopRequireDefault$3(v35$1);

const _md = _interopRequireDefault$3(md5$1);

function _interopRequireDefault$3(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

const v3 = (0, _v$1.default)('v3', 0x30, _md.default);
const _default$6 = v3;
v3$1.default = _default$6;

const v4$1 = {};

const native = {};

Object.defineProperty(native, '__esModule', {
  value: true,
});
native.default = void 0;
const randomUUID = typeof crypto !== 'undefined' && crypto.randomUUID && crypto.randomUUID.bind(crypto);
const _default$5 = {
  randomUUID,
};
native.default = _default$5;

Object.defineProperty(v4$1, '__esModule', {
  value: true,
});
v4$1.default = void 0;

const _native = _interopRequireDefault$2(native);

const _rng = _interopRequireDefault$2(rng$1);

const _stringify = stringify$1;

function _interopRequireDefault$2(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

function v4(options, buf, offset) {
  if (_native.default.randomUUID && !buf && !options) {
    return _native.default.randomUUID();
  }

  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`

  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.unsafeStringify)(rnds);
}

const _default$4 = v4;
v4$1.default = _default$4;

const v5$1 = {};

const sha1$1 = {};

Object.defineProperty(sha1$1, '__esModule', {
  value: true,
});
sha1$1.default = void 0; // Adapted from Chris Veness' SHA1 code at
// http://www.movable-type.co.uk/scripts/sha1.html

function f(s, x, y, z) {
  switch (s) {
    case 0:
      return x & y ^ ~x & z;

    case 1:
      return x ^ y ^ z;

    case 2:
      return x & y ^ x & z ^ y & z;

    case 3:
      return x ^ y ^ z;
  }
}

function ROTL(x, n) {
  return x << n | x >>> 32 - n;
}

function sha1(bytes) {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  const H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  if (typeof bytes === 'string') {
    const msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = [];

    for (let i = 0; i < msg.length; ++i) {
      bytes.push(msg.charCodeAt(i));
    }
  } else if (!Array.isArray(bytes)) {
    // Convert Array-like to Array
    bytes = Array.prototype.slice.call(bytes);
  }

  bytes.push(0x80);
  const l = bytes.length / 4 + 2;
  const N = Math.ceil(l / 16);
  const M = new Array(N);

  for (let i = 0; i < N; ++i) {
    const arr = new Uint32Array(16);

    for (let j = 0; j < 16; ++j) {
      arr[j] = bytes[i * 64 + j * 4] << 24 | bytes[i * 64 + j * 4 + 1] << 16 | bytes[i * 64 + j * 4 + 2] << 8 | bytes[i * 64 + j * 4 + 3];
    }

    M[i] = arr;
  }

  M[N - 1][14] = (bytes.length - 1) * 8 / 2 ** 32;
  M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

  for (let i = 0; i < N; ++i) {
    const W = new Uint32Array(80);

    for (let t = 0; t < 16; ++t) {
      W[t] = M[i][t];
    }

    for (let t = 16; t < 80; ++t) {
      W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];

    for (let t = 0; t < 80; ++t) {
      const s = Math.floor(t / 20);
      const T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[t] >>> 0;
      e = d;
      d = c;
      c = ROTL(b, 30) >>> 0;
      b = a;
      a = T;
    }

    H[0] = H[0] + a >>> 0;
    H[1] = H[1] + b >>> 0;
    H[2] = H[2] + c >>> 0;
    H[3] = H[3] + d >>> 0;
    H[4] = H[4] + e >>> 0;
  }

  return [H[0] >> 24 & 0xff, H[0] >> 16 & 0xff, H[0] >> 8 & 0xff, H[0] & 0xff, H[1] >> 24 & 0xff, H[1] >> 16 & 0xff, H[1] >> 8 & 0xff, H[1] & 0xff, H[2] >> 24 & 0xff, H[2] >> 16 & 0xff, H[2] >> 8 & 0xff, H[2] & 0xff, H[3] >> 24 & 0xff, H[3] >> 16 & 0xff, H[3] >> 8 & 0xff, H[3] & 0xff, H[4] >> 24 & 0xff, H[4] >> 16 & 0xff, H[4] >> 8 & 0xff, H[4] & 0xff];
}

const _default$3 = sha1;
sha1$1.default = _default$3;

Object.defineProperty(v5$1, '__esModule', {
  value: true,
});
v5$1.default = void 0;

const _v = _interopRequireDefault$1(v35$1);

const _sha = _interopRequireDefault$1(sha1$1);

function _interopRequireDefault$1(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
const _default$2 = v5;
v5$1.default = _default$2;

const nil = {};

Object.defineProperty(nil, '__esModule', {
  value: true,
});
nil.default = void 0;
const _default$1 = '00000000-0000-0000-0000-000000000000';
nil.default = _default$1;

const version$1 = {};

Object.defineProperty(version$1, '__esModule', {
  value: true,
});
version$1.default = void 0;

const _validate = _interopRequireDefault(validate$1);

function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    default: obj,
  };
}

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.slice(14, 15), 16);
}

const _default = version;
version$1.default = _default;

(function (exports) {
  Object.defineProperty(exports, '__esModule', {
    value: true,
  });
  Object.defineProperty(exports, 'NIL', {
    enumerable: true,
    get: function get() {
      return _nil.default;
    },
  });
  Object.defineProperty(exports, 'parse', {
    enumerable: true,
    get: function get() {
      return _parse.default;
    },
  });
  Object.defineProperty(exports, 'stringify', {
    enumerable: true,
    get: function get() {
      return _stringify.default;
    },
  });
  Object.defineProperty(exports, 'v1', {
    enumerable: true,
    get: function get() {
      return _v.default;
    },
  });
  Object.defineProperty(exports, 'v3', {
    enumerable: true,
    get: function get() {
      return _v2.default;
    },
  });
  Object.defineProperty(exports, 'v4', {
    enumerable: true,
    get: function get() {
      return _v3.default;
    },
  });
  Object.defineProperty(exports, 'v5', {
    enumerable: true,
    get: function get() {
      return _v4.default;
    },
  });
  Object.defineProperty(exports, 'validate', {
    enumerable: true,
    get: function get() {
      return _validate.default;
    },
  });
  Object.defineProperty(exports, 'version', {
    enumerable: true,
    get: function get() {
      return _version.default;
    },
  });

  var _v = _interopRequireDefault(v1$1);

  var _v2 = _interopRequireDefault(v3$1);

  var _v3 = _interopRequireDefault(v4$1);

  var _v4 = _interopRequireDefault(v5$1);

  var _nil = _interopRequireDefault(nil);

  var _version = _interopRequireDefault(version$1);

  var _validate = _interopRequireDefault(validate$1);

  var _stringify = _interopRequireDefault(stringify$1);

  var _parse = _interopRequireDefault(parse$1);

  function _interopRequireDefault(obj) {
    return obj && obj.__esModule ? obj : {
      default: obj,
    };
  }
}(commonjsBrowser));

const utils = {};

utils.isDetectionTooLarge = function (detections, largestAllowed) {
  if (detections.w >= largestAllowed) {
    return true;
  }

  return false;
};

const isInsideArea = function isInsideArea(area, point) {
  const xMin = area.x - area.w / 2;
  const xMax = area.x + area.w / 2;
  const yMin = area.y - area.h / 2;
  const yMax = area.y + area.h / 2;

  if (point.x >= xMin && point.x <= xMax && point.y >= yMin && point.y <= yMax) {
    return true;
  }

  return false;
};

utils.isInsideArea = isInsideArea;

utils.isInsideSomeAreas = function (areas, point) {
  const isInside = areas.some((area) => isInsideArea(area, point));
  return isInside;
};

utils.ignoreObjectsNotToDetect = function (detections, objectsToDetect) {
  return detections.filter((detection) => objectsToDetect.indexOf(detection.name) > -1);
};

const getRectangleEdges = function getRectangleEdges(item) {
  return {
    x0: item.x - item.w / 2,
    y0: item.y - item.h / 2,
    x1: item.x + item.w / 2,
    y1: item.y + item.h / 2,
  };
};

utils.getRectangleEdges = getRectangleEdges;

utils.iouAreas = function (item1, item2) {
  const rect1 = getRectangleEdges(item1);
  const rect2 = getRectangleEdges(item2); // Get overlap rectangle

  const overlap_x0 = Math.max(rect1.x0, rect2.x0);
  const overlap_y0 = Math.max(rect1.y0, rect2.y0);
  const overlap_x1 = Math.min(rect1.x1, rect2.x1);
  const overlap_y1 = Math.min(rect1.y1, rect2.y1); // if there an overlap

  if (overlap_x1 - overlap_x0 <= 0 || overlap_y1 - overlap_y0 <= 0) {
    // no overlap
    return 0;
  }

  const area_rect1 = item1.w * item1.h;
  const area_rect2 = item2.w * item2.h;
  const area_intersection = (overlap_x1 - overlap_x0) * (overlap_y1 - overlap_y0);
  const area_union = area_rect1 + area_rect2 - area_intersection;
  return area_intersection / area_union;
};

utils.computeVelocityVector = function (item1, item2, nbFrame) {
  return {
    dx: (item2.x - item1.x) / nbFrame,
    dy: (item2.y - item1.y) / nbFrame,
  };
};
/*

  computeBearingIn360

                       dY

                       ^               XX
                       |             XXX
                       |            XX
                       |           XX
                       |         XX
                       |       XXX
                       |      XX
                       |     XX
                       |    XX    bearing = this angle in degree
                       |  XX
                       |XX
+----------------------XX----------------------->  dX
                       |
                       |
                       |
                       |
                       |
                       |
                       |
                       |
                       |
                       |
                       |
                       +

*/

utils.computeBearingIn360 = function (dx, dy) {
  const angle = Math.atan(dx / dy) / (Math.PI / 180);

  if (angle > 0) {
    if (dy > 0) {
      return angle;
    }

    return 180 + angle;
  }

  if (dx > 0) {
    return 180 + angle;
  }

  return 360 + angle;
};

(function (exports) {
  const uuidv4 = commonjsBrowser.v4;
  const { computeBearingIn360 } = utils;
  const { computeVelocityVector } = utils; // Properties example
  // {
  //   "x": 1021,
  //   "y": 65,
  //   "w": 34,
  //   "h": 27,
  //   "confidence": 26,
  //   "name": "car"
  // }

  /** The maximum length of the item history. */

  exports.ITEM_HISTORY_MAX_LENGTH = 15; // Use a simple incremental unique id for the display

  let idDisplay = 0;

  exports.ItemTracked = function (properties, frameNb, unMatchedFramesTolerance, fastDelete) {
    const DEFAULT_UNMATCHEDFRAMES_TOLERANCE = unMatchedFramesTolerance;
    const itemTracked = {}; // ==== Private =====
    // Am I available to be matched?

    itemTracked.available = true; // Should I be deleted?

    itemTracked.delete = false;
    itemTracked.fastDelete = fastDelete; // How many unmatched frame should I survive?

    itemTracked.frameUnmatchedLeftBeforeDying = unMatchedFramesTolerance;
    itemTracked.isZombie = false;
    itemTracked.appearFrame = frameNb;
    itemTracked.disappearFrame = null;
    itemTracked.disappearArea = {}; // Keep track of the most counted class

    itemTracked.nameCount = {};
    itemTracked.nameCount[properties.name] = 1; // ==== Public =====

    itemTracked.x = properties.x;
    itemTracked.y = properties.y;
    itemTracked.w = properties.w;
    itemTracked.h = properties.h;
    itemTracked.name = properties.name;
    itemTracked.confidence = properties.confidence;
    itemTracked.itemHistory = [];
    itemTracked.itemHistory.push({
      x: properties.x,
      y: properties.y,
      w: properties.w,
      h: properties.h,
      confidence: properties.confidence,
    });

    if (itemTracked.itemHistory.length >= exports.ITEM_HISTORY_MAX_LENGTH) {
      itemTracked.itemHistory.shift();
    }

    itemTracked.velocity = {
      dx: 0,
      dy: 0,
    };
    itemTracked.nbTimeMatched = 1; // Assign an unique id to each Item tracked

    itemTracked.id = uuidv4(); // Use an simple id for the display and debugging

    itemTracked.idDisplay = idDisplay;
    idDisplay++; // Give me a new location / size

    itemTracked.update = function (properties, frameNb) {
      // if it was zombie and disappear frame was set, reset it to null
      if (this.disappearFrame) {
        this.disappearFrame = null;
        this.disappearArea = {};
      }

      this.isZombie = false;
      this.nbTimeMatched += 1;
      this.x = properties.x;
      this.y = properties.y;
      this.w = properties.w;
      this.h = properties.h;
      this.confidence = properties.confidence;
      this.itemHistory.push({
        x: this.x,
        y: this.y,
        w: this.w,
        h: this.h,
        confidence: this.confidence,
      });

      if (itemTracked.itemHistory.length >= exports.ITEM_HISTORY_MAX_LENGTH) {
        itemTracked.itemHistory.shift();
      }

      this.name = properties.name;

      if (this.nameCount[properties.name]) {
        this.nameCount[properties.name]++;
      } else {
        this.nameCount[properties.name] = 1;
      } // Reset dying counter

      this.frameUnmatchedLeftBeforeDying = DEFAULT_UNMATCHEDFRAMES_TOLERANCE; // Compute new velocityVector based on last positions history

      this.velocity = this.updateVelocityVector();
    };

    itemTracked.makeAvailable = function () {
      this.available = true;
      return this;
    };

    itemTracked.makeUnavailable = function () {
      this.available = false;
      return this;
    };

    itemTracked.countDown = function (frameNb) {
      // Set frame disappear number
      if (this.disappearFrame === null) {
        this.disappearFrame = frameNb;
        this.disappearArea = {
          x: this.x,
          y: this.y,
          w: this.w,
          h: this.h,
        };
      }

      this.frameUnmatchedLeftBeforeDying--;
      this.isZombie = true; // If it was matched less than 1 time, it should die quick

      if (this.fastDelete && this.nbTimeMatched <= 1) {
        this.frameUnmatchedLeftBeforeDying = -1;
      }
    };

    itemTracked.updateTheoricalPositionAndSize = function () {
      this.itemHistory.push({
        x: this.x,
        y: this.y,
        w: this.w,
        h: this.h,
        confidence: this.confidence,
      });

      if (itemTracked.itemHistory.length >= exports.ITEM_HISTORY_MAX_LENGTH) {
        itemTracked.itemHistory.shift();
      }

      this.x += this.velocity.dx;
      this.y += this.velocity.dy;
    };

    itemTracked.predictNextPosition = function () {
      return {
        x: this.x + this.velocity.dx,
        y: this.y + this.velocity.dy,
        w: this.w,
        h: this.h,
      };
    };

    itemTracked.isDead = function () {
      return this.frameUnmatchedLeftBeforeDying < 0;
    }; // Velocity vector based on the last 15 frames

    itemTracked.updateVelocityVector = function () {
      if (exports.ITEM_HISTORY_MAX_LENGTH <= 2) {
        return {
          dx: undefined,
          dy: undefined,
        };
      }

      if (this.itemHistory.length <= exports.ITEM_HISTORY_MAX_LENGTH) {
        const _start = this.itemHistory[0];
        const _end = this.itemHistory[this.itemHistory.length - 1];
        return computeVelocityVector(_start, _end, this.itemHistory.length);
      }

      const start = this.itemHistory[this.itemHistory.length - exports.ITEM_HISTORY_MAX_LENGTH];
      const end = this.itemHistory[this.itemHistory.length - 1];
      return computeVelocityVector(start, end, exports.ITEM_HISTORY_MAX_LENGTH);
    };

    itemTracked.getMostlyMatchedName = function () {
      const _this = this;

      let nameMostlyMatchedOccurences = 0;
      let nameMostlyMatched = '';
      Object.keys(this.nameCount).map((name) => {
        if (_this.nameCount[name] > nameMostlyMatchedOccurences) {
          nameMostlyMatched = name;
          nameMostlyMatchedOccurences = _this.nameCount[name];
        }
      });
      return nameMostlyMatched;
    };

    itemTracked.toJSONDebug = function () {
      const roundInt = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;
      return {
        id: this.id,
        idDisplay: this.idDisplay,
        x: roundInt ? parseInt(this.x, 10) : this.x,
        y: roundInt ? parseInt(this.y, 10) : this.y,
        w: roundInt ? parseInt(this.w, 10) : this.w,
        h: roundInt ? parseInt(this.h, 10) : this.h,
        confidence: Math.round(this.confidence * 100) / 100,
        // Here we negate dy to be in "normal" carthesian coordinates
        bearing: parseInt(computeBearingIn360(this.velocity.dx, -this.velocity.dy)),
        name: this.getMostlyMatchedName(),
        isZombie: this.isZombie,
        appearFrame: this.appearFrame,
        disappearFrame: this.disappearFrame,
      };
    };

    itemTracked.toJSON = function () {
      const roundInt = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;
      return {
        id: this.idDisplay,
        x: roundInt ? parseInt(this.x, 10) : this.x,
        y: roundInt ? parseInt(this.y, 10) : this.y,
        w: roundInt ? parseInt(this.w, 10) : this.w,
        h: roundInt ? parseInt(this.h, 10) : this.h,
        confidence: Math.round(this.confidence * 100) / 100,
        // Here we negate dy to be in "normal" carthesian coordinates
        bearing: parseInt(computeBearingIn360(this.velocity.dx, -this.velocity.dy), 10),
        name: this.getMostlyMatchedName(),
        isZombie: this.isZombie,
      };
    };

    itemTracked.toMOT = function (frameIndex) {
      return ''.concat(frameIndex, ',').concat(this.idDisplay, ',').concat(this.x - this.w / 2, ',').concat(this.y - this.h / 2, ',')
        .concat(this.w, ',')
        .concat(this.h, ',')
        .concat(this.confidence / 100, ',-1,-1,-1');
    };

    itemTracked.toJSONGenericInfo = function () {
      return {
        id: this.id,
        idDisplay: this.idDisplay,
        appearFrame: this.appearFrame,
        disappearFrame: this.disappearFrame,
        disappearArea: this.disappearArea,
        nbActiveFrame: this.disappearFrame - this.appearFrame,
        name: this.getMostlyMatchedName(),
      };
    };

    return itemTracked;
  };

  exports.reset = function () {
    idDisplay = 0;
  };
}(ItemTracked$1));

const kdTreeMin = {};

/**
 * k-d Tree JavaScript - V 1.01
 *
 * https://github.com/ubilabs/kd-tree-javascript
 *
 * @author Mircea Pricop <pricop@ubilabs.net>, 2012
 * @author Martin Kleppe <kleppe@ubilabs.net>, 2012
 * @author Ubilabs http://ubilabs.net, 2012
 * @license MIT License <http://www.opensource.org/licenses/mit-license.php>
 */

(function (exports) {
  !(function (t, n) {
    n(exports);
  }(commonjsGlobal, (t) => {
    function n(t, n, o) {
      this.obj = t, this.left = null, this.right = null, this.parent = o, this.dimension = n;
    }

    function o(t) {
      this.content = [], this.scoreFunction = t;
    }

    o.prototype = {
      push(t) {
        this.content.push(t), this.bubbleUp(this.content.length - 1);
      },
      pop() {
        const t = this.content[0];
        const n = this.content.pop();
        return this.content.length > 0 && (this.content[0] = n, this.sinkDown(0)), t;
      },
      peek() {
        return this.content[0];
      },
      remove(t) {
        for (let n = this.content.length, o = 0; o < n; o++) {
          if (this.content[o] == t) {
            const i = this.content.pop();
            return void (o != n - 1 && (this.content[o] = i, this.scoreFunction(i) < this.scoreFunction(t) ? this.bubbleUp(o) : this.sinkDown(o)));
          }
        }

        throw new Error('Node not found.');
      },
      size() {
        return this.content.length;
      },
      bubbleUp(t) {
        for (let n = this.content[t]; t > 0;) {
          const o = Math.floor((t + 1) / 2) - 1;
          const i = this.content[o];
          if (!(this.scoreFunction(n) < this.scoreFunction(i))) break;
          this.content[o] = n, this.content[t] = i, t = o;
        }
      },
      sinkDown(t) {
        for (let n = this.content.length, o = this.content[t], i = this.scoreFunction(o); ;) {
          const e = 2 * (t + 1);
          const r = e - 1;
          let l = null;

          if (r < n) {
            const u = this.content[r];
            var h = this.scoreFunction(u);
            h < i && (l = r);
          }

          if (e < n) {
            const s = this.content[e];
            this.scoreFunction(s) < (l == null ? i : h) && (l = e);
          }

          if (l == null) break;
          this.content[t] = this.content[l], this.content[l] = o, t = l;
        }
      },
    }, t.kdTree = function (t, i, e) {
      function r(t, o, i) {
        let l;
        let u;
        const h = o % e.length;
        return t.length === 0 ? null : t.length === 1 ? new n(t[0], h, i) : (t.sort((t, n) => t[e[h]] - n[e[h]]), l = Math.floor(t.length / 2), u = new n(t[l], h, i), u.left = r(t.slice(0, l), o + 1, u), u.right = r(t.slice(l + 1), o + 1, u), u);
      }

      const l = this;
      Array.isArray(t) ? this.root = r(t, 0, null) : (function (t) {
        function n(t) {
          t.left && (t.left.parent = t, n(t.left)), t.right && (t.right.parent = t, n(t.right));
        }

        l.root = t, n(l.root);
      }(t)), this.toJSON = function (t) {
        t || (t = this.root);
        const o = new n(t.obj, t.dimension, null);
        return t.left && (o.left = l.toJSON(t.left)), t.right && (o.right = l.toJSON(t.right)), o;
      }, this.insert = function (t) {
        function o(n, i) {
          if (n === null) return i;
          const r = e[n.dimension];
          return t[r] < n.obj[r] ? o(n.left, n) : o(n.right, n);
        }

        let i;
        let r;
        const l = o(this.root, null);
        l !== null ? (i = new n(t, (l.dimension + 1) % e.length, l), r = e[l.dimension], t[r] < l.obj[r] ? l.left = i : l.right = i) : this.root = new n(t, 0, null);
      }, this.remove = function (t) {
        function n(o) {
          if (o === null) return null;
          if (o.obj === t) return o;
          const i = e[o.dimension];
          return t[i] < o.obj[i] ? n(o.left) : n(o.right);
        }

        function o(t) {
          function n(t, o) {
            let i; let r; let l; let u; let
              h;
            return t === null ? null : (i = e[o], t.dimension === o ? t.left !== null ? n(t.left, o) : t : (r = t.obj[i], l = n(t.left, o), u = n(t.right, o), h = t, l !== null && l.obj[i] < r && (h = l), u !== null && u.obj[i] < h.obj[i] && (h = u), h));
          }

          let i; let r; let
            u;
          if (t.left === null && t.right === null) return t.parent === null ? void (l.root = null) : (u = e[t.parent.dimension], void (t.obj[u] < t.parent.obj[u] ? t.parent.left = null : t.parent.right = null));
          t.right !== null ? (r = (i = n(t.right, t.dimension)).obj, o(i), t.obj = r) : (r = (i = n(t.left, t.dimension)).obj, o(i), t.right = t.left, t.left = null, t.obj = r);
        }

        let i;
        (i = n(l.root)) !== null && o(i);
      }, this.nearest = function (t, n, r) {
        function u(o) {
          function r(t, o) {
            f.push([t, o]), f.size() > n && f.pop();
          }

          let l;
          let h;
          let s;
          let c;
          const a = e[o.dimension];
          const g = i(t, o.obj);
          const p = {};

          for (c = 0; c < e.length; c += 1) c === o.dimension ? p[e[c]] = t[e[c]] : p[e[c]] = o.obj[e[c]];

          h = i(p, o.obj), o.right !== null || o.left !== null ? (u(l = o.right === null ? o.left : o.left === null ? o.right : t[a] < o.obj[a] ? o.left : o.right), (f.size() < n || g < f.peek()[1]) && r(o, g), (f.size() < n || Math.abs(h) < f.peek()[1]) && (s = l === o.left ? o.right : o.left) !== null && u(s)) : (f.size() < n || g < f.peek()[1]) && r(o, g);
        }

        let h; let s; let
          f;
        if (f = new o((t) => -t[1]), r) for (h = 0; h < n; h += 1) f.push([null, r]);

        for (l.root && u(l.root), s = [], h = 0; h < Math.min(n, f.content.length); h += 1) f.content[h][0] && s.push([f.content[h][0].obj, f.content[h][1]]);

        return s;
      }, this.balanceFactor = function () {
        function t(n) {
          return n === null ? 0 : Math.max(t(n.left), t(n.right)) + 1;
        }

        function n(t) {
          return t === null ? 0 : n(t.left) + n(t.right) + 1;
        }

        return t(l.root) / (Math.log(n(l.root)) / Math.log(2));
      };
    }, t.BinaryHeap = o;
  }));
}(kdTreeMin));

const lodash_isequal = { exports: {} };

/**
 * Lodash (Custom Build) <https://lodash.com/>
 * Build: `lodash modularize exports="npm" -o ./`
 * Copyright JS Foundation and other contributors <https://js.foundation/>
 * Released under MIT license <https://lodash.com/license>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 */

(function (module, exports) {
  /** Used as the size to enable large array optimizations. */
  const LARGE_ARRAY_SIZE = 200;
  /** Used to stand-in for `undefined` hash values. */

  const HASH_UNDEFINED = '__lodash_hash_undefined__';
  /** Used to compose bitmasks for value comparisons. */

  const COMPARE_PARTIAL_FLAG = 1;
  const COMPARE_UNORDERED_FLAG = 2;
  /** Used as references for various `Number` constants. */

  const MAX_SAFE_INTEGER = 9007199254740991;
  /** `Object#toString` result references. */

  const argsTag = '[object Arguments]';
  const arrayTag = '[object Array]';
  const asyncTag = '[object AsyncFunction]';
  const boolTag = '[object Boolean]';
  const dateTag = '[object Date]';
  const errorTag = '[object Error]';
  const funcTag = '[object Function]';
  const genTag = '[object GeneratorFunction]';
  const mapTag = '[object Map]';
  const numberTag = '[object Number]';
  const nullTag = '[object Null]';
  const objectTag = '[object Object]';
  const promiseTag = '[object Promise]';
  const proxyTag = '[object Proxy]';
  const regexpTag = '[object RegExp]';
  const setTag = '[object Set]';
  const stringTag = '[object String]';
  const symbolTag = '[object Symbol]';
  const undefinedTag = '[object Undefined]';
  const weakMapTag = '[object WeakMap]';
  const arrayBufferTag = '[object ArrayBuffer]';
  const dataViewTag = '[object DataView]';
  const float32Tag = '[object Float32Array]';
  const float64Tag = '[object Float64Array]';
  const int8Tag = '[object Int8Array]';
  const int16Tag = '[object Int16Array]';
  const int32Tag = '[object Int32Array]';
  const uint8Tag = '[object Uint8Array]';
  const uint8ClampedTag = '[object Uint8ClampedArray]';
  const uint16Tag = '[object Uint16Array]';
  const uint32Tag = '[object Uint32Array]';
  /**
   * Used to match `RegExp`
   * [syntax characters](http://ecma-international.org/ecma-262/7.0/#sec-patterns).
   */

  const reRegExpChar = /[\\^$.*+?()[\]{}|]/g;
  /** Used to detect host constructors (Safari). */

  const reIsHostCtor = /^\[object .+?Constructor\]$/;
  /** Used to detect unsigned integer values. */

  const reIsUint = /^(?:0|[1-9]\d*)$/;
  /** Used to identify `toStringTag` values of typed arrays. */

  const typedArrayTags = {};
  typedArrayTags[float32Tag] = typedArrayTags[float64Tag] = typedArrayTags[int8Tag] = typedArrayTags[int16Tag] = typedArrayTags[int32Tag] = typedArrayTags[uint8Tag] = typedArrayTags[uint8ClampedTag] = typedArrayTags[uint16Tag] = typedArrayTags[uint32Tag] = true;
  typedArrayTags[argsTag] = typedArrayTags[arrayTag] = typedArrayTags[arrayBufferTag] = typedArrayTags[boolTag] = typedArrayTags[dataViewTag] = typedArrayTags[dateTag] = typedArrayTags[errorTag] = typedArrayTags[funcTag] = typedArrayTags[mapTag] = typedArrayTags[numberTag] = typedArrayTags[objectTag] = typedArrayTags[regexpTag] = typedArrayTags[setTag] = typedArrayTags[stringTag] = typedArrayTags[weakMapTag] = false;
  /** Detect free variable `global` from Node.js. */

  const freeGlobal = typeof commonjsGlobal === 'object' && commonjsGlobal && commonjsGlobal.Object === Object && commonjsGlobal;
  /** Detect free variable `self`. */

  const freeSelf = typeof self === 'object' && self && self.Object === Object && self;
  /** Used as a reference to the global object. */

  const root = freeGlobal || freeSelf || Function('return this')();
  /** Detect free variable `exports`. */

  const freeExports = exports && !exports.nodeType && exports;
  /** Detect free variable `module`. */

  const freeModule = freeExports && 'object' === 'object' && module && !module.nodeType && module;
  /** Detect the popular CommonJS extension `module.exports`. */

  const moduleExports = freeModule && freeModule.exports === freeExports;
  /** Detect free variable `process` from Node.js. */

  const freeProcess = moduleExports && freeGlobal.process;
  /** Used to access faster Node.js helpers. */

  const nodeUtil = (function () {
    try {
      return freeProcess && freeProcess.binding && freeProcess.binding('util');
    } catch (e) {}
  }());
  /* Node.js helper references. */

  const nodeIsTypedArray = nodeUtil && nodeUtil.isTypedArray;
  /**
   * A specialized version of `_.filter` for arrays without support for
   * iteratee shorthands.
   *
   * @private
   * @param {Array} [array] The array to iterate over.
   * @param {Function} predicate The function invoked per iteration.
   * @returns {Array} Returns the new filtered array.
   */

  function arrayFilter(array, predicate) {
    let index = -1;
    const length = array == null ? 0 : array.length;
    let resIndex = 0;
    const result = [];

    while (++index < length) {
      const value = array[index];

      if (predicate(value, index, array)) {
        result[resIndex++] = value;
      }
    }

    return result;
  }
  /**
   * Appends the elements of `values` to `array`.
   *
   * @private
   * @param {Array} array The array to modify.
   * @param {Array} values The values to append.
   * @returns {Array} Returns `array`.
   */

  function arrayPush(array, values) {
    let index = -1;
    const { length } = values;
    const offset = array.length;

    while (++index < length) {
      array[offset + index] = values[index];
    }

    return array;
  }
  /**
   * A specialized version of `_.some` for arrays without support for iteratee
   * shorthands.
   *
   * @private
   * @param {Array} [array] The array to iterate over.
   * @param {Function} predicate The function invoked per iteration.
   * @returns {boolean} Returns `true` if any element passes the predicate check,
   *  else `false`.
   */

  function arraySome(array, predicate) {
    let index = -1;
    const length = array == null ? 0 : array.length;

    while (++index < length) {
      if (predicate(array[index], index, array)) {
        return true;
      }
    }

    return false;
  }
  /**
   * The base implementation of `_.times` without support for iteratee shorthands
   * or max array length checks.
   *
   * @private
   * @param {number} n The number of times to invoke `iteratee`.
   * @param {Function} iteratee The function invoked per iteration.
   * @returns {Array} Returns the array of results.
   */

  function baseTimes(n, iteratee) {
    let index = -1;
    const result = Array(n);

    while (++index < n) {
      result[index] = iteratee(index);
    }

    return result;
  }
  /**
   * The base implementation of `_.unary` without support for storing metadata.
   *
   * @private
   * @param {Function} func The function to cap arguments for.
   * @returns {Function} Returns the new capped function.
   */

  function baseUnary(func) {
    return function (value) {
      return func(value);
    };
  }
  /**
   * Checks if a `cache` value for `key` exists.
   *
   * @private
   * @param {Object} cache The cache to query.
   * @param {string} key The key of the entry to check.
   * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
   */

  function cacheHas(cache, key) {
    return cache.has(key);
  }
  /**
   * Gets the value at `key` of `object`.
   *
   * @private
   * @param {Object} [object] The object to query.
   * @param {string} key The key of the property to get.
   * @returns {*} Returns the property value.
   */

  function getValue(object, key) {
    return object == null ? undefined : object[key];
  }
  /**
   * Converts `map` to its key-value pairs.
   *
   * @private
   * @param {Object} map The map to convert.
   * @returns {Array} Returns the key-value pairs.
   */

  function mapToArray(map) {
    let index = -1;
    const result = Array(map.size);
    map.forEach((value, key) => {
      result[++index] = [key, value];
    });
    return result;
  }
  /**
   * Creates a unary function that invokes `func` with its argument transformed.
   *
   * @private
   * @param {Function} func The function to wrap.
   * @param {Function} transform The argument transform.
   * @returns {Function} Returns the new function.
   */

  function overArg(func, transform) {
    return function (arg) {
      return func(transform(arg));
    };
  }
  /**
   * Converts `set` to an array of its values.
   *
   * @private
   * @param {Object} set The set to convert.
   * @returns {Array} Returns the values.
   */

  function setToArray(set) {
    let index = -1;
    const result = Array(set.size);
    set.forEach((value) => {
      result[++index] = value;
    });
    return result;
  }
  /** Used for built-in method references. */

  const arrayProto = Array.prototype;
  const funcProto = Function.prototype;
  const objectProto = Object.prototype;
  /** Used to detect overreaching core-js shims. */

  const coreJsData = root['__core-js_shared__'];
  /** Used to resolve the decompiled source of functions. */

  const funcToString = funcProto.toString;
  /** Used to check objects for own properties. */

  const { hasOwnProperty } = objectProto;
  /** Used to detect methods masquerading as native. */

  const maskSrcKey = (function () {
    const uid = /[^.]+$/.exec(coreJsData && coreJsData.keys && coreJsData.keys.IE_PROTO || '');
    return uid ? `Symbol(src)_1.${uid}` : '';
  }());
  /**
   * Used to resolve the
   * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)
   * of values.
   */

  const nativeObjectToString = objectProto.toString;
  /** Used to detect if a method is native. */

  const reIsNative = RegExp(`^${funcToString.call(hasOwnProperty).replace(reRegExpChar, '\\$&').replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, '$1.*?')}$`);
  /** Built-in value references. */

  const Buffer = moduleExports ? root.Buffer : undefined;
  const { Symbol } = root;
  const { Uint8Array } = root;
  const { propertyIsEnumerable } = objectProto;
  const { splice } = arrayProto;
  const symToStringTag = Symbol ? Symbol.toStringTag : undefined;
  /* Built-in method references for those with the same name as other `lodash` methods. */

  const nativeGetSymbols = Object.getOwnPropertySymbols;
  const nativeIsBuffer = Buffer ? Buffer.isBuffer : undefined;
  const nativeKeys = overArg(Object.keys, Object);
  /* Built-in method references that are verified to be native. */

  const DataView = getNative(root, 'DataView');
  const Map = getNative(root, 'Map');
  const Promise = getNative(root, 'Promise');
  const Set = getNative(root, 'Set');
  const WeakMap = getNative(root, 'WeakMap');
  const nativeCreate = getNative(Object, 'create');
  /** Used to detect maps, sets, and weakmaps. */

  const dataViewCtorString = toSource(DataView);
  const mapCtorString = toSource(Map);
  const promiseCtorString = toSource(Promise);
  const setCtorString = toSource(Set);
  const weakMapCtorString = toSource(WeakMap);
  /** Used to convert symbols to primitives and strings. */

  const symbolProto = Symbol ? Symbol.prototype : undefined;
  const symbolValueOf = symbolProto ? symbolProto.valueOf : undefined;
  /**
   * Creates a hash object.
   *
   * @private
   * @constructor
   * @param {Array} [entries] The key-value pairs to cache.
   */

  function Hash(entries) {
    let index = -1;
    const length = entries == null ? 0 : entries.length;
    this.clear();

    while (++index < length) {
      const entry = entries[index];
      this.set(entry[0], entry[1]);
    }
  }
  /**
   * Removes all key-value entries from the hash.
   *
   * @private
   * @name clear
   * @memberOf Hash
   */

  function hashClear() {
    this.__data__ = nativeCreate ? nativeCreate(null) : {};
    this.size = 0;
  }
  /**
   * Removes `key` and its value from the hash.
   *
   * @private
   * @name delete
   * @memberOf Hash
   * @param {Object} hash The hash to modify.
   * @param {string} key The key of the value to remove.
   * @returns {boolean} Returns `true` if the entry was removed, else `false`.
   */

  function hashDelete(key) {
    const result = this.has(key) && delete this.__data__[key];
    this.size -= result ? 1 : 0;
    return result;
  }
  /**
   * Gets the hash value for `key`.
   *
   * @private
   * @name get
   * @memberOf Hash
   * @param {string} key The key of the value to get.
   * @returns {*} Returns the entry value.
   */

  function hashGet(key) {
    const data = this.__data__;

    if (nativeCreate) {
      const result = data[key];
      return result === HASH_UNDEFINED ? undefined : result;
    }

    return hasOwnProperty.call(data, key) ? data[key] : undefined;
  }
  /**
   * Checks if a hash value for `key` exists.
   *
   * @private
   * @name has
   * @memberOf Hash
   * @param {string} key The key of the entry to check.
   * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
   */

  function hashHas(key) {
    const data = this.__data__;
    return nativeCreate ? data[key] !== undefined : hasOwnProperty.call(data, key);
  }
  /**
   * Sets the hash `key` to `value`.
   *
   * @private
   * @name set
   * @memberOf Hash
   * @param {string} key The key of the value to set.
   * @param {*} value The value to set.
   * @returns {Object} Returns the hash instance.
   */

  function hashSet(key, value) {
    const data = this.__data__;
    this.size += this.has(key) ? 0 : 1;
    data[key] = nativeCreate && value === undefined ? HASH_UNDEFINED : value;
    return this;
  } // Add methods to `Hash`.

  Hash.prototype.clear = hashClear;
  Hash.prototype.delete = hashDelete;
  Hash.prototype.get = hashGet;
  Hash.prototype.has = hashHas;
  Hash.prototype.set = hashSet;
  /**
   * Creates an list cache object.
   *
   * @private
   * @constructor
   * @param {Array} [entries] The key-value pairs to cache.
   */

  function ListCache(entries) {
    let index = -1;
    const length = entries == null ? 0 : entries.length;
    this.clear();

    while (++index < length) {
      const entry = entries[index];
      this.set(entry[0], entry[1]);
    }
  }
  /**
   * Removes all key-value entries from the list cache.
   *
   * @private
   * @name clear
   * @memberOf ListCache
   */

  function listCacheClear() {
    this.__data__ = [];
    this.size = 0;
  }
  /**
   * Removes `key` and its value from the list cache.
   *
   * @private
   * @name delete
   * @memberOf ListCache
   * @param {string} key The key of the value to remove.
   * @returns {boolean} Returns `true` if the entry was removed, else `false`.
   */

  function listCacheDelete(key) {
    const data = this.__data__;
    const index = assocIndexOf(data, key);

    if (index < 0) {
      return false;
    }

    const lastIndex = data.length - 1;

    if (index == lastIndex) {
      data.pop();
    } else {
      splice.call(data, index, 1);
    }

    --this.size;
    return true;
  }
  /**
   * Gets the list cache value for `key`.
   *
   * @private
   * @name get
   * @memberOf ListCache
   * @param {string} key The key of the value to get.
   * @returns {*} Returns the entry value.
   */

  function listCacheGet(key) {
    const data = this.__data__;
    const index = assocIndexOf(data, key);
    return index < 0 ? undefined : data[index][1];
  }
  /**
   * Checks if a list cache value for `key` exists.
   *
   * @private
   * @name has
   * @memberOf ListCache
   * @param {string} key The key of the entry to check.
   * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
   */

  function listCacheHas(key) {
    return assocIndexOf(this.__data__, key) > -1;
  }
  /**
   * Sets the list cache `key` to `value`.
   *
   * @private
   * @name set
   * @memberOf ListCache
   * @param {string} key The key of the value to set.
   * @param {*} value The value to set.
   * @returns {Object} Returns the list cache instance.
   */

  function listCacheSet(key, value) {
    const data = this.__data__;
    const index = assocIndexOf(data, key);

    if (index < 0) {
      ++this.size;
      data.push([key, value]);
    } else {
      data[index][1] = value;
    }

    return this;
  } // Add methods to `ListCache`.

  ListCache.prototype.clear = listCacheClear;
  ListCache.prototype.delete = listCacheDelete;
  ListCache.prototype.get = listCacheGet;
  ListCache.prototype.has = listCacheHas;
  ListCache.prototype.set = listCacheSet;
  /**
   * Creates a map cache object to store key-value pairs.
   *
   * @private
   * @constructor
   * @param {Array} [entries] The key-value pairs to cache.
   */

  function MapCache(entries) {
    let index = -1;
    const length = entries == null ? 0 : entries.length;
    this.clear();

    while (++index < length) {
      const entry = entries[index];
      this.set(entry[0], entry[1]);
    }
  }
  /**
   * Removes all key-value entries from the map.
   *
   * @private
   * @name clear
   * @memberOf MapCache
   */

  function mapCacheClear() {
    this.size = 0;
    this.__data__ = {
      hash: new Hash(),
      map: new (Map || ListCache)(),
      string: new Hash(),
    };
  }
  /**
   * Removes `key` and its value from the map.
   *
   * @private
   * @name delete
   * @memberOf MapCache
   * @param {string} key The key of the value to remove.
   * @returns {boolean} Returns `true` if the entry was removed, else `false`.
   */

  function mapCacheDelete(key) {
    const result = getMapData(this, key).delete(key);
    this.size -= result ? 1 : 0;
    return result;
  }
  /**
   * Gets the map value for `key`.
   *
   * @private
   * @name get
   * @memberOf MapCache
   * @param {string} key The key of the value to get.
   * @returns {*} Returns the entry value.
   */

  function mapCacheGet(key) {
    return getMapData(this, key).get(key);
  }
  /**
   * Checks if a map value for `key` exists.
   *
   * @private
   * @name has
   * @memberOf MapCache
   * @param {string} key The key of the entry to check.
   * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
   */

  function mapCacheHas(key) {
    return getMapData(this, key).has(key);
  }
  /**
   * Sets the map `key` to `value`.
   *
   * @private
   * @name set
   * @memberOf MapCache
   * @param {string} key The key of the value to set.
   * @param {*} value The value to set.
   * @returns {Object} Returns the map cache instance.
   */

  function mapCacheSet(key, value) {
    const data = getMapData(this, key);
    const { size } = data;
    data.set(key, value);
    this.size += data.size == size ? 0 : 1;
    return this;
  } // Add methods to `MapCache`.

  MapCache.prototype.clear = mapCacheClear;
  MapCache.prototype.delete = mapCacheDelete;
  MapCache.prototype.get = mapCacheGet;
  MapCache.prototype.has = mapCacheHas;
  MapCache.prototype.set = mapCacheSet;
  /**
   *
   * Creates an array cache object to store unique values.
   *
   * @private
   * @constructor
   * @param {Array} [values] The values to cache.
   */

  function SetCache(values) {
    let index = -1;
    const length = values == null ? 0 : values.length;
    this.__data__ = new MapCache();

    while (++index < length) {
      this.add(values[index]);
    }
  }
  /**
   * Adds `value` to the array cache.
   *
   * @private
   * @name add
   * @memberOf SetCache
   * @alias push
   * @param {*} value The value to cache.
   * @returns {Object} Returns the cache instance.
   */

  function setCacheAdd(value) {
    this.__data__.set(value, HASH_UNDEFINED);

    return this;
  }
  /**
   * Checks if `value` is in the array cache.
   *
   * @private
   * @name has
   * @memberOf SetCache
   * @param {*} value The value to search for.
   * @returns {number} Returns `true` if `value` is found, else `false`.
   */

  function setCacheHas(value) {
    return this.__data__.has(value);
  } // Add methods to `SetCache`.

  SetCache.prototype.add = SetCache.prototype.push = setCacheAdd;
  SetCache.prototype.has = setCacheHas;
  /**
   * Creates a stack cache object to store key-value pairs.
   *
   * @private
   * @constructor
   * @param {Array} [entries] The key-value pairs to cache.
   */

  function Stack(entries) {
    const data = this.__data__ = new ListCache(entries);
    this.size = data.size;
  }
  /**
   * Removes all key-value entries from the stack.
   *
   * @private
   * @name clear
   * @memberOf Stack
   */

  function stackClear() {
    this.__data__ = new ListCache();
    this.size = 0;
  }
  /**
   * Removes `key` and its value from the stack.
   *
   * @private
   * @name delete
   * @memberOf Stack
   * @param {string} key The key of the value to remove.
   * @returns {boolean} Returns `true` if the entry was removed, else `false`.
   */

  function stackDelete(key) {
    const data = this.__data__;
    const result = data.delete(key);
    this.size = data.size;
    return result;
  }
  /**
   * Gets the stack value for `key`.
   *
   * @private
   * @name get
   * @memberOf Stack
   * @param {string} key The key of the value to get.
   * @returns {*} Returns the entry value.
   */

  function stackGet(key) {
    return this.__data__.get(key);
  }
  /**
   * Checks if a stack value for `key` exists.
   *
   * @private
   * @name has
   * @memberOf Stack
   * @param {string} key The key of the entry to check.
   * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
   */

  function stackHas(key) {
    return this.__data__.has(key);
  }
  /**
   * Sets the stack `key` to `value`.
   *
   * @private
   * @name set
   * @memberOf Stack
   * @param {string} key The key of the value to set.
   * @param {*} value The value to set.
   * @returns {Object} Returns the stack cache instance.
   */

  function stackSet(key, value) {
    let data = this.__data__;

    if (data instanceof ListCache) {
      const pairs = data.__data__;

      if (!Map || pairs.length < LARGE_ARRAY_SIZE - 1) {
        pairs.push([key, value]);
        this.size = ++data.size;
        return this;
      }

      data = this.__data__ = new MapCache(pairs);
    }

    data.set(key, value);
    this.size = data.size;
    return this;
  } // Add methods to `Stack`.

  Stack.prototype.clear = stackClear;
  Stack.prototype.delete = stackDelete;
  Stack.prototype.get = stackGet;
  Stack.prototype.has = stackHas;
  Stack.prototype.set = stackSet;
  /**
   * Creates an array of the enumerable property names of the array-like `value`.
   *
   * @private
   * @param {*} value The value to query.
   * @param {boolean} inherited Specify returning inherited property names.
   * @returns {Array} Returns the array of property names.
   */

  function arrayLikeKeys(value, inherited) {
    const isArr = isArray(value);
    const isArg = !isArr && isArguments(value);
    const isBuff = !isArr && !isArg && isBuffer(value);
    const isType = !isArr && !isArg && !isBuff && isTypedArray(value);
    const skipIndexes = isArr || isArg || isBuff || isType;
    const result = skipIndexes ? baseTimes(value.length, String) : [];
    const { length } = result;

    for (const key in value) {
      if ((inherited || hasOwnProperty.call(value, key)) && !(skipIndexes && ( // Safari 9 has enumerable `arguments.length` in strict mode.
        key == 'length' // Node.js 0.10 has enumerable non-index properties on buffers.
      || isBuff && (key == 'offset' || key == 'parent') // PhantomJS 2 has enumerable non-index properties on typed arrays.
      || isType && (key == 'buffer' || key == 'byteLength' || key == 'byteOffset') // Skip index properties.
      || isIndex(key, length)))) {
        result.push(key);
      }
    }

    return result;
  }
  /**
   * Gets the index at which the `key` is found in `array` of key-value pairs.
   *
   * @private
   * @param {Array} array The array to inspect.
   * @param {*} key The key to search for.
   * @returns {number} Returns the index of the matched value, else `-1`.
   */

  function assocIndexOf(array, key) {
    let { length } = array;

    while (length--) {
      if (eq(array[length][0], key)) {
        return length;
      }
    }

    return -1;
  }
  /**
   * The base implementation of `getAllKeys` and `getAllKeysIn` which uses
   * `keysFunc` and `symbolsFunc` to get the enumerable property names and
   * symbols of `object`.
   *
   * @private
   * @param {Object} object The object to query.
   * @param {Function} keysFunc The function to get the keys of `object`.
   * @param {Function} symbolsFunc The function to get the symbols of `object`.
   * @returns {Array} Returns the array of property names and symbols.
   */

  function baseGetAllKeys(object, keysFunc, symbolsFunc) {
    const result = keysFunc(object);
    return isArray(object) ? result : arrayPush(result, symbolsFunc(object));
  }
  /**
   * The base implementation of `getTag` without fallbacks for buggy environments.
   *
   * @private
   * @param {*} value The value to query.
   * @returns {string} Returns the `toStringTag`.
   */

  function baseGetTag(value) {
    if (value == null) {
      return value === undefined ? undefinedTag : nullTag;
    }

    return symToStringTag && symToStringTag in Object(value) ? getRawTag(value) : objectToString(value);
  }
  /**
   * The base implementation of `_.isArguments`.
   *
   * @private
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is an `arguments` object,
   */

  function baseIsArguments(value) {
    return isObjectLike(value) && baseGetTag(value) == argsTag;
  }
  /**
   * The base implementation of `_.isEqual` which supports partial comparisons
   * and tracks traversed objects.
   *
   * @private
   * @param {*} value The value to compare.
   * @param {*} other The other value to compare.
   * @param {boolean} bitmask The bitmask flags.
   *  1 - Unordered comparison
   *  2 - Partial comparison
   * @param {Function} [customizer] The function to customize comparisons.
   * @param {Object} [stack] Tracks traversed `value` and `other` objects.
   * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
   */

  function baseIsEqual(value, other, bitmask, customizer, stack) {
    if (value === other) {
      return true;
    }

    if (value == null || other == null || !isObjectLike(value) && !isObjectLike(other)) {
      return value !== value && other !== other;
    }

    return baseIsEqualDeep(value, other, bitmask, customizer, baseIsEqual, stack);
  }
  /**
   * A specialized version of `baseIsEqual` for arrays and objects which performs
   * deep comparisons and tracks traversed objects enabling objects with circular
   * references to be compared.
   *
   * @private
   * @param {Object} object The object to compare.
   * @param {Object} other The other object to compare.
   * @param {number} bitmask The bitmask flags. See `baseIsEqual` for more details.
   * @param {Function} customizer The function to customize comparisons.
   * @param {Function} equalFunc The function to determine equivalents of values.
   * @param {Object} [stack] Tracks traversed `object` and `other` objects.
   * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
   */

  function baseIsEqualDeep(object, other, bitmask, customizer, equalFunc, stack) {
    let objIsArr = isArray(object);
    const othIsArr = isArray(other);
    let objTag = objIsArr ? arrayTag : getTag(object);
    let othTag = othIsArr ? arrayTag : getTag(other);
    objTag = objTag == argsTag ? objectTag : objTag;
    othTag = othTag == argsTag ? objectTag : othTag;
    let objIsObj = objTag == objectTag;
    const othIsObj = othTag == objectTag;
    const isSameTag = objTag == othTag;

    if (isSameTag && isBuffer(object)) {
      if (!isBuffer(other)) {
        return false;
      }

      objIsArr = true;
      objIsObj = false;
    }

    if (isSameTag && !objIsObj) {
      stack || (stack = new Stack());
      return objIsArr || isTypedArray(object) ? equalArrays(object, other, bitmask, customizer, equalFunc, stack) : equalByTag(object, other, objTag, bitmask, customizer, equalFunc, stack);
    }

    if (!(bitmask & COMPARE_PARTIAL_FLAG)) {
      const objIsWrapped = objIsObj && hasOwnProperty.call(object, '__wrapped__');
      const othIsWrapped = othIsObj && hasOwnProperty.call(other, '__wrapped__');

      if (objIsWrapped || othIsWrapped) {
        const objUnwrapped = objIsWrapped ? object.value() : object;
        const othUnwrapped = othIsWrapped ? other.value() : other;
        stack || (stack = new Stack());
        return equalFunc(objUnwrapped, othUnwrapped, bitmask, customizer, stack);
      }
    }

    if (!isSameTag) {
      return false;
    }

    stack || (stack = new Stack());
    return equalObjects(object, other, bitmask, customizer, equalFunc, stack);
  }
  /**
   * The base implementation of `_.isNative` without bad shim checks.
   *
   * @private
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a native function,
   *  else `false`.
   */

  function baseIsNative(value) {
    if (!isObject(value) || isMasked(value)) {
      return false;
    }

    const pattern = isFunction(value) ? reIsNative : reIsHostCtor;
    return pattern.test(toSource(value));
  }
  /**
   * The base implementation of `_.isTypedArray` without Node.js optimizations.
   *
   * @private
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a typed array, else `false`.
   */

  function baseIsTypedArray(value) {
    return isObjectLike(value) && isLength(value.length) && !!typedArrayTags[baseGetTag(value)];
  }
  /**
   * The base implementation of `_.keys` which doesn't treat sparse arrays as dense.
   *
   * @private
   * @param {Object} object The object to query.
   * @returns {Array} Returns the array of property names.
   */

  function baseKeys(object) {
    if (!isPrototype(object)) {
      return nativeKeys(object);
    }

    const result = [];

    for (const key in Object(object)) {
      if (hasOwnProperty.call(object, key) && key != 'constructor') {
        result.push(key);
      }
    }

    return result;
  }
  /**
   * A specialized version of `baseIsEqualDeep` for arrays with support for
   * partial deep comparisons.
   *
   * @private
   * @param {Array} array The array to compare.
   * @param {Array} other The other array to compare.
   * @param {number} bitmask The bitmask flags. See `baseIsEqual` for more details.
   * @param {Function} customizer The function to customize comparisons.
   * @param {Function} equalFunc The function to determine equivalents of values.
   * @param {Object} stack Tracks traversed `array` and `other` objects.
   * @returns {boolean} Returns `true` if the arrays are equivalent, else `false`.
   */

  function equalArrays(array, other, bitmask, customizer, equalFunc, stack) {
    const isPartial = bitmask & COMPARE_PARTIAL_FLAG;
    const arrLength = array.length;
    const othLength = other.length;

    if (arrLength != othLength && !(isPartial && othLength > arrLength)) {
      return false;
    } // Assume cyclic values are equal.

    const stacked = stack.get(array);

    if (stacked && stack.get(other)) {
      return stacked == other;
    }

    let index = -1;
    let result = true;
    const seen = bitmask & COMPARE_UNORDERED_FLAG ? new SetCache() : undefined;
    stack.set(array, other);
    stack.set(other, array); // Ignore non-index properties.

    while (++index < arrLength) {
      var arrValue = array[index];
      const othValue = other[index];

      if (customizer) {
        var compared = isPartial ? customizer(othValue, arrValue, index, other, array, stack) : customizer(arrValue, othValue, index, array, other, stack);
      }

      if (compared !== undefined) {
        if (compared) {
          continue;
        }

        result = false;
        break;
      } // Recursively compare arrays (susceptible to call stack limits).

      if (seen) {
        if (!arraySome(other, (othValue, othIndex) => {
          if (!cacheHas(seen, othIndex) && (arrValue === othValue || equalFunc(arrValue, othValue, bitmask, customizer, stack))) {
            return seen.push(othIndex);
          }
        })) {
          result = false;
          break;
        }
      } else if (!(arrValue === othValue || equalFunc(arrValue, othValue, bitmask, customizer, stack))) {
        result = false;
        break;
      }
    }

    stack.delete(array);
    stack.delete(other);
    return result;
  }
  /**
   * A specialized version of `baseIsEqualDeep` for comparing objects of
   * the same `toStringTag`.
   *
   * **Note:** This function only supports comparing values with tags of
   * `Boolean`, `Date`, `Error`, `Number`, `RegExp`, or `String`.
   *
   * @private
   * @param {Object} object The object to compare.
   * @param {Object} other The other object to compare.
   * @param {string} tag The `toStringTag` of the objects to compare.
   * @param {number} bitmask The bitmask flags. See `baseIsEqual` for more details.
   * @param {Function} customizer The function to customize comparisons.
   * @param {Function} equalFunc The function to determine equivalents of values.
   * @param {Object} stack Tracks traversed `object` and `other` objects.
   * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
   */

  function equalByTag(object, other, tag, bitmask, customizer, equalFunc, stack) {
    switch (tag) {
      case dataViewTag:
        if (object.byteLength != other.byteLength || object.byteOffset != other.byteOffset) {
          return false;
        }

        object = object.buffer;
        other = other.buffer;

      case arrayBufferTag:
        if (object.byteLength != other.byteLength || !equalFunc(new Uint8Array(object), new Uint8Array(other))) {
          return false;
        }

        return true;

      case boolTag:
      case dateTag:
      case numberTag:
        // Coerce booleans to `1` or `0` and dates to milliseconds.
        // Invalid dates are coerced to `NaN`.
        return eq(+object, +other);

      case errorTag:
        return object.name == other.name && object.message == other.message;

      case regexpTag:
      case stringTag:
        // Coerce regexes to strings and treat strings, primitives and objects,
        // as equal. See http://www.ecma-international.org/ecma-262/7.0/#sec-regexp.prototype.tostring
        // for more details.
        return object == `${other}`;

      case mapTag:
        var convert = mapToArray;

      case setTag:
        var isPartial = bitmask & COMPARE_PARTIAL_FLAG;
        convert || (convert = setToArray);

        if (object.size != other.size && !isPartial) {
          return false;
        } // Assume cyclic values are equal.

        var stacked = stack.get(object);

        if (stacked) {
          return stacked == other;
        }

        bitmask |= COMPARE_UNORDERED_FLAG; // Recursively compare objects (susceptible to call stack limits).

        stack.set(object, other);
        var result = equalArrays(convert(object), convert(other), bitmask, customizer, equalFunc, stack);
        stack.delete(object);
        return result;

      case symbolTag:
        if (symbolValueOf) {
          return symbolValueOf.call(object) == symbolValueOf.call(other);
        }
    }

    return false;
  }
  /**
   * A specialized version of `baseIsEqualDeep` for objects with support for
   * partial deep comparisons.
   *
   * @private
   * @param {Object} object The object to compare.
   * @param {Object} other The other object to compare.
   * @param {number} bitmask The bitmask flags. See `baseIsEqual` for more details.
   * @param {Function} customizer The function to customize comparisons.
   * @param {Function} equalFunc The function to determine equivalents of values.
   * @param {Object} stack Tracks traversed `object` and `other` objects.
   * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
   */

  function equalObjects(object, other, bitmask, customizer, equalFunc, stack) {
    const isPartial = bitmask & COMPARE_PARTIAL_FLAG;
    const objProps = getAllKeys(object);
    const objLength = objProps.length;
    const othProps = getAllKeys(other);
    const othLength = othProps.length;

    if (objLength != othLength && !isPartial) {
      return false;
    }

    let index = objLength;

    while (index--) {
      var key = objProps[index];

      if (!(isPartial ? key in other : hasOwnProperty.call(other, key))) {
        return false;
      }
    } // Assume cyclic values are equal.

    const stacked = stack.get(object);

    if (stacked && stack.get(other)) {
      return stacked == other;
    }

    let result = true;
    stack.set(object, other);
    stack.set(other, object);
    let skipCtor = isPartial;

    while (++index < objLength) {
      key = objProps[index];
      const objValue = object[key];
      const othValue = other[key];

      if (customizer) {
        var compared = isPartial ? customizer(othValue, objValue, key, other, object, stack) : customizer(objValue, othValue, key, object, other, stack);
      } // Recursively compare objects (susceptible to call stack limits).

      if (!(compared === undefined ? objValue === othValue || equalFunc(objValue, othValue, bitmask, customizer, stack) : compared)) {
        result = false;
        break;
      }

      skipCtor || (skipCtor = key == 'constructor');
    }

    if (result && !skipCtor) {
      const objCtor = object.constructor;
      const othCtor = other.constructor; // Non `Object` object instances with different constructors are not equal.

      if (objCtor != othCtor && 'constructor' in object && 'constructor' in other && !(typeof objCtor === 'function' && objCtor instanceof objCtor && typeof othCtor === 'function' && othCtor instanceof othCtor)) {
        result = false;
      }
    }

    stack.delete(object);
    stack.delete(other);
    return result;
  }
  /**
   * Creates an array of own enumerable property names and symbols of `object`.
   *
   * @private
   * @param {Object} object The object to query.
   * @returns {Array} Returns the array of property names and symbols.
   */

  function getAllKeys(object) {
    return baseGetAllKeys(object, keys, getSymbols);
  }
  /**
   * Gets the data for `map`.
   *
   * @private
   * @param {Object} map The map to query.
   * @param {string} key The reference key.
   * @returns {*} Returns the map data.
   */

  function getMapData(map, key) {
    const data = map.__data__;
    return isKeyable(key) ? data[typeof key === 'string' ? 'string' : 'hash'] : data.map;
  }
  /**
   * Gets the native function at `key` of `object`.
   *
   * @private
   * @param {Object} object The object to query.
   * @param {string} key The key of the method to get.
   * @returns {*} Returns the function if it's native, else `undefined`.
   */

  function getNative(object, key) {
    const value = getValue(object, key);
    return baseIsNative(value) ? value : undefined;
  }
  /**
   * A specialized version of `baseGetTag` which ignores `Symbol.toStringTag` values.
   *
   * @private
   * @param {*} value The value to query.
   * @returns {string} Returns the raw `toStringTag`.
   */

  function getRawTag(value) {
    const isOwn = hasOwnProperty.call(value, symToStringTag);
    const tag = value[symToStringTag];

    try {
      value[symToStringTag] = undefined;
      var unmasked = true;
    } catch (e) {}

    const result = nativeObjectToString.call(value);

    if (unmasked) {
      if (isOwn) {
        value[symToStringTag] = tag;
      } else {
        delete value[symToStringTag];
      }
    }

    return result;
  }
  /**
   * Creates an array of the own enumerable symbols of `object`.
   *
   * @private
   * @param {Object} object The object to query.
   * @returns {Array} Returns the array of symbols.
   */

  var getSymbols = !nativeGetSymbols ? stubArray : function (object) {
    if (object == null) {
      return [];
    }

    object = Object(object);
    return arrayFilter(nativeGetSymbols(object), (symbol) => propertyIsEnumerable.call(object, symbol));
  };
  /**
   * Gets the `toStringTag` of `value`.
   *
   * @private
   * @param {*} value The value to query.
   * @returns {string} Returns the `toStringTag`.
   */

  var getTag = baseGetTag; // Fallback for data views, maps, sets, and weak maps in IE 11 and promises in Node.js < 6.

  if (DataView && getTag(new DataView(new ArrayBuffer(1))) != dataViewTag || Map && getTag(new Map()) != mapTag || Promise && getTag(Promise.resolve()) != promiseTag || Set && getTag(new Set()) != setTag || WeakMap && getTag(new WeakMap()) != weakMapTag) {
    getTag = function (value) {
      const result = baseGetTag(value);
      const Ctor = result == objectTag ? value.constructor : undefined;
      const ctorString = Ctor ? toSource(Ctor) : '';

      if (ctorString) {
        switch (ctorString) {
          case dataViewCtorString:
            return dataViewTag;

          case mapCtorString:
            return mapTag;

          case promiseCtorString:
            return promiseTag;

          case setCtorString:
            return setTag;

          case weakMapCtorString:
            return weakMapTag;
        }
      }

      return result;
    };
  }
  /**
   * Checks if `value` is a valid array-like index.
   *
   * @private
   * @param {*} value The value to check.
   * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
   * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
   */

  function isIndex(value, length) {
    length = length == null ? MAX_SAFE_INTEGER : length;
    return !!length && (typeof value === 'number' || reIsUint.test(value)) && value > -1 && value % 1 == 0 && value < length;
  }
  /**
   * Checks if `value` is suitable for use as unique object key.
   *
   * @private
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is suitable, else `false`.
   */

  function isKeyable(value) {
    const type = typeof value;
    return type == 'string' || type == 'number' || type == 'symbol' || type == 'boolean' ? value !== '__proto__' : value === null;
  }
  /**
   * Checks if `func` has its source masked.
   *
   * @private
   * @param {Function} func The function to check.
   * @returns {boolean} Returns `true` if `func` is masked, else `false`.
   */

  function isMasked(func) {
    return !!maskSrcKey && maskSrcKey in func;
  }
  /**
   * Checks if `value` is likely a prototype object.
   *
   * @private
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a prototype, else `false`.
   */

  function isPrototype(value) {
    const Ctor = value && value.constructor;
    const proto = typeof Ctor === 'function' && Ctor.prototype || objectProto;
    return value === proto;
  }
  /**
   * Converts `value` to a string using `Object.prototype.toString`.
   *
   * @private
   * @param {*} value The value to convert.
   * @returns {string} Returns the converted string.
   */

  function objectToString(value) {
    return nativeObjectToString.call(value);
  }
  /**
   * Converts `func` to its source code.
   *
   * @private
   * @param {Function} func The function to convert.
   * @returns {string} Returns the source code.
   */

  function toSource(func) {
    if (func != null) {
      try {
        return funcToString.call(func);
      } catch (e) {}

      try {
        return `${func}`;
      } catch (e) {}
    }

    return '';
  }
  /**
   * Performs a
   * [`SameValueZero`](http://ecma-international.org/ecma-262/7.0/#sec-samevaluezero)
   * comparison between two values to determine if they are equivalent.
   *
   * @static
   * @memberOf _
   * @since 4.0.0
   * @category Lang
   * @param {*} value The value to compare.
   * @param {*} other The other value to compare.
   * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
   * @example
   *
   * var object = { 'a': 1 };
   * var other = { 'a': 1 };
   *
   * _.eq(object, object);
   * // => true
   *
   * _.eq(object, other);
   * // => false
   *
   * _.eq('a', 'a');
   * // => true
   *
   * _.eq('a', Object('a'));
   * // => false
   *
   * _.eq(NaN, NaN);
   * // => true
   */

  function eq(value, other) {
    return value === other || value !== value && other !== other;
  }
  /**
   * Checks if `value` is likely an `arguments` object.
   *
   * @static
   * @memberOf _
   * @since 0.1.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is an `arguments` object,
   *  else `false`.
   * @example
   *
   * _.isArguments(function() { return arguments; }());
   * // => true
   *
   * _.isArguments([1, 2, 3]);
   * // => false
   */

  var isArguments = baseIsArguments(function () {
    return arguments;
  }()) ? baseIsArguments : function (value) {
      return isObjectLike(value) && hasOwnProperty.call(value, 'callee') && !propertyIsEnumerable.call(value, 'callee');
    };
  /**
   * Checks if `value` is classified as an `Array` object.
   *
   * @static
   * @memberOf _
   * @since 0.1.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is an array, else `false`.
   * @example
   *
   * _.isArray([1, 2, 3]);
   * // => true
   *
   * _.isArray(document.body.children);
   * // => false
   *
   * _.isArray('abc');
   * // => false
   *
   * _.isArray(_.noop);
   * // => false
   */

  var { isArray } = Array;
  /**
   * Checks if `value` is array-like. A value is considered array-like if it's
   * not a function and has a `value.length` that's an integer greater than or
   * equal to `0` and less than or equal to `Number.MAX_SAFE_INTEGER`.
   *
   * @static
   * @memberOf _
   * @since 4.0.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
   * @example
   *
   * _.isArrayLike([1, 2, 3]);
   * // => true
   *
   * _.isArrayLike(document.body.children);
   * // => true
   *
   * _.isArrayLike('abc');
   * // => true
   *
   * _.isArrayLike(_.noop);
   * // => false
   */

  function isArrayLike(value) {
    return value != null && isLength(value.length) && !isFunction(value);
  }
  /**
   * Checks if `value` is a buffer.
   *
   * @static
   * @memberOf _
   * @since 4.3.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a buffer, else `false`.
   * @example
   *
   * _.isBuffer(new Buffer(2));
   * // => true
   *
   * _.isBuffer(new Uint8Array(2));
   * // => false
   */

  var isBuffer = nativeIsBuffer || stubFalse;
  /**
   * Performs a deep comparison between two values to determine if they are
   * equivalent.
   *
   * **Note:** This method supports comparing arrays, array buffers, booleans,
   * date objects, error objects, maps, numbers, `Object` objects, regexes,
   * sets, strings, symbols, and typed arrays. `Object` objects are compared
   * by their own, not inherited, enumerable properties. Functions and DOM
   * nodes are compared by strict equality, i.e. `===`.
   *
   * @static
   * @memberOf _
   * @since 0.1.0
   * @category Lang
   * @param {*} value The value to compare.
   * @param {*} other The other value to compare.
   * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
   * @example
   *
   * var object = { 'a': 1 };
   * var other = { 'a': 1 };
   *
   * _.isEqual(object, other);
   * // => true
   *
   * object === other;
   * // => false
   */

  function isEqual(value, other) {
    return baseIsEqual(value, other);
  }
  /**
   * Checks if `value` is classified as a `Function` object.
   *
   * @static
   * @memberOf _
   * @since 0.1.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a function, else `false`.
   * @example
   *
   * _.isFunction(_);
   * // => true
   *
   * _.isFunction(/abc/);
   * // => false
   */

  function isFunction(value) {
    if (!isObject(value)) {
      return false;
    } // The use of `Object#toString` avoids issues with the `typeof` operator
    // in Safari 9 which returns 'object' for typed arrays and other constructors.

    const tag = baseGetTag(value);
    return tag == funcTag || tag == genTag || tag == asyncTag || tag == proxyTag;
  }
  /**
   * Checks if `value` is a valid array-like length.
   *
   * **Note:** This method is loosely based on
   * [`ToLength`](http://ecma-international.org/ecma-262/7.0/#sec-tolength).
   *
   * @static
   * @memberOf _
   * @since 4.0.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
   * @example
   *
   * _.isLength(3);
   * // => true
   *
   * _.isLength(Number.MIN_VALUE);
   * // => false
   *
   * _.isLength(Infinity);
   * // => false
   *
   * _.isLength('3');
   * // => false
   */

  function isLength(value) {
    return typeof value === 'number' && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
  }
  /**
   * Checks if `value` is the
   * [language type](http://www.ecma-international.org/ecma-262/7.0/#sec-ecmascript-language-types)
   * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
   *
   * @static
   * @memberOf _
   * @since 0.1.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is an object, else `false`.
   * @example
   *
   * _.isObject({});
   * // => true
   *
   * _.isObject([1, 2, 3]);
   * // => true
   *
   * _.isObject(_.noop);
   * // => true
   *
   * _.isObject(null);
   * // => false
   */

  function isObject(value) {
    const type = typeof value;
    return value != null && (type == 'object' || type == 'function');
  }
  /**
   * Checks if `value` is object-like. A value is object-like if it's not `null`
   * and has a `typeof` result of "object".
   *
   * @static
   * @memberOf _
   * @since 4.0.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
   * @example
   *
   * _.isObjectLike({});
   * // => true
   *
   * _.isObjectLike([1, 2, 3]);
   * // => true
   *
   * _.isObjectLike(_.noop);
   * // => false
   *
   * _.isObjectLike(null);
   * // => false
   */

  function isObjectLike(value) {
    return value != null && typeof value === 'object';
  }
  /**
   * Checks if `value` is classified as a typed array.
   *
   * @static
   * @memberOf _
   * @since 3.0.0
   * @category Lang
   * @param {*} value The value to check.
   * @returns {boolean} Returns `true` if `value` is a typed array, else `false`.
   * @example
   *
   * _.isTypedArray(new Uint8Array);
   * // => true
   *
   * _.isTypedArray([]);
   * // => false
   */

  var isTypedArray = nodeIsTypedArray ? baseUnary(nodeIsTypedArray) : baseIsTypedArray;
  /**
   * Creates an array of the own enumerable property names of `object`.
   *
   * **Note:** Non-object values are coerced to objects. See the
   * [ES spec](http://ecma-international.org/ecma-262/7.0/#sec-object.keys)
   * for more details.
   *
   * @static
   * @since 0.1.0
   * @memberOf _
   * @category Object
   * @param {Object} object The object to query.
   * @returns {Array} Returns the array of property names.
   * @example
   *
   * function Foo() {
   *   this.a = 1;
   *   this.b = 2;
   * }
   *
   * Foo.prototype.c = 3;
   *
   * _.keys(new Foo);
   * // => ['a', 'b'] (iteration order is not guaranteed)
   *
   * _.keys('hi');
   * // => ['0', '1']
   */

  function keys(object) {
    return isArrayLike(object) ? arrayLikeKeys(object) : baseKeys(object);
  }
  /**
   * This method returns a new empty array.
   *
   * @static
   * @memberOf _
   * @since 4.13.0
   * @category Util
   * @returns {Array} Returns the new empty array.
   * @example
   *
   * var arrays = _.times(2, _.stubArray);
   *
   * console.log(arrays);
   * // => [[], []]
   *
   * console.log(arrays[0] === arrays[1]);
   * // => false
   */

  function stubArray() {
    return [];
  }
  /**
   * This method returns `false`.
   *
   * @static
   * @memberOf _
   * @since 4.13.0
   * @category Util
   * @returns {boolean} Returns `false`.
   * @example
   *
   * _.times(2, _.stubFalse);
   * // => [false, false]
   */

  function stubFalse() {
    return false;
  }

  module.exports = isEqual;
}(lodash_isequal, lodash_isequal.exports));

const munkres$1 = { exports: {} };

/**
 * Introduction
 * ============
 *
 * The Munkres module provides an implementation of the Munkres algorithm
 * (also called the Hungarian algorithm or the Kuhn-Munkres algorithm),
 * useful for solving the Assignment Problem.
 *
 * Assignment Problem
 * ==================
 *
 * Let C be an n×n-matrix representing the costs of each of n workers
 * to perform any of n jobs. The assignment problem is to assign jobs to
 * workers in a way that minimizes the total cost. Since each worker can perform
 * only one job and each job can be assigned to only one worker the assignments
 * represent an independent set of the matrix C.
 *
 * One way to generate the optimal set is to create all permutations of
 * the indices necessary to traverse the matrix so that no row and column
 * are used more than once. For instance, given this matrix (expressed in
 * Python)
 *
 *  matrix = [[5, 9, 1],
 *        [10, 3, 2],
 *        [8, 7, 4]]
 *
 * You could use this code to generate the traversal indices::
 *
 *  def permute(a, results):
 *    if len(a) == 1:
 *      results.insert(len(results), a)
 *
 *    else:
 *      for i in range(0, len(a)):
 *        element = a[i]
 *        a_copy = [a[j] for j in range(0, len(a)) if j != i]
 *        subresults = []
 *        permute(a_copy, subresults)
 *        for subresult in subresults:
 *          result = [element] + subresult
 *          results.insert(len(results), result)
 *
 *  results = []
 *  permute(range(len(matrix)), results) # [0, 1, 2] for a 3x3 matrix
 *
 * After the call to permute(), the results matrix would look like this::
 *
 *  [[0, 1, 2],
 *   [0, 2, 1],
 *   [1, 0, 2],
 *   [1, 2, 0],
 *   [2, 0, 1],
 *   [2, 1, 0]]
 *
 * You could then use that index matrix to loop over the original cost matrix
 * and calculate the smallest cost of the combinations
 *
 *  n = len(matrix)
 *  minval = sys.maxsize
 *  for row in range(n):
 *    cost = 0
 *    for col in range(n):
 *      cost += matrix[row][col]
 *    minval = min(cost, minval)
 *
 *  print minval
 *
 * While this approach works fine for small matrices, it does not scale. It
 * executes in O(n!) time: Calculating the permutations for an n×x-matrix
 * requires n! operations. For a 12×12 matrix, that’s 479,001,600
 * traversals. Even if you could manage to perform each traversal in just one
 * millisecond, it would still take more than 133 hours to perform the entire
 * traversal. A 20×20 matrix would take 2,432,902,008,176,640,000 operations. At
 * an optimistic millisecond per operation, that’s more than 77 million years.
 *
 * The Munkres algorithm runs in O(n³) time, rather than O(n!). This
 * package provides an implementation of that algorithm.
 *
 * This version is based on
 * http://csclab.murraystate.edu/~bob.pilgrim/445/munkres.html
 *
 * This version was originally written for Python by Brian Clapper from the
 * algorithm at the above web site (The ``Algorithm::Munkres`` Perl version,
 * in CPAN, was clearly adapted from the same web site.) and ported to
 * JavaScript by Anna Henningsen (addaleax).
 *
 * Usage
 * =====
 *
 * Construct a Munkres object
 *
 *  var m = new Munkres();
 *
 * Then use it to compute the lowest cost assignment from a cost matrix. Here’s
 * a sample program
 *
 *  var matrix = [[5, 9, 1],
 *           [10, 3, 2],
 *           [8, 7, 4]];
 *  var m = new Munkres();
 *  var indices = m.compute(matrix);
 *  console.log(format_matrix(matrix), 'Lowest cost through this matrix:');
 *  var total = 0;
 *  for (var i = 0; i < indices.length; ++i) {
 *    var row = indices[l][0], col = indices[l][1];
 *    var value = matrix[row][col];
 *    total += value;
 *
 *    console.log('(' + rol + ', ' + col + ') -> ' + value);
 *  }
 *
 *  console.log('total cost:', total);
 *
 * Running that program produces::
 *
 *  Lowest cost through this matrix:
 *  [5, 9, 1]
 *  [10, 3, 2]
 *  [8, 7, 4]
 *  (0, 0) -> 5
 *  (1, 1) -> 3
 *  (2, 2) -> 4
 *  total cost: 12
 *
 * The instantiated Munkres object can be used multiple times on different
 * matrices.
 *
 * Non-square Cost Matrices
 * ========================
 *
 * The Munkres algorithm assumes that the cost matrix is square. However, it's
 * possible to use a rectangular matrix if you first pad it with 0 values to make
 * it square. This module automatically pads rectangular cost matrices to make
 * them square.
 *
 * Notes:
 *
 * - The module operates on a *copy* of the caller's matrix, so any padding will
 *   not be seen by the caller.
 * - The cost matrix must be rectangular or square. An irregular matrix will
 *   *not* work.
 *
 * Calculating Profit, Rather than Cost
 * ====================================
 *
 * The cost matrix is just that: A cost matrix. The Munkres algorithm finds
 * the combination of elements (one from each row and column) that results in
 * the smallest cost. It’s also possible to use the algorithm to maximize
 * profit. To do that, however, you have to convert your profit matrix to a
 * cost matrix. The simplest way to do that is to subtract all elements from a
 * large value.
 *
 * The ``munkres`` module provides a convenience method for creating a cost
 * matrix from a profit matrix, i.e. make_cost_matrix.
 *
 * References
 * ==========
 *
 * 1. http://www.public.iastate.edu/~ddoty/HungarianAlgorithm.html
 *
 * 2. Harold W. Kuhn. The Hungarian Method for the assignment problem.
 *    *Naval Research Logistics Quarterly*, 2:83-97, 1955.
 *
 * 3. Harold W. Kuhn. Variants of the Hungarian method for assignment
 *    problems. *Naval Research Logistics Quarterly*, 3: 253-258, 1956.
 *
 * 4. Munkres, J. Algorithms for the Assignment and Transportation Problems.
 *    *Journal of the Society of Industrial and Applied Mathematics*,
 *    5(1):32-38, March, 1957.
 *
 * 5. https://en.wikipedia.org/wiki/Hungarian_algorithm
 *
 * Copyright and License
 * =====================
 *
 * Copyright 2008-2016 Brian M. Clapper
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

(function (module) {
  /**
   * A very large numerical value which can be used like an integer
   * (i. e., adding integers of similar size does not result in overflow).
   */
  const MAX_SIZE = parseInt(Number.MAX_SAFE_INTEGER / 2) || (1 << 26) * (1 << 26);
  /**
   * A default value to pad the cost matrix with if it is not quadratic.
   */

  const DEFAULT_PAD_VALUE = 0; // ---------------------------------------------------------------------------
  // Classes
  // ---------------------------------------------------------------------------

  /**
   * Calculate the Munkres solution to the classical assignment problem.
   * See the module documentation for usage.
   * @constructor
   */

  function Munkres() {
    this.C = null;
    this.row_covered = [];
    this.col_covered = [];
    this.n = 0;
    this.Z0_r = 0;
    this.Z0_c = 0;
    this.marked = null;
    this.path = null;
  }
  /**
   * Pad a possibly non-square matrix to make it square.
   *
   * @param {Array} matrix An array of arrays containing the matrix cells
   * @param {Number} [pad_value] The value used to pad a rectangular matrix
   *
   * @return {Array} An array of arrays representing the padded matrix
   */

  Munkres.prototype.pad_matrix = function (matrix, pad_value) {
    pad_value = pad_value || DEFAULT_PAD_VALUE;
    let max_columns = 0;
    let total_rows = matrix.length;
    let i;

    for (i = 0; i < total_rows; ++i) if (matrix[i].length > max_columns) max_columns = matrix[i].length;

    total_rows = max_columns > total_rows ? max_columns : total_rows;
    const new_matrix = [];

    for (i = 0; i < total_rows; ++i) {
      const row = matrix[i] || [];
      const new_row = row.slice(); // If this row is too short, pad it

      while (total_rows > new_row.length) new_row.push(pad_value);

      new_matrix.push(new_row);
    }

    return new_matrix;
  };
  /**
   * Compute the indices for the lowest-cost pairings between rows and columns
   * in the database. Returns a list of (row, column) tuples that can be used
   * to traverse the matrix.
   *
   * **WARNING**: This code handles square and rectangular matrices.
   * It does *not* handle irregular matrices.
   *
   * @param {Array} cost_matrix The cost matrix. If this cost matrix is not square,
   *                            it will be padded with DEFAULT_PAD_VALUE. Optionally,
   *                            the pad value can be specified via options.padValue.
   *                            This method does *not* modify the caller's matrix.
   *                            It operates on a copy of the matrix.
   * @param {Object} [options] Additional options to pass in
   * @param {Number} [options.padValue] The value to use to pad a rectangular cost_matrix
   *
   * @return {Array} An array of ``(row, column)`` arrays that describe the lowest
   *                 cost path through the matrix
   */

  Munkres.prototype.compute = function (cost_matrix, options) {
    options = options || {};
    options.padValue = options.padValue || DEFAULT_PAD_VALUE;
    this.C = this.pad_matrix(cost_matrix, options.padValue);
    this.n = this.C.length;
    this.original_length = cost_matrix.length;
    this.original_width = cost_matrix[0].length;
    const nfalseArray = [];
    /* array of n false values */

    while (nfalseArray.length < this.n) nfalseArray.push(false);

    this.row_covered = nfalseArray.slice();
    this.col_covered = nfalseArray.slice();
    this.Z0_r = 0;
    this.Z0_c = 0;
    this.path = this.__make_matrix(this.n * 2, 0);
    this.marked = this.__make_matrix(this.n, 0);
    let step = 1;
    const steps = {
      1: this.__step1,
      2: this.__step2,
      3: this.__step3,
      4: this.__step4,
      5: this.__step5,
      6: this.__step6,
    };

    while (true) {
      const func = steps[step];
      if (!func) // done
      { break; }
      step = func.apply(this);
    }

    const results = [];

    for (let i = 0; i < this.original_length; ++i) for (let j = 0; j < this.original_width; ++j) if (this.marked[i][j] == 1) results.push([i, j]);

    return results;
  };
  /**
   * Create an n×n matrix, populating it with the specific value.
   *
   * @param {Number} n Matrix dimensions
   * @param {Number} val Value to populate the matrix with
   *
   * @return {Array} An array of arrays representing the newly created matrix
   */

  Munkres.prototype.__make_matrix = function (n, val) {
    const matrix = [];

    for (let i = 0; i < n; ++i) {
      matrix[i] = [];

      for (let j = 0; j < n; ++j) matrix[i][j] = val;
    }

    return matrix;
  };
  /**
   * For each row of the matrix, find the smallest element and
   * subtract it from every element in its row. Go to Step 2.
   */

  Munkres.prototype.__step1 = function () {
    for (let i = 0; i < this.n; ++i) {
      // Find the minimum value for this row and subtract that minimum
      // from every element in the row.
      const minval = Math.min.apply(Math, this.C[i]);

      for (let j = 0; j < this.n; ++j) this.C[i][j] -= minval;
    }

    return 2;
  };
  /**
   * Find a zero (Z) in the resulting matrix. If there is no starred
   * zero in its row or column, star Z. Repeat for each element in the
   * matrix. Go to Step 3.
   */

  Munkres.prototype.__step2 = function () {
    for (let i = 0; i < this.n; ++i) {
      for (let j = 0; j < this.n; ++j) {
        if (this.C[i][j] === 0 && !this.col_covered[j] && !this.row_covered[i]) {
          this.marked[i][j] = 1;
          this.col_covered[j] = true;
          this.row_covered[i] = true;
          break;
        }
      }
    }

    this.__clear_covers();

    return 3;
  };
  /**
   * Cover each column containing a starred zero. If K columns are
   * covered, the starred zeros describe a complete set of unique
   * assignments. In this case, Go to DONE, otherwise, Go to Step 4.
   */

  Munkres.prototype.__step3 = function () {
    let count = 0;

    for (let i = 0; i < this.n; ++i) {
      for (let j = 0; j < this.n; ++j) {
        if (this.marked[i][j] == 1 && this.col_covered[j] == false) {
          this.col_covered[j] = true;
          ++count;
        }
      }
    }

    return count >= this.n ? 7 : 4;
  };
  /**
   * Find a noncovered zero and prime it. If there is no starred zero
   * in the row containing this primed zero, Go to Step 5. Otherwise,
   * cover this row and uncover the column containing the starred
   * zero. Continue in this manner until there are no uncovered zeros
   * left. Save the smallest uncovered value and Go to Step 6.
   */

  Munkres.prototype.__step4 = function () {
    const done = false;
    let row = -1;
    let col = -1;
    let star_col = -1;

    while (!done) {
      const z = this.__find_a_zero();

      row = z[0];
      col = z[1];
      if (row < 0) return 6;
      this.marked[row][col] = 2;
      star_col = this.__find_star_in_row(row);

      if (star_col >= 0) {
        col = star_col;
        this.row_covered[row] = true;
        this.col_covered[col] = false;
      } else {
        this.Z0_r = row;
        this.Z0_c = col;
        return 5;
      }
    }
  };
  /**
   * Construct a series of alternating primed and starred zeros as
   * follows. Let Z0 represent the uncovered primed zero found in Step 4.
   * Let Z1 denote the starred zero in the column of Z0 (if any).
   * Let Z2 denote the primed zero in the row of Z1 (there will always
   * be one). Continue until the series terminates at a primed zero
   * that has no starred zero in its column. Unstar each starred zero
   * of the series, star each primed zero of the series, erase all
   * primes and uncover every line in the matrix. Return to Step 3
   */

  Munkres.prototype.__step5 = function () {
    let count = 0;
    this.path[count][0] = this.Z0_r;
    this.path[count][1] = this.Z0_c;
    let done = false;

    while (!done) {
      const row = this.__find_star_in_col(this.path[count][1]);

      if (row >= 0) {
        count++;
        this.path[count][0] = row;
        this.path[count][1] = this.path[count - 1][1];
      } else {
        done = true;
      }

      if (!done) {
        const col = this.__find_prime_in_row(this.path[count][0]);

        count++;
        this.path[count][0] = this.path[count - 1][0];
        this.path[count][1] = col;
      }
    }

    this.__convert_path(this.path, count);

    this.__clear_covers();

    this.__erase_primes();

    return 3;
  };
  /**
   * Add the value found in Step 4 to every element of each covered
   * row, and subtract it from every element of each uncovered column.
   * Return to Step 4 without altering any stars, primes, or covered
   * lines.
   */

  Munkres.prototype.__step6 = function () {
    const minval = this.__find_smallest();

    for (let i = 0; i < this.n; ++i) {
      for (let j = 0; j < this.n; ++j) {
        if (this.row_covered[i]) this.C[i][j] += minval;
        if (!this.col_covered[j]) this.C[i][j] -= minval;
      }
    }

    return 4;
  };
  /**
   * Find the smallest uncovered value in the matrix.
   *
   * @return {Number} The smallest uncovered value, or MAX_SIZE if no value was found
   */

  Munkres.prototype.__find_smallest = function () {
    let minval = MAX_SIZE;

    for (let i = 0; i < this.n; ++i) for (let j = 0; j < this.n; ++j) if (!this.row_covered[i] && !this.col_covered[j]) if (minval > this.C[i][j]) minval = this.C[i][j];

    return minval;
  };
  /**
   * Find the first uncovered element with value 0.
   *
   * @return {Array} The indices of the found element or [-1, -1] if not found
   */

  Munkres.prototype.__find_a_zero = function () {
    for (let i = 0; i < this.n; ++i) for (let j = 0; j < this.n; ++j) if (this.C[i][j] === 0 && !this.row_covered[i] && !this.col_covered[j]) return [i, j];

    return [-1, -1];
  };
  /**
   * Find the first starred element in the specified row. Returns
   * the column index, or -1 if no starred element was found.
   *
   * @param {Number} row The index of the row to search
   * @return {Number}
   */

  Munkres.prototype.__find_star_in_row = function (row) {
    for (let j = 0; j < this.n; ++j) if (this.marked[row][j] == 1) return j;

    return -1;
  };
  /**
   * Find the first starred element in the specified column.
   *
   * @return {Number} The row index, or -1 if no starred element was found
   */

  Munkres.prototype.__find_star_in_col = function (col) {
    for (let i = 0; i < this.n; ++i) if (this.marked[i][col] == 1) return i;

    return -1;
  };
  /**
   * Find the first prime element in the specified row.
   *
   * @return {Number} The column index, or -1 if no prime element was found
   */

  Munkres.prototype.__find_prime_in_row = function (row) {
    for (let j = 0; j < this.n; ++j) if (this.marked[row][j] == 2) return j;

    return -1;
  };

  Munkres.prototype.__convert_path = function (path, count) {
    for (let i = 0; i <= count; ++i) this.marked[path[i][0]][path[i][1]] = this.marked[path[i][0]][path[i][1]] == 1 ? 0 : 1;
  };
  /** Clear all covered matrix cells */

  Munkres.prototype.__clear_covers = function () {
    for (let i = 0; i < this.n; ++i) {
      this.row_covered[i] = false;
      this.col_covered[i] = false;
    }
  };
  /** Erase all prime markings */

  Munkres.prototype.__erase_primes = function () {
    for (let i = 0; i < this.n; ++i) for (let j = 0; j < this.n; ++j) if (this.marked[i][j] == 2) this.marked[i][j] = 0;
  }; // ---------------------------------------------------------------------------
  // Functions
  // ---------------------------------------------------------------------------

  /**
   * Create a cost matrix from a profit matrix by calling
   * 'inversion_function' to invert each value. The inversion
   * function must take one numeric argument (of any type) and return
   * another numeric argument which is presumed to be the cost inverse
   * of the original profit.
   *
   * This is a static method. Call it like this:
   *
   *  cost_matrix = make_cost_matrix(matrix[, inversion_func]);
   *
   * For example:
   *
   *  cost_matrix = make_cost_matrix(matrix, function(x) { return MAXIMUM - x; });
   *
   * @param {Array} profit_matrix An array of arrays representing the matrix
   *                              to convert from a profit to a cost matrix
   * @param {Function} [inversion_function] The function to use to invert each
   *                                       entry in the profit matrix
   *
   * @return {Array} The converted matrix
   */

  function make_cost_matrix(profit_matrix, inversion_function) {
    let i; let
      j;

    if (!inversion_function) {
      let maximum = -1.0 / 0.0;

      for (i = 0; i < profit_matrix.length; ++i) for (j = 0; j < profit_matrix[i].length; ++j) if (profit_matrix[i][j] > maximum) maximum = profit_matrix[i][j];

      inversion_function = function (x) {
        return maximum - x;
      };
    }

    const cost_matrix = [];

    for (i = 0; i < profit_matrix.length; ++i) {
      const row = profit_matrix[i];
      cost_matrix[i] = [];

      for (j = 0; j < row.length; ++j) cost_matrix[i][j] = inversion_function(profit_matrix[i][j]);
    }

    return cost_matrix;
  }
  /**
   * Convenience function: Converts the contents of a matrix of integers
   * to a printable string.
   *
   * @param {Array} matrix The matrix to print
   *
   * @return {String} The formatted matrix
   */

  function format_matrix(matrix) {
    const columnWidths = [];
    let i; let
      j;

    for (i = 0; i < matrix.length; ++i) {
      for (j = 0; j < matrix[i].length; ++j) {
        const entryWidth = String(matrix[i][j]).length;
        if (!columnWidths[j] || entryWidth >= columnWidths[j]) columnWidths[j] = entryWidth;
      }
    }

    let formatted = '';

    for (i = 0; i < matrix.length; ++i) {
      for (j = 0; j < matrix[i].length; ++j) {
        let s = String(matrix[i][j]); // pad at front with spaces

        while (s.length < columnWidths[j]) s = ` ${s}`;

        formatted += s; // separate columns

        if (j != matrix[i].length - 1) formatted += ' ';
      }

      if (i != matrix[i].length - 1) formatted += '\n';
    }

    return formatted;
  } // ---------------------------------------------------------------------------
  // Exports
  // ---------------------------------------------------------------------------

  function computeMunkres(cost_matrix, options) {
    const m = new Munkres();
    return m.compute(cost_matrix, options);
  }

  computeMunkres.version = '1.2.2';
  computeMunkres.format_matrix = format_matrix;
  computeMunkres.make_cost_matrix = make_cost_matrix;
  computeMunkres.Munkres = Munkres; // backwards compatibility

  if (module.exports) {
    module.exports = computeMunkres;
  }
}(munkres$1));

const itemTrackedModule = ItemTracked$1;
const { ItemTracked } = itemTrackedModule;
const { kdTree } = kdTreeMin;
const munkres = munkres$1.exports;
const { iouAreas } = utils;

const iouDistance = function iouDistance(item1, item2) {
  // IOU distance, between 0 and 1
  // The smaller the less overlap
  const iou = iouAreas(item1, item2); // Invert this as the KDTREESEARCH is looking for the smaller value

  let distance = 1 - iou; // If the overlap is iou < 0.95, exclude value

  if (distance > 1 - params.iouLimit) {
    distance = params.distanceLimit + 1;
  }

  return distance;
};

var params = {
  // DEFAULT_UNMATCHEDFRAMES_TOLERANCE
  // This the number of frame we wait when an object isn't matched before considering it gone
  unMatchedFramesTolerance: 5,
  // DEFAULT_IOU_LIMIT, exclude things from beeing matched if their IOU is lower than this
  // 1 means total overlap whereas 0 means no overlap
  iouLimit: 0.05,
  // Remove new objects fast if they could not be matched in the next frames.
  // Setting this to false ensures the object will stick around at least
  // unMatchedFramesTolerance frames, even if they could neven be matched in
  // subsequent frames.
  fastDelete: true,
  // The function to use to determine the distance between to detected objects
  distanceFunc: iouDistance,
  // The distance limit for matching. If values need to be excluded from
  // matching set their distance to something greater than the distance limit
  distanceLimit: 10000,
  // The algorithm used to match tracks with new detections. Can be either
  // 'kdTree' or 'munkres'.
  matchingAlgorithm: 'munkres', // matchingAlgorithm: 'kdTree',

}; // A dictionary of itemTracked currently tracked
// key: uuid
// value: ItemTracked object

let mapOfItemsTracked = new Map(); // A dictionnary keeping memory of all tracked object (even after they disappear)
// Useful to ouput the file of all items tracked

let mapOfAllItemsTracked = new Map(); // By default, we do not keep all the history in memory

let keepAllHistoryInMemory = false;
const computeDistance = tracker.computeDistance = iouDistance;

const updateTrackedItemsWithNewFrame = tracker.updateTrackedItemsWithNewFrame = function (detectionsOfThisFrame, frameNb) {
  // A kd-tree containing all the itemtracked
  // Need to rebuild on each frame, because itemTracked positions have changed
  let treeItemsTracked = new kdTree(Array.from(mapOfItemsTracked.values()), params.distanceFunc, ['x', 'y', 'w', 'h']); // Contruct a kd tree for the detections of this frame

  const treeDetectionsOfThisFrame = new kdTree(detectionsOfThisFrame, params.distanceFunc, ['x', 'y', 'w', 'h']); // SCENARIO 1: itemsTracked map is empty

  if (mapOfItemsTracked.size === 0) {
    // Just add every detected item as item Tracked
    detectionsOfThisFrame.forEach((itemDetected) => {
      const newItemTracked = new ItemTracked(itemDetected, frameNb, params.unMatchedFramesTolerance, params.fastDelete); // Add it to the map

      mapOfItemsTracked.set(newItemTracked.id, newItemTracked); // Add it to the kd tree

      treeItemsTracked.insert(newItemTracked);
    });
  } // SCENARIO 2: We already have itemsTracked in the map
  else {
    const matchedList = new Array(detectionsOfThisFrame.length);
    matchedList.fill(false); // Match existing Tracked items with the items detected in the new frame
    // For each look in the new detection to find the closest match

    if (detectionsOfThisFrame.length > 0) {
      if (params.matchingAlgorithm === 'munkres') {
        const trackedItemIds = Array.from(mapOfItemsTracked.keys());
        const costMatrix = Array.from(mapOfItemsTracked.values()).map((itemTracked) => {
          const predictedPosition = itemTracked.predictNextPosition();
          return detectionsOfThisFrame.map((detection) => params.distanceFunc(predictedPosition, detection));
        });
        mapOfItemsTracked.forEach((itemTracked) => {
          itemTracked.makeAvailable();
        });
        munkres(costMatrix).filter((m) => costMatrix[m[0]][m[1]] <= params.distanceLimit).forEach((m) => {
          const itemTracked = mapOfItemsTracked.get(trackedItemIds[m[0]]);
          const updatedTrackedItemProperties = detectionsOfThisFrame[m[1]];
          matchedList[m[1]] = {
            idDisplay: itemTracked.idDisplay,
          };
          itemTracked.makeUnavailable().update(updatedTrackedItemProperties, frameNb);
        });
        matchedList.forEach((matched, index) => {
          if (!matched) {
            if (Math.min.apply(Math, _toConsumableArray(costMatrix.map((m) => m[index]))) > params.distanceLimit) {
              const newItemTracked = ItemTracked(detectionsOfThisFrame[index], frameNb, params.unMatchedFramesTolerance, params.fastDelete);
              mapOfItemsTracked.set(newItemTracked.id, newItemTracked);
              newItemTracked.makeUnavailable();
              costMatrix.push(detectionsOfThisFrame.map((detection) => params.distanceFunc(newItemTracked, detection)));
            }
          }
        });
      } else if (params.matchingAlgorithm === 'kdTree') {
        mapOfItemsTracked.forEach((itemTracked) => {
          // First predict the new position of the itemTracked
          const predictedPosition = itemTracked.predictNextPosition(); // Make available for matching

          itemTracked.makeAvailable(); // Search for a detection that matches

          const treeSearchResult = treeDetectionsOfThisFrame.nearest(predictedPosition, 1, params.distanceLimit)[0]; // Only for debug assessments of predictions

          treeDetectionsOfThisFrame.nearest(itemTracked, 1, params.distanceLimit)[0]; // Only if we enable the extra refinement

          treeDetectionsOfThisFrame.nearest(predictedPosition, 2, params.distanceLimit); // If we have found something

          if (treeSearchResult) {
            const indexClosestNewDetectedItem = detectionsOfThisFrame.indexOf(treeSearchResult[0]); // If this detections was not already matched to a tracked item
            // (otherwise it would be matched to two tracked items...)

            if (!matchedList[indexClosestNewDetectedItem]) {
              matchedList[indexClosestNewDetectedItem] = {
                idDisplay: itemTracked.idDisplay,
              }; // Update properties of tracked object

              const updatedTrackedItemProperties = detectionsOfThisFrame[indexClosestNewDetectedItem];
              mapOfItemsTracked.get(itemTracked.id).makeUnavailable().update(updatedTrackedItemProperties, frameNb);
            }
          }
        });
      } else {
        throw 'Unknown matching algorithm "'.concat(params.matchingAlgorithm, '"');
      }
    } else {
      mapOfItemsTracked.forEach((itemTracked) => {
        itemTracked.makeAvailable();
      });
    }

    if (params.matchingAlgorithm === 'kdTree') {
      // Add any unmatched items as new trackedItem only if those new items are not too similar
      // to existing trackedItems this avoids adding some double match of YOLO and bring down drasticly reassignments
      if (mapOfItemsTracked.size > 0) {
        // Safety check to see if we still have object tracked (could have been deleted previously)
        // Rebuild tracked item tree to take in account the new positions
        treeItemsTracked = new kdTree(Array.from(mapOfItemsTracked.values()), params.distanceFunc, ['x', 'y', 'w', 'h']); // console.log(`Nb new items Unmatched : ${matchedList.filter((isMatched) => isMatched === false).length}`)

        matchedList.forEach((matched, index) => {
          // Iterate through unmatched new detections
          if (!matched) {
            // Do not add as new tracked item if it is to similar to an existing one
            const treeSearchResult = treeItemsTracked.nearest(detectionsOfThisFrame[index], 1, params.distanceLimit)[0];

            if (!treeSearchResult) {
              const newItemTracked = ItemTracked(detectionsOfThisFrame[index], frameNb, params.unMatchedFramesTolerance, params.fastDelete); // Add it to the map

              mapOfItemsTracked.set(newItemTracked.id, newItemTracked); // Add it to the kd tree

              treeItemsTracked.insert(newItemTracked); // Make unvailable

              newItemTracked.makeUnavailable();
            }
          }
        });
      }
    } // Start killing the itemTracked (and predicting next position)
    // that are tracked but haven't been matched this frame

    mapOfItemsTracked.forEach((itemTracked) => {
      if (itemTracked.available) {
        itemTracked.countDown(frameNb);
        itemTracked.updateTheoricalPositionAndSize();

        if (itemTracked.isDead()) {
          mapOfItemsTracked.delete(itemTracked.id);
          treeItemsTracked.remove(itemTracked);

          if (keepAllHistoryInMemory) {
            mapOfAllItemsTracked.set(itemTracked.id, itemTracked);
          }
        }
      }
    });
  }
};

const reset = tracker.reset = function () {
  mapOfItemsTracked = new Map();
  mapOfAllItemsTracked = new Map();
  itemTrackedModule.reset();
};

const setParams = tracker.setParams = function (newParams) {
  Object.keys(newParams).forEach((key) => {
    params[key] = newParams[key];
  });
};

const enableKeepInMemory = tracker.enableKeepInMemory = function () {
  keepAllHistoryInMemory = true;
};

const disableKeepInMemory = tracker.disableKeepInMemory = function () {
  keepAllHistoryInMemory = false;
};

const getJSONOfTrackedItems = tracker.getJSONOfTrackedItems = function () {
  const roundInt = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toJSON(roundInt));
};

const getJSONDebugOfTrackedItems = tracker.getJSONDebugOfTrackedItems = function () {
  const roundInt = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toJSONDebug(roundInt));
};

const getTrackedItemsInMOTFormat = tracker.getTrackedItemsInMOTFormat = function (frameNb) {
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toMOT(frameNb));
}; // Work only if keepInMemory is enabled

const getAllTrackedItems = tracker.getAllTrackedItems = function () {
  return mapOfAllItemsTracked;
}; // Work only if keepInMemory is enabled

const getJSONOfAllTrackedItems = tracker.getJSONOfAllTrackedItems = function () {
  return Array.from(mapOfAllItemsTracked.values()).map((itemTracked) => itemTracked.toJSONGenericInfo());
};

export {
  computeDistance, tracker as default, disableKeepInMemory, enableKeepInMemory, getAllTrackedItems, getJSONDebugOfTrackedItems, getJSONOfAllTrackedItems, getJSONOfTrackedItems, getTrackedItemsInMOTFormat, reset, setParams, updateTrackedItemsWithNewFrame,
};
