const ALGORITHMS = {
    "rc4-40": { version: 1, revision: 2, keyLengthBits: 40, method: "rc4" },
    "rc4-128": { version: 2, revision: 3, keyLengthBits: 128, method: "rc4" },
    "aes-128": { version: 4, revision: 4, keyLengthBits: 128, method: "aesv2" },
    "aes-256": { version: 5, revision: 6, keyLengthBits: 256, method: "aesv3" },
  };

  const PERMISSIONS = {
    PRINT: 1 << 2,
    MODIFY: 1 << 3,
    COPY: 1 << 4,
    ANNOTATE: 1 << 5,
    FORM: 1 << 8,
    ACCESSIBILITY: 1 << 9,
    ASSEMBLE: 1 << 10,
    PRINT_HQ: 1 << 11,
  };

  const PDF_DOC_ENCODING = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x02d8, 0x02c7, 0x02c6, 0x02d9, 0x02dd, 0x02db, 0x02da, 0x02dc,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x0000,
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044,
    0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c, 0x201d, 0x2018,
    0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x0141, 0x0152, 0x0160,
    0x0178, 0x017d, 0x0131, 0x0142, 0x0153, 0x0161, 0x017e, 0x0000,
    0x20ac, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x0000, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,
  ];

  const PASSWORD_PADDING = new Uint8Array([
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
    0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
    0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
  ]);

  const MD5_SHIFT = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  const MD5_INDEX = new Uint8Array(64);
  const MD5_K = new Uint32Array(64);
  const textEncoder = new TextEncoder();
  const unicodeToPdfDoc = new Map();

  for (let i = 0; i < 64; i += 1) {
    if (i < 16) {
      MD5_INDEX[i] = i;
    } else if (i < 32) {
      MD5_INDEX[i] = (5 * i + 1) % 16;
    } else if (i < 48) {
      MD5_INDEX[i] = (3 * i + 5) % 16;
    } else {
      MD5_INDEX[i] = (7 * i) % 16;
    }

    MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }

  for (let i = 0; i < PDF_DOC_ENCODING.length; i += 1) {
    const codePoint = PDF_DOC_ENCODING[i];

    if (!unicodeToPdfDoc.has(codePoint)) {
      unicodeToPdfDoc.set(codePoint, i);
    }
  }

  const subtleCrypto = globalThis.crypto && globalThis.crypto.subtle ? globalThis.crypto.subtle : null;

  // Generic byte and hashing helpers.
  function assert(condition, message) {
    if (!condition) {
      throw new Error(message);
    }
  }

  function normalizeBytes(value, label) {
    if (value instanceof Uint8Array) {
      return value;
    }

    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }

    if (Array.isArray(value)) {
      return Uint8Array.from(value);
    }

    if (typeof value === "string") {
      return textEncoder.encode(value);
    }

    throw new TypeError(`Expected ${label} to be bytes, an array, or a string.`);
  }

  function concatBytes() {
    let length = 0;

    for (const value of arguments) {
      length += value.length;
    }

    const output = new Uint8Array(length);
    let offset = 0;

    for (const value of arguments) {
      output.set(value, offset);
      offset += value.length;
    }

    return output;
  }

  function leftRotate32(value, shift) {
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
  }

  function md5Bytes(input) {
    const bytes = normalizeBytes(input, "input");
    const bitLength = BigInt(bytes.length) * 8n;
    const paddingLength = ((56 - ((bytes.length + 1) % 64)) + 64) % 64;
    const padded = new Uint8Array(bytes.length + 1 + paddingLength + 8);
    const words = new Uint32Array(16);
    let a0 = 0x67452301;
    let b0 = 0xefcdab89;
    let c0 = 0x98badcfe;
    let d0 = 0x10325476;

    padded.set(bytes);
    padded[bytes.length] = 0x80;

    for (let i = 0; i < 8; i += 1) {
      padded[padded.length - 8 + i] = Number((bitLength >> BigInt(i * 8)) & 0xffn);
    }

    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i += 1) {
        const index = offset + i * 4;
        words[i] =
          (padded[index]) |
          (padded[index + 1] << 8) |
          (padded[index + 2] << 16) |
          (padded[index + 3] << 24);
      }

      let a = a0;
      let b = b0;
      let c = c0;
      let d = d0;

      for (let i = 0; i < 64; i += 1) {
        let f;

        if (i < 16) {
          f = (b & c) | (~b & d);
        } else if (i < 32) {
          f = (d & b) | (~d & c);
        } else if (i < 48) {
          f = b ^ c ^ d;
        } else {
          f = c ^ (b | ~d);
        }

        const temp = d;
        const sum = (a + f + MD5_K[i] + words[MD5_INDEX[i]]) >>> 0;

        d = c;
        c = b;
        b = (b + leftRotate32(sum, MD5_SHIFT[i])) >>> 0;
        a = temp;
      }

      a0 = (a0 + a) >>> 0;
      b0 = (b0 + b) >>> 0;
      c0 = (c0 + c) >>> 0;
      d0 = (d0 + d) >>> 0;
    }

    const output = new Uint8Array(16);
    const values = [a0, b0, c0, d0];

    for (let i = 0; i < values.length; i += 1) {
      const value = values[i];
      const offset = i * 4;

      output[offset] = value & 0xff;
      output[offset + 1] = (value >>> 8) & 0xff;
      output[offset + 2] = (value >>> 16) & 0xff;
      output[offset + 3] = (value >>> 24) & 0xff;
    }

    return output;
  }

  async function hashBytes(algorithm, bytes) {
    if (algorithm === "MD5") {
      return md5Bytes(bytes);
    }

    if (subtleCrypto) {
      const result = await subtleCrypto.digest(algorithm, normalizeBytes(bytes, "hash input"));
      return new Uint8Array(result);
    }

    throw new Error(`No implementation available for ${algorithm}.`);
  }

  function rc4Encrypt(keyBytes, dataBytes) {
    const key = normalizeBytes(keyBytes, "RC4 key");
    const data = normalizeBytes(dataBytes, "RC4 data");
    const state = new Uint8Array(256);
    const output = new Uint8Array(data.length);
    let j = 0;
    let i = 0;

    for (let index = 0; index < 256; index += 1) {
      state[index] = index;
    }

    for (let index = 0; index < 256; index += 1) {
      j = (j + state[index] + key[index % key.length]) & 0xff;
      const swap = state[index];
      state[index] = state[j];
      state[j] = swap;
    }

    j = 0;

    for (let index = 0; index < data.length; index += 1) {
      i = (i + 1) & 0xff;
      j = (j + state[i]) & 0xff;

      const swap = state[i];
      state[i] = state[j];
      state[j] = swap;

      const keyByte = state[(state[i] + state[j]) & 0xff];
      output[index] = data[index] ^ keyByte;
    }

    return output;
  }

  // AES helpers used for object encryption and revision 5/6 key wrapping.
  const AES_SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ]);

  const AES_INV_SBOX = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
  ]);

  const AES_RCON = new Uint8Array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  ]);

  function aesXtime(value) {
    return ((value << 1) ^ (value & 0x80 ? 0x11b : 0)) & 0xff;
  }

  function aesMul(left, right) {
    let a = left & 0xff;
    let b = right & 0xff;
    let result = 0;

    while (b > 0) {
      if (b & 1) {
        result ^= a;
      }

      a = aesXtime(a);
      b >>>= 1;
    }

    return result & 0xff;
  }

  class AesBlockCipher {
    constructor(keyBytes) {
      const key = normalizeBytes(keyBytes, "AES key");

      if (key.length !== 16 && key.length !== 32) {
        throw new Error("AES block cipher requires a 16-byte or 32-byte key.");
      }

      this.roundCount = key.length === 16 ? 10 : 14;
      this.roundKeys = this.expandKey(key);
    }

    expandKey(keyBytes) {
      const keyLength = keyBytes.length;
      const expanded = new Uint8Array((this.roundCount + 1) * 16);
      const temp = new Uint8Array(4);
      let expandedLength = 0;
      let rconIndex = 1;

      expanded.set(keyBytes);
      expandedLength = keyLength;

      while (expandedLength < expanded.length) {
        temp.set(expanded.subarray(expandedLength - 4, expandedLength));

        if (expandedLength % keyLength === 0) {
          const rotated = temp[0];
          temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIndex];
          temp[1] = AES_SBOX[temp[2]];
          temp[2] = AES_SBOX[temp[3]];
          temp[3] = AES_SBOX[rotated];
          rconIndex += 1;
        } else if (keyLength === 32 && expandedLength % keyLength === 16) {
          temp[0] = AES_SBOX[temp[0]];
          temp[1] = AES_SBOX[temp[1]];
          temp[2] = AES_SBOX[temp[2]];
          temp[3] = AES_SBOX[temp[3]];
        }

        for (let index = 0; index < 4 && expandedLength < expanded.length; index += 1) {
          expanded[expandedLength] = expanded[expandedLength - keyLength] ^ temp[index];
          expandedLength += 1;
        }
      }

      return expanded;
    }

    addRoundKey(state, round) {
      const offset = round * 16;

      for (let index = 0; index < 16; index += 1) {
        state[index] ^= this.roundKeys[offset + index];
      }
    }

    subBytes(state) {
      for (let index = 0; index < 16; index += 1) {
        state[index] = AES_SBOX[state[index]];
      }
    }

    inverseSubBytes(state) {
      for (let index = 0; index < 16; index += 1) {
        state[index] = AES_INV_SBOX[state[index]];
      }
    }

    shiftRows(state) {
      let temp = state[1];
      state[1] = state[5];
      state[5] = state[9];
      state[9] = state[13];
      state[13] = temp;

      temp = state[2];
      let temp2 = state[6];
      state[2] = state[10];
      state[6] = state[14];
      state[10] = temp;
      state[14] = temp2;

      temp = state[3];
      temp2 = state[7];
      const temp3 = state[11];
      state[3] = state[15];
      state[7] = temp;
      state[11] = temp2;
      state[15] = temp3;
    }

    inverseShiftRows(state) {
      let temp = state[13];
      state[13] = state[9];
      state[9] = state[5];
      state[5] = state[1];
      state[1] = temp;

      temp = state[14];
      let temp2 = state[10];
      state[14] = state[6];
      state[10] = state[2];
      state[6] = temp;
      state[2] = temp2;

      temp = state[15];
      temp2 = state[11];
      const temp3 = state[7];
      state[15] = state[3];
      state[11] = temp;
      state[7] = temp2;
      state[3] = temp3;
    }

    mixColumns(state) {
      for (let column = 0; column < 16; column += 4) {
        const s0 = state[column];
        const s1 = state[column + 1];
        const s2 = state[column + 2];
        const s3 = state[column + 3];
        const mix = s0 ^ s1 ^ s2 ^ s3;

        state[column] ^= mix ^ aesXtime(s0 ^ s1);
        state[column + 1] ^= mix ^ aesXtime(s1 ^ s2);
        state[column + 2] ^= mix ^ aesXtime(s2 ^ s3);
        state[column + 3] ^= mix ^ aesXtime(s3 ^ s0);
      }
    }

    inverseMixColumns(state) {
      for (let column = 0; column < 16; column += 4) {
        const s0 = state[column];
        const s1 = state[column + 1];
        const s2 = state[column + 2];
        const s3 = state[column + 3];

        state[column] = aesMul(s0, 14) ^ aesMul(s1, 11) ^ aesMul(s2, 13) ^ aesMul(s3, 9);
        state[column + 1] = aesMul(s0, 9) ^ aesMul(s1, 14) ^ aesMul(s2, 11) ^ aesMul(s3, 13);
        state[column + 2] = aesMul(s0, 13) ^ aesMul(s1, 9) ^ aesMul(s2, 14) ^ aesMul(s3, 11);
        state[column + 3] = aesMul(s0, 11) ^ aesMul(s1, 13) ^ aesMul(s2, 9) ^ aesMul(s3, 14);
      }
    }

    encryptBlock(blockBytes) {
      const state = new Uint8Array(blockBytes);

      this.addRoundKey(state, 0);

      for (let round = 1; round < this.roundCount; round += 1) {
        this.subBytes(state);
        this.shiftRows(state);
        this.mixColumns(state);
        this.addRoundKey(state, round);
      }

      this.subBytes(state);
      this.shiftRows(state);
      this.addRoundKey(state, this.roundCount);

      return state;
    }

    decryptBlock(blockBytes) {
      const state = new Uint8Array(blockBytes);

      this.addRoundKey(state, this.roundCount);

      for (let round = this.roundCount - 1; round >= 1; round -= 1) {
        this.inverseShiftRows(state);
        this.inverseSubBytes(state);
        this.addRoundKey(state, round);
        this.inverseMixColumns(state);
      }

      this.inverseShiftRows(state);
      this.inverseSubBytes(state);
      this.addRoundKey(state, 0);

      return state;
    }
  }

  function aesCbcTransformNoPadding(keyBytes, ivBytes, dataBytes, decrypt) {
    const key = normalizeBytes(keyBytes, "AES key");
    const iv = normalizeBytes(ivBytes, "AES IV");
    const data = normalizeBytes(dataBytes, "AES data");
    const cipher = new AesBlockCipher(key);
    const output = new Uint8Array(data.length);
    let previous = new Uint8Array(iv);

    assert(data.length % 16 === 0, "AES-CBC without padding requires whole blocks.");

    for (let offset = 0; offset < data.length; offset += 16) {
      const block = data.subarray(offset, offset + 16);

      if (decrypt) {
        const plainBlock = cipher.decryptBlock(block);

        for (let index = 0; index < 16; index += 1) {
          output[offset + index] = plainBlock[index] ^ previous[index];
        }

        previous = new Uint8Array(block);
      } else {
        const workBlock = new Uint8Array(16);

        for (let index = 0; index < 16; index += 1) {
          workBlock[index] = block[index] ^ previous[index];
        }

        const encryptedBlock = cipher.encryptBlock(workBlock);
        output.set(encryptedBlock, offset);
        previous = encryptedBlock;
      }
    }

    return output;
  }

  async function aesCbcEncrypt(keyBytes, ivBytes, dataBytes, noPadding) {
    const key = normalizeBytes(keyBytes, "AES key");
    const iv = normalizeBytes(ivBytes, "AES IV");
    const data = normalizeBytes(dataBytes, "AES data");

    assert(iv.length === 16, "AES-CBC requires a 16-byte IV.");

    if (noPadding) {
      return aesCbcTransformNoPadding(key, iv, data, false);
    }

    if (subtleCrypto) {
      const cryptoKey = await subtleCrypto.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
      const encrypted = new Uint8Array(await subtleCrypto.encrypt({ name: "AES-CBC", iv }, cryptoKey, data));

      return noPadding ? encrypted.subarray(0, data.length) : encrypted;
    }

    throw new Error("AES-CBC encryption requires Web Crypto.");
  }

  async function aesCbcDecrypt(keyBytes, ivBytes, dataBytes, noPadding) {
    const key = normalizeBytes(keyBytes, "AES key");
    const iv = normalizeBytes(ivBytes, "AES IV");
    const data = normalizeBytes(dataBytes, "AES data");

    assert(iv.length === 16, "AES-CBC requires a 16-byte IV.");
    assert(data.length % 16 === 0, "AES-CBC ciphertext must be a multiple of 16 bytes.");

    if (noPadding) {
      return aesCbcTransformNoPadding(key, iv, data, true);
    }

    if (subtleCrypto) {
      const cryptoKey = await subtleCrypto.importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"]);
      const decrypted = await subtleCrypto.decrypt({ name: "AES-CBC", iv }, cryptoKey, data);
      return new Uint8Array(decrypted);
    }

    throw new Error("AES-CBC decryption requires Web Crypto.");
  }

  function littleEndian32(value) {
    const output = new Uint8Array(4);

    output[0] = value & 0xff;
    output[1] = (value >>> 8) & 0xff;
    output[2] = (value >>> 16) & 0xff;
    output[3] = (value >>> 24) & 0xff;

    return output;
  }

  function littleEndian24(value) {
    return new Uint8Array([
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
    ]);
  }

  function littleEndian16(value) {
    return new Uint8Array([
      value & 0xff,
      (value >>> 8) & 0xff,
    ]);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  function equalBytes(leftBytes, rightBytes, length) {
    const left = normalizeBytes(leftBytes, "left bytes");
    const right = normalizeBytes(rightBytes, "right bytes");
    const compareLength = typeof length === "number" ? length : Math.max(left.length, right.length);

    if (left.length < compareLength || right.length < compareLength) {
      return false;
    }

    for (let index = 0; index < compareLength; index += 1) {
      if (left[index] !== right[index]) {
        return false;
      }
    }

    return true;
  }

  function encodePdfDocPassword(password) {
    const output = [];

    for (const character of password) {
      const codePoint = character.codePointAt(0);
      const byte = unicodeToPdfDoc.get(codePoint);

      if (byte !== undefined) {
        output.push(byte);
      }
    }

    return Uint8Array.from(output);
  }

  function encodePassword(password, revision) {
    const normalized = typeof password === "string" ? password : String(password || "");

    if (revision <= 4) {
      return encodePdfDocPassword(normalized);
    }

    return textEncoder.encode(normalized);
  }

  function padPassword(passwordBytes) {
    const output = new Uint8Array(32);
    const bytes = normalizeBytes(passwordBytes, "password");
    const copyLength = Math.min(bytes.length, 32);

    output.set(bytes.subarray(0, copyLength));

    if (copyLength < 32) {
      output.set(PASSWORD_PADDING.subarray(0, 32 - copyLength), copyLength);
    }

    return output;
  }

  function defaultRandomBytes(length) {
    const output = new Uint8Array(length);

    if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
      globalThis.crypto.getRandomValues(output);
      return output;
    }

    throw new Error("No secure random byte source is available.");
  }

  function getRandomBytes(randomBytes, length) {
    const output = normalizeBytes(randomBytes(length), "random bytes");
    assert(output.length === length, `Expected ${length} random bytes, received ${output.length}.`);
    return output;
  }

  function toSignedInt32(value) {
    return value >> 0;
  }

  function normalizeOptions(options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("createEncryptionContext expects an options object.");
    }

    const algorithmName = options.encrypt || options.algorithm || "aes-256";
    const algorithm = ALGORITHMS[algorithmName];
    const requestedPermissions =
      typeof options.permissions === "number"
        ? options.permissions
        : (
          PERMISSIONS.PRINT |
          PERMISSIONS.MODIFY |
          PERMISSIONS.COPY |
          PERMISSIONS.ANNOTATE |
          PERMISSIONS.FORM |
          PERMISSIONS.ACCESSIBILITY |
          PERMISSIONS.ASSEMBLE |
          PERMISSIONS.PRINT_HQ
        );
    const permissions = toSignedInt32((requestedPermissions & 0x0f3c) | 0xfffff0c0);

    assert(algorithm, `Unsupported encryption algorithm "${algorithmName}".`);

    return {
      algorithmName,
      algorithm,
      userPassword: options["user-password"] ?? options.userPassword ?? "",
      ownerPassword: options["owner-password"] ?? options.ownerPassword ?? options["user-password"] ?? options.userPassword ?? "",
      permissions,
      requestedPermissions,
      encryptMetadata: options.encryptMetadata !== false && options["encrypt-metadata"] !== false,
      fileId: options.fileId ? normalizeBytes(options.fileId, "fileId") : null,
      randomBytes: typeof options.randomBytes === "function" ? options.randomBytes : defaultRandomBytes,
    };
  }

  async function computeEncryptionKey(crypt, passwordBytes) {
    const keyLength = Math.max(0, Math.min(16, crypt.keyLengthBits / 8));
    let digest = await hashBytes(
      "MD5",
      concatBytes(
        padPassword(passwordBytes),
        crypt.O,
        littleEndian32(crypt.permissions >>> 0),
        crypt.fileId
      )
    );

    if (crypt.revision >= 4 && !crypt.encryptMetadata) {
      digest = await hashBytes("MD5", concatBytes(digest, new Uint8Array([0xff, 0xff, 0xff, 0xff])));
    }

    if (crypt.revision >= 3) {
      for (let i = 0; i < 50; i += 1) {
        digest = await hashBytes("MD5", digest.subarray(0, keyLength));
      }
    }

    return digest.subarray(0, keyLength);
  }

  async function computeOwnerPassword(crypt, ownerPasswordBytes, userPasswordBytes) {
    const keyLength = Math.max(0, Math.min(16, crypt.keyLengthBits / 8));
    let digest = await hashBytes("MD5", padPassword(ownerPasswordBytes));

    if (crypt.revision >= 3) {
      for (let i = 0; i < 50; i += 1) {
        digest = await hashBytes("MD5", digest.subarray(0, keyLength));
      }
    }

    const key = digest.subarray(0, keyLength);
    let output = rc4Encrypt(key, padPassword(userPasswordBytes));

    if (crypt.revision >= 3) {
      for (let x = 1; x <= 19; x += 1) {
        const xorKey = new Uint8Array(keyLength);

        for (let i = 0; i < keyLength; i += 1) {
          xorKey[i] = key[i] ^ x;
        }

        output = rc4Encrypt(xorKey, output);
      }
    }

    return output;
  }

  async function computeUserPassword(crypt, userPasswordBytes) {
    if (crypt.revision === 2) {
      const fileKey = await computeEncryptionKey(crypt, userPasswordBytes);
      return {
        fileKey,
        entry: rc4Encrypt(fileKey, PASSWORD_PADDING),
      };
    }

    const fileKey = await computeEncryptionKey(crypt, userPasswordBytes);
    let digest = await hashBytes("MD5", concatBytes(PASSWORD_PADDING, crypt.fileId));
    let output = rc4Encrypt(fileKey, digest.subarray(0, 16));

    for (let x = 1; x <= 19; x += 1) {
      const xorKey = new Uint8Array(fileKey.length);

      for (let i = 0; i < fileKey.length; i += 1) {
        xorKey[i] = fileKey[i] ^ x;
      }

      output = rc4Encrypt(xorKey, output);
    }

    const entry = new Uint8Array(32);
    entry.set(output.subarray(0, 16), 0);
    entry.set(PASSWORD_PADDING.subarray(0, 16), 16);

    return {
      fileKey,
      entry,
    };
  }

  async function computeEncryptionKeyR5(crypt, passwordBytes, ownerKey) {
    const password = normalizeBytes(passwordBytes, "password").subarray(0, Math.min(passwordBytes.length, 127));
    const validationSeed = ownerKey
      ? concatBytes(password, crypt.O.subarray(32, 40), crypt.U)
      : concatBytes(password, crypt.U.subarray(32, 40));
    const fileKeySeed = ownerKey
      ? concatBytes(password, crypt.O.subarray(40, 48), crypt.U)
      : concatBytes(password, crypt.U.subarray(40, 48));
    const validationKey = await hashBytes("SHA-256", validationSeed);
    const fileKeyHash = await hashBytes("SHA-256", fileKeySeed);
    const fileKey = await aesCbcDecrypt(
      fileKeyHash,
      new Uint8Array(16),
      ownerKey ? crypt.OE : crypt.UE,
      true
    );

    return {
      validationKey,
      fileKey,
    };
  }

  async function computeEncryptionKeyR6(crypt, passwordBytes, ownerKey) {
    const password = normalizeBytes(passwordBytes, "password").subarray(0, Math.min(passwordBytes.length, 127));
    const validationSalt = ownerKey ? crypt.O.subarray(32, 40) : crypt.U.subarray(32, 40);
    const keySalt = ownerKey ? crypt.O.subarray(40, 48) : crypt.U.subarray(40, 48);
    const validationKey = await computeHardenedHashR6(password, validationSalt, ownerKey ? crypt.U : null);
    const keyHash = await computeHardenedHashR6(password, keySalt, ownerKey ? crypt.U : null);
    const fileKey = await aesCbcDecrypt(
      keyHash,
      new Uint8Array(16),
      ownerKey ? crypt.OE : crypt.UE,
      true
    );

    return {
      validationKey,
      fileKey,
    };
  }

  async function computeHardenedHashR6(passwordBytes, salt, ownerBytes) {
    const password = normalizeBytes(passwordBytes, "password").subarray(0, Math.min(passwordBytes.length, 127));
    const owner = ownerBytes ? normalizeBytes(ownerBytes, "owner bytes") : null;
    let block = await hashBytes("SHA-256", concatBytes(password, salt, owner || new Uint8Array(0)));
    let blockSize = 32;
    let encryptedLastByte = 0;

    for (let round = 0; round < 64 || round < encryptedLastByte + 32; round += 1) {
      const dataSeed = concatBytes(password, block.subarray(0, blockSize), owner || new Uint8Array(0));
      const expanded = new Uint8Array(dataSeed.length * 64);

      for (let i = 0; i < 64; i += 1) {
        expanded.set(dataSeed, i * dataSeed.length);
      }

      const encrypted = await aesCbcEncrypt(block.subarray(0, 16), block.subarray(16, 32), expanded, true);
      encryptedLastByte = encrypted[encrypted.length - 1];
      let sum = 0;

      for (let i = 0; i < 16; i += 1) {
        sum += encrypted[i];
      }

      blockSize = 32 + (sum % 3) * 16;

      if (blockSize === 32) {
        block = await hashBytes("SHA-256", encrypted);
      } else if (blockSize === 48) {
        block = await hashBytes("SHA-384", encrypted);
      } else {
        block = await hashBytes("SHA-512", encrypted);
      }
    }

    return block.subarray(0, 32);
  }

  async function computeUserPasswordR6(crypt, passwordBytes, randomBytes) {
    const validationsalt = getRandomBytes(randomBytes, 8);
    const keysalt = getRandomBytes(randomBytes, 8);
    const validationHash = await computeHardenedHashR6(passwordBytes, validationsalt, null);
    const keyHash = await computeHardenedHashR6(passwordBytes, keysalt, null);
    const iv = new Uint8Array(16);

    return {
      U: concatBytes(validationHash, validationsalt, keysalt),
      UE: await aesCbcEncrypt(keyHash, iv, crypt.fileKey, true),
    };
  }

  async function computeOwnerPasswordR6(crypt, passwordBytes, randomBytes) {
    const validationsalt = getRandomBytes(randomBytes, 8);
    const keysalt = getRandomBytes(randomBytes, 8);
    const validationHash = await computeHardenedHashR6(passwordBytes, validationsalt, crypt.U);
    const keyHash = await computeHardenedHashR6(passwordBytes, keysalt, crypt.U);
    const iv = new Uint8Array(16);

    return {
      O: concatBytes(validationHash, validationsalt, keysalt),
      OE: await aesCbcEncrypt(keyHash, iv, crypt.fileKey, true),
    };
  }

  async function computePermissionsR6(crypt, randomBytes) {
    const buffer = new Uint8Array(16);
    const iv = new Uint8Array(16);

    buffer.set(littleEndian32(crypt.permissions >>> 0), 0);
    buffer.set([0xff, 0xff, 0xff, 0xff], 4);
    buffer[8] = crypt.encryptMetadata ? 0x54 : 0x46;
    buffer[9] = 0x61;
    buffer[10] = 0x64;
    buffer[11] = 0x62;
    buffer.set(getRandomBytes(randomBytes, 4), 12);

    return aesCbcEncrypt(crypt.fileKey, iv, buffer, true);
  }

  function computeObjectKey(crypt, objectNumber, generationNumber) {
    const fileKey = crypt.fileKey;
    const keyLength = Math.min(fileKey.length, 32);

    if (crypt.method === "aesv3") {
      return fileKey.subarray(0, keyLength);
    }

    const seed = concatBytes(
      fileKey.subarray(0, keyLength),
      littleEndian24(objectNumber),
      littleEndian16(generationNumber),
      crypt.method === "aesv2" ? textEncoder.encode("sAlT") : new Uint8Array(0)
    );
    const digest = md5Bytes(seed);

    return digest.subarray(0, Math.min(keyLength + 5, 16));
  }

  async function encryptObjectBytes(crypt, objectNumber, generationNumber, bytes, randomBytes) {
    const payload = normalizeBytes(bytes, "object bytes");
    const key = computeObjectKey(crypt, objectNumber, generationNumber);

    if (crypt.method === "rc4") {
      return rc4Encrypt(key, payload);
    }

    if (payload.length === 0) {
      return new Uint8Array(0);
    }

    const iv = getRandomBytes(randomBytes || crypt.randomBytes, 16);
    const encrypted = await aesCbcEncrypt(key, iv, payload, false);

    return concatBytes(iv, encrypted);
  }

  async function decryptObjectBytes(crypt, objectNumber, generationNumber, bytes) {
    const payload = normalizeBytes(bytes, "object bytes");
    const key = computeObjectKey(crypt, objectNumber, generationNumber);

    if (crypt.method === "rc4") {
      return rc4Encrypt(key, payload);
    }

    if (payload.length === 0) {
      return new Uint8Array(0);
    }

    assert(payload.length >= 32, "AES-encrypted PDF objects must include an IV and at least one data block.");

    const iv = payload.subarray(0, 16);
    const encrypted = payload.subarray(16);

    return aesCbcDecrypt(key, iv, encrypted);
  }

  function createEncryptionDictionary(crypt) {
    const dictionary = {
      Filter: "Standard",
      R: crypt.revision,
      V: crypt.version,
      Length: crypt.keyLengthBits,
      P: crypt.permissions,
      EncryptMetadata: crypt.encryptMetadata,
      O: crypt.O,
      U: crypt.U,
    };

    if (crypt.revision === 4) {
      dictionary.StmF = "StdCF";
      dictionary.StrF = "StdCF";
      dictionary.CF = {
        StdCF: {
          AuthEvent: "DocOpen",
          CFM: "AESV2",
          Length: 16,
        },
      };
    }

    if (crypt.revision === 6) {
      dictionary.StmF = "StdCF";
      dictionary.StrF = "StdCF";
      dictionary.CF = {
        StdCF: {
          AuthEvent: "DocOpen",
          CFM: "AESV3",
          Length: 32,
        },
      };
      dictionary.OE = crypt.OE;
      dictionary.UE = crypt.UE;
      dictionary.Perms = crypt.Perms;
    }

    return dictionary;
  }

  function serializeEncryptionDictionary(crypt) {
    const dictionary = createEncryptionDictionary(crypt);
    const lines = [
      "<<",
      `/Filter /${dictionary.Filter}`,
      `/R ${dictionary.R}`,
      `/V ${dictionary.V}`,
      `/Length ${dictionary.Length}`,
      `/P ${dictionary.P}`,
      `/EncryptMetadata ${dictionary.EncryptMetadata ? "true" : "false"}`,
      `/O <${bytesToHex(dictionary.O)}>`,
      `/U <${bytesToHex(dictionary.U)}>`,
    ];

    if (dictionary.CF) {
      lines.push("/StmF /StdCF");
      lines.push("/StrF /StdCF");

      if (dictionary.R === 4) {
        lines.push("/CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >> >>");
      } else {
        lines.push("/CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >>");
        lines.push(`/OE <${bytesToHex(dictionary.OE)}>`);
        lines.push(`/UE <${bytesToHex(dictionary.UE)}>`);
        lines.push(`/Perms <${bytesToHex(dictionary.Perms)}>`);
      }
    }

    lines.push(">>");
    return lines.join("\n");
  }

  async function createEncryptionContext(options) {
    const normalized = normalizeOptions(options);
    const fileId = normalized.fileId || getRandomBytes(normalized.randomBytes, 16);
    const crypt = {
      algorithm: normalized.algorithmName,
      version: normalized.algorithm.version,
      revision: normalized.algorithm.revision,
      keyLengthBits: normalized.algorithm.keyLengthBits,
      method: normalized.algorithm.method,
      permissions: normalized.permissions,
      requestedPermissions: normalized.requestedPermissions,
      encryptMetadata: normalized.encryptMetadata,
      fileId,
      randomBytes: normalized.randomBytes,
    };
    const userPasswordBytes = encodePassword(normalized.userPassword, crypt.revision);
    const ownerPasswordBytes = encodePassword(normalized.ownerPassword, crypt.revision);

    if (crypt.revision <= 4) {
      crypt.O = await computeOwnerPassword(crypt, ownerPasswordBytes, userPasswordBytes);

      const userResult = await computeUserPassword(crypt, userPasswordBytes);
      crypt.U = userResult.entry;
      crypt.fileKey = userResult.fileKey;
      crypt.OE = null;
      crypt.UE = null;
      crypt.Perms = null;
    } else {
      crypt.fileKey = getRandomBytes(normalized.randomBytes, 32);

      const userResult = await computeUserPasswordR6(crypt, userPasswordBytes, normalized.randomBytes);
      crypt.U = userResult.U;
      crypt.UE = userResult.UE;

      const ownerResult = await computeOwnerPasswordR6(crypt, ownerPasswordBytes, normalized.randomBytes);
      crypt.O = ownerResult.O;
      crypt.OE = ownerResult.OE;
      crypt.Perms = await computePermissionsR6(crypt, normalized.randomBytes);
    }

    return crypt;
  }

  // pdf-lib bridge used to normalize input PDFs into a writable classic-xref form.

export {
  ALGORITHMS,
  PERMISSIONS,
  PDF_DOC_ENCODING,
  PASSWORD_PADDING,
  MD5_SHIFT,
  MD5_INDEX,
  MD5_K,
  textEncoder,
  unicodeToPdfDoc,
  subtleCrypto,
  assert,
  normalizeBytes,
  concatBytes,
  leftRotate32,
  md5Bytes,
  hashBytes,
  rc4Encrypt,
  AES_SBOX,
  AES_INV_SBOX,
  AES_RCON,
  aesXtime,
  aesMul,
  AesBlockCipher,
  aesCbcTransformNoPadding,
  aesCbcEncrypt,
  aesCbcDecrypt,
  littleEndian32,
  littleEndian24,
  littleEndian16,
  bytesToHex,
  equalBytes,
  encodePdfDocPassword,
  encodePassword,
  padPassword,
  defaultRandomBytes,
  getRandomBytes,
  toSignedInt32,
  normalizeOptions,
  computeEncryptionKey,
  computeOwnerPassword,
  computeUserPassword,
  computeEncryptionKeyR5,
  computeEncryptionKeyR6,
  computeHardenedHashR6,
  computeUserPasswordR6,
  computeOwnerPasswordR6,
  computePermissionsR6,
  computeObjectKey,
  encryptObjectBytes,
  decryptObjectBytes,
  createEncryptionDictionary,
  serializeEncryptionDictionary,
  createEncryptionContext
};

