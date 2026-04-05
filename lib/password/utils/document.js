import {
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
} from "./crypto.js";
import { PDFDocument } from "../../../node_modules/pdf-lib/dist/pdf-lib.esm.js";

function getPdfLib() {
  return { PDFDocument };
}

  function isWhiteSpace(byte) {
    return byte === 0x00 || byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
  }

  function isDelimiter(byte) {
    return (
      byte === 0x28 ||
      byte === 0x29 ||
      byte === 0x3c ||
      byte === 0x3e ||
      byte === 0x5b ||
      byte === 0x5d ||
      byte === 0x7b ||
      byte === 0x7d ||
      byte === 0x2f ||
      byte === 0x25
    );
  }

  function isDigit(byte) {
    return byte >= 0x30 && byte <= 0x39;
  }

  function isOctalDigit(byte) {
    return byte >= 0x30 && byte <= 0x37;
  }

  function isHexDigit(byte) {
    return (
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x46) ||
      (byte >= 0x61 && byte <= 0x66)
    );
  }

  function bytesToAscii(bytes, start, end) {
    const input = normalizeBytes(bytes, "bytes");
    const from = start || 0;
    const to = end === undefined ? input.length : end;
    let output = "";

    for (let i = from; i < to; i += 1) {
      output += String.fromCharCode(input[i]);
    }

    return output;
  }

  function asciiBytes(value) {
    const output = new Uint8Array(value.length);

    for (let i = 0; i < value.length; i += 1) {
      output[i] = value.charCodeAt(i) & 0xff;
    }

    return output;
  }

  function isIntegerToken(token) {
    return /^[+-]?\d+$/.test(token);
  }

  function makeName(value) {
    return { type: "name", value };
  }

  function makeNumber(value) {
    return { type: "number", value: String(value) };
  }

  function makeString(value) {
    return { type: "string", value: normalizeBytes(value, "string bytes") };
  }

  function makeRef(objectNumber, generationNumber) {
    return {
      type: "ref",
      objectNumber,
      generationNumber,
    };
  }

  function cloneValue(value) {
    if (!value || typeof value !== "object") {
      return value;
    }

    if (value.type === "string") {
      return {
        type: "string",
        value: new Uint8Array(value.value),
      };
    }

    if (value.type === "array") {
      return {
        type: "array",
        items: value.items.map(cloneValue),
      };
    }

    if (value.type === "dict") {
      return {
        type: "dict",
        entries: value.entries.map((entry) => ({
          key: entry.key,
          value: cloneValue(entry.value),
        })),
      };
    }

    if (value.type === "ref") {
      return {
        type: "ref",
        objectNumber: value.objectNumber,
        generationNumber: value.generationNumber,
      };
    }

    return { ...value };
  }

  function dictIndexOf(dictValue, key) {
    return dictValue.entries.findIndex((entry) => entry.key === key);
  }

  function dictGet(dictValue, key) {
    const index = dictIndexOf(dictValue, key);
    return index === -1 ? null : dictValue.entries[index].value;
  }

  function dictSet(dictValue, key, value) {
    const index = dictIndexOf(dictValue, key);

    if (index === -1) {
      dictValue.entries.push({ key, value });
      return;
    }

    dictValue.entries[index] = { key, value };
  }

  function dictDelete(dictValue, key) {
    const index = dictIndexOf(dictValue, key);

    if (index !== -1) {
      dictValue.entries.splice(index, 1);
    }
  }

  function dictGetName(dictValue, key) {
    const value = dictGet(dictValue, key);
    return value && value.type === "name" ? value.value : null;
  }

  function dictGetInteger(dictValue, key) {
    const value = dictGet(dictValue, key);

    if (!value || value.type !== "number" || !isIntegerToken(value.value)) {
      return null;
    }

    return Number.parseInt(value.value, 10);
  }

  function dictGetBoolean(dictValue, key, fallback) {
    const value = dictGet(dictValue, key);

    if (!value || value.type !== "boolean") {
      return fallback;
    }

    return value.value;
  }

  function dictGetStringBytes(dictValue, key) {
    const value = dictGet(dictValue, key);
    return value && value.type === "string" ? new Uint8Array(value.value) : null;
  }

  function serializeNameToken(name) {
    let output = "";

    for (let i = 0; i < name.length; i += 1) {
      const code = name.charCodeAt(i);
      const isSafe =
        (code >= 0x30 && code <= 0x39) ||
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a) ||
        code === 0x2d ||
        code === 0x5f ||
        code === 0x2e;

      if (isSafe) {
        output += String.fromCharCode(code);
      } else {
        output += `#${code.toString(16).padStart(2, "0").toUpperCase()}`;
      }
    }

    return output;
  }

  function serializeValue(value) {
    switch (value.type) {
      case "name":
        return `/${serializeNameToken(value.value)}`;
      case "number":
        return value.value;
      case "boolean":
        return value.value ? "true" : "false";
      case "null":
        return "null";
      case "ref":
        return `${value.objectNumber} ${value.generationNumber} R`;
      case "string":
        return `<${bytesToHex(value.value)}>`;
      case "array":
        return `[ ${value.items.map((item) => serializeValue(item)).join(" ")} ]`;
      case "dict":
        return [
          "<<",
          ...value.entries.map((entry) => `/${serializeNameToken(entry.key)} ${serializeValue(entry.value)}`),
          ">>",
        ].join("\n");
      default:
        throw new Error(`Cannot serialize PDF value of type "${value.type}".`);
    }
  }

  class PdfReader {
    constructor(bytes) {
      this.bytes = normalizeBytes(bytes, "PDF bytes");
      this.offset = 0;
    }

    eof() {
      return this.offset >= this.bytes.length;
    }

    peek(offset) {
      const delta = offset || 0;
      return this.bytes[this.offset + delta];
    }

    skipWhitespaceAndComments() {
      while (!this.eof()) {
        const byte = this.peek();

        if (isWhiteSpace(byte)) {
          this.offset += 1;
          continue;
        }

        if (byte === 0x25) {
          this.offset += 1;

          while (!this.eof()) {
            const current = this.peek();
            this.offset += 1;

            if (current === 0x0a || current === 0x0d) {
              break;
            }
          }

          continue;
        }

        break;
      }
    }

    matchKeyword(keyword) {
      const token = asciiBytes(keyword);

      for (let i = 0; i < token.length; i += 1) {
        if (this.bytes[this.offset + i] !== token[i]) {
          return false;
        }
      }

      const next = this.bytes[this.offset + token.length];
      return next === undefined || isWhiteSpace(next) || isDelimiter(next);
    }

    expectKeyword(keyword) {
      this.skipWhitespaceAndComments();

      if (!this.matchKeyword(keyword)) {
        throw new Error(`Expected PDF keyword "${keyword}".`);
      }

      this.offset += keyword.length;
    }

    readSimpleToken() {
      this.skipWhitespaceAndComments();
      const start = this.offset;

      while (!this.eof()) {
        const byte = this.peek();

        if (isWhiteSpace(byte) || isDelimiter(byte)) {
          break;
        }

        this.offset += 1;
      }

      return bytesToAscii(this.bytes, start, this.offset);
    }
  }

  function parseName(reader) {
    reader.skipWhitespaceAndComments();

    if (reader.peek() !== 0x2f) {
      throw new Error("Expected PDF name object.");
    }

    reader.offset += 1;
    let output = "";

    while (!reader.eof()) {
      const byte = reader.peek();

      if (isWhiteSpace(byte) || isDelimiter(byte)) {
        break;
      }

      if (byte === 0x23 && isHexDigit(reader.peek(1)) && isHexDigit(reader.peek(2))) {
        output += String.fromCharCode(Number.parseInt(bytesToAscii(reader.bytes, reader.offset + 1, reader.offset + 3), 16));
        reader.offset += 3;
        continue;
      }

      output += String.fromCharCode(byte);
      reader.offset += 1;
    }

    return makeName(output);
  }

  function parseHexString(reader) {
    reader.skipWhitespaceAndComments();
    reader.offset += 1;

    let hex = "";

    while (!reader.eof()) {
      const byte = reader.peek();

      if (byte === 0x3e) {
        reader.offset += 1;
        break;
      }

      if (!isWhiteSpace(byte)) {
        if (!isHexDigit(byte)) {
          throw new Error("Invalid PDF hex string.");
        }

        hex += String.fromCharCode(byte);
      }

      reader.offset += 1;
    }

    if (hex.length % 2 === 1) {
      hex += "0";
    }

    const output = new Uint8Array(hex.length / 2);

    for (let i = 0; i < hex.length; i += 2) {
      output[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
    }

    return makeString(output);
  }

  function parseLiteralString(reader) {
    reader.skipWhitespaceAndComments();
    reader.offset += 1;

    const output = [];
    let depth = 1;

    while (!reader.eof() && depth > 0) {
      const byte = reader.peek();
      reader.offset += 1;

      if (byte === 0x5c) {
        if (reader.eof()) {
          break;
        }

        const escaped = reader.peek();
        reader.offset += 1;

        if (escaped === 0x0a) {
          continue;
        }

        if (escaped === 0x0d) {
          if (reader.peek() === 0x0a) {
            reader.offset += 1;
          }

          continue;
        }

        if (escaped === 0x6e) {
          output.push(0x0a);
          continue;
        }

        if (escaped === 0x72) {
          output.push(0x0d);
          continue;
        }

        if (escaped === 0x74) {
          output.push(0x09);
          continue;
        }

        if (escaped === 0x62) {
          output.push(0x08);
          continue;
        }

        if (escaped === 0x66) {
          output.push(0x0c);
          continue;
        }

        if (isOctalDigit(escaped)) {
          let octal = String.fromCharCode(escaped);

          for (let i = 0; i < 2 && isOctalDigit(reader.peek()); i += 1) {
            octal += String.fromCharCode(reader.peek());
            reader.offset += 1;
          }

          output.push(Number.parseInt(octal, 8) & 0xff);
          continue;
        }

        output.push(escaped);
        continue;
      }

      if (byte === 0x28) {
        depth += 1;
        output.push(byte);
        continue;
      }

      if (byte === 0x29) {
        depth -= 1;

        if (depth > 0) {
          output.push(byte);
        }

        continue;
      }

      output.push(byte);
    }

    return makeString(Uint8Array.from(output));
  }

  function parseArray(reader) {
    reader.skipWhitespaceAndComments();
    reader.offset += 1;

    const items = [];

    while (true) {
      reader.skipWhitespaceAndComments();

      if (reader.peek() === 0x5d) {
        reader.offset += 1;
        break;
      }

      items.push(parseValue(reader));
    }

    return {
      type: "array",
      items,
    };
  }

  function parseDictionary(reader) {
    reader.skipWhitespaceAndComments();
    reader.offset += 2;

    const entries = [];

    while (true) {
      reader.skipWhitespaceAndComments();

      if (reader.peek() === 0x3e && reader.peek(1) === 0x3e) {
        reader.offset += 2;
        break;
      }

      const key = parseName(reader);
      const value = parseValue(reader);
      entries.push({ key: key.value, value });
    }

    return {
      type: "dict",
      entries,
    };
  }

  function parseValue(reader) {
    reader.skipWhitespaceAndComments();
    const byte = reader.peek();

    if (byte === 0x3c && reader.peek(1) === 0x3c) {
      return parseDictionary(reader);
    }

    if (byte === 0x5b) {
      return parseArray(reader);
    }

    if (byte === 0x2f) {
      return parseName(reader);
    }

    if (byte === 0x28) {
      return parseLiteralString(reader);
    }

    if (byte === 0x3c) {
      return parseHexString(reader);
    }

    const token = reader.readSimpleToken();

    if (token === "true" || token === "false") {
      return {
        type: "boolean",
        value: token === "true",
      };
    }

    if (token === "null") {
      return { type: "null" };
    }

    if (!token) {
      throw new Error("Unexpected end of PDF value.");
    }

    if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(token)) {
      const checkpoint = reader.offset;

      if (isIntegerToken(token)) {
        reader.skipWhitespaceAndComments();
        const secondToken = reader.readSimpleToken();

        if (isIntegerToken(secondToken)) {
          reader.skipWhitespaceAndComments();

          if (reader.matchKeyword("R")) {
            reader.offset += 1;
            return makeRef(Number.parseInt(token, 10), Number.parseInt(secondToken, 10));
          }
        }

        reader.offset = checkpoint;
      }

      return {
        type: "number",
        value: token,
      };
    }

    throw new Error(`Unsupported PDF token "${token}".`);
  }

  function findLastKeyword(bytes, keyword) {
    const input = normalizeBytes(bytes, "PDF bytes");
    const token = asciiBytes(keyword);

    for (let index = input.length - token.length; index >= 0; index -= 1) {
      let matches = true;

      for (let i = 0; i < token.length; i += 1) {
        if (input[index + i] !== token[i]) {
          matches = false;
          break;
        }
      }

      if (!matches) {
        continue;
      }

      const before = index > 0 ? input[index - 1] : undefined;
      const after = input[index + token.length];

      if (
        (before === undefined || isWhiteSpace(before) || isDelimiter(before)) &&
        (after === undefined || isWhiteSpace(after) || isDelimiter(after))
      ) {
        return index;
      }
    }

    return -1;
  }

  function parsePdfDocument(bytes) {
    const input = normalizeBytes(bytes, "PDF bytes");
    const header = bytesToAscii(input, 0, Math.min(input.length, 16));
    const versionMatch = header.match(/%PDF-(\d\.\d)/);

    if (!versionMatch) {
      throw new Error("Expected a PDF header.");
    }

    const reader = new PdfReader(input);
    const objects = [];

    while (!reader.eof()) {
      reader.skipWhitespaceAndComments();

      if (reader.matchKeyword("xref")) {
        break;
      }

      if (reader.eof()) {
        break;
      }

      const objectNumberToken = reader.readSimpleToken();
      const generationNumberToken = reader.readSimpleToken();

      if (!isIntegerToken(objectNumberToken) || !isIntegerToken(generationNumberToken)) {
        throw new Error("Expected an indirect object header.");
      }

      reader.expectKeyword("obj");
      const value = parseValue(reader);
      let streamBytes = null;

      reader.skipWhitespaceAndComments();

      if (value.type === "dict" && reader.matchKeyword("stream")) {
        const length = dictGetInteger(value, "Length");

        if (length === null || length < 0) {
          throw new Error("Only direct integer stream lengths are supported.");
        }

        reader.offset += "stream".length;

        if (reader.peek() === 0x0d && reader.peek(1) === 0x0a) {
          reader.offset += 2;
        } else if (reader.peek() === 0x0d || reader.peek() === 0x0a) {
          reader.offset += 1;
        } else {
          throw new Error("Expected a line break after the stream keyword.");
        }

        streamBytes = input.slice(reader.offset, reader.offset + length);
        reader.offset += length;

        if (reader.peek() === 0x0d && reader.peek(1) === 0x0a && bytesToAscii(input, reader.offset + 2, reader.offset + 11) === "endstream") {
          reader.offset += 2;
        } else if ((reader.peek() === 0x0d || reader.peek() === 0x0a) && bytesToAscii(input, reader.offset + 1, reader.offset + 10) === "endstream") {
          reader.offset += 1;
        }

        reader.expectKeyword("endstream");
      }

      reader.expectKeyword("endobj");

      objects.push({
        objectNumber: Number.parseInt(objectNumberToken, 10),
        generationNumber: Number.parseInt(generationNumberToken, 10),
        value,
        streamBytes,
      });
    }

    const trailerIndex = findLastKeyword(input, "trailer");

    if (trailerIndex === -1) {
      throw new Error("Expected a trailer dictionary.");
    }

    reader.offset = trailerIndex + "trailer".length;
    const trailer = parseValue(reader);

    if (!trailer || trailer.type !== "dict") {
      throw new Error("Expected trailer to be a dictionary.");
    }

    return {
      version: versionMatch[1],
      objects,
      trailer,
    };
  }

  // Parsed PDF helpers for reading and writing encrypted documents.
  function createEncryptionDictionaryValue(crypt) {
    const dictionary = {
      type: "dict",
      entries: [
        { key: "Filter", value: makeName("Standard") },
        { key: "R", value: makeNumber(crypt.revision) },
        { key: "V", value: makeNumber(crypt.version) },
        { key: "Length", value: makeNumber(crypt.keyLengthBits) },
        { key: "P", value: makeNumber(crypt.permissions) },
        {
          key: "EncryptMetadata",
          value: { type: "boolean", value: crypt.encryptMetadata },
        },
        { key: "O", value: makeString(crypt.O) },
        { key: "U", value: makeString(crypt.U) },
      ],
    };

    if (crypt.revision === 4) {
      dictSet(dictionary, "StmF", makeName("StdCF"));
      dictSet(dictionary, "StrF", makeName("StdCF"));
      dictSet(dictionary, "CF", {
        type: "dict",
        entries: [
          {
            key: "StdCF",
            value: {
              type: "dict",
              entries: [
                { key: "AuthEvent", value: makeName("DocOpen") },
                { key: "CFM", value: makeName("AESV2") },
                { key: "Length", value: makeNumber(16) },
              ],
            },
          },
        ],
      });
    }

    if (crypt.revision === 6) {
      dictSet(dictionary, "StmF", makeName("StdCF"));
      dictSet(dictionary, "StrF", makeName("StdCF"));
      dictSet(dictionary, "CF", {
        type: "dict",
        entries: [
          {
            key: "StdCF",
            value: {
              type: "dict",
              entries: [
                { key: "AuthEvent", value: makeName("DocOpen") },
                { key: "CFM", value: makeName("AESV3") },
                { key: "Length", value: makeNumber(32) },
              ],
            },
          },
        ],
      });
      dictSet(dictionary, "OE", makeString(crypt.OE));
      dictSet(dictionary, "UE", makeString(crypt.UE));
      dictSet(dictionary, "Perms", makeString(crypt.Perms));
    }

    return dictionary;
  }

  function isSignatureDictionary(dictValue) {
    return (
      dictGetName(dictValue, "Type") === "Sig" &&
      dictGet(dictValue, "Contents") &&
      dictGet(dictValue, "ByteRange") &&
      dictGet(dictValue, "Filter")
    );
  }

  function isMetadataStreamObject(objectRecord) {
    return objectRecord.streamBytes && dictGetName(objectRecord.value, "Type") === "Metadata";
  }

  function buildObjectMaps(objects) {
    const map = new Map();
    const keyMap = new Map();

    for (const objectRecord of objects) {
      map.set(objectRecord.objectNumber, objectRecord);
      keyMap.set(`${objectRecord.objectNumber} ${objectRecord.generationNumber}`, objectRecord);
    }

    return { map, keyMap };
  }

  function resolveReferenceObject(objectMaps, value) {
    if (!value || value.type !== "ref") {
      return null;
    }

    return (
      objectMaps.keyMap.get(`${value.objectNumber} ${value.generationNumber}`) ||
      objectMaps.map.get(value.objectNumber) ||
      null
    );
  }

  function resolveReferenceValue(objectMaps, value) {
    const objectRecord = resolveReferenceObject(objectMaps, value);
    return objectRecord ? objectRecord.value : value;
  }

  function getTrailerFileId(parsedDocument) {
    const idValue = dictGet(parsedDocument.trailer, "ID");

    if (!idValue || idValue.type !== "array" || idValue.items.length < 1 || idValue.items[0].type !== "string") {
      throw new Error("Encrypted PDFs must include a trailer ID array.");
    }

    return new Uint8Array(idValue.items[0].value);
  }

  function parseCryptMethod(methodName) {
    if (!methodName || methodName === "V2") {
      return "rc4";
    }

    if (methodName === "AESV2") {
      return "aesv2";
    }

    if (methodName === "AESV3") {
      return "aesv3";
    }

    if (methodName === "Identity") {
      return "identity";
    }

    throw new Error(`Unsupported crypt filter method "${methodName}".`);
  }

  function parseCryptFilterMethod(encryptDictionary, filterName, objectMaps, fallbackMethod) {
    if (!filterName || filterName === "Identity") {
      return "identity";
    }

    const cryptFilters = resolveReferenceValue(objectMaps, dictGet(encryptDictionary, "CF"));

    if (!cryptFilters || cryptFilters.type !== "dict") {
      return fallbackMethod;
    }

    const filterDictionary = resolveReferenceValue(objectMaps, dictGet(cryptFilters, filterName));

    if (!filterDictionary || filterDictionary.type !== "dict") {
      return fallbackMethod;
    }

    return parseCryptMethod(dictGetName(filterDictionary, "CFM"));
  }

  function parseEncryptionDictionary(parsedDocument) {
    const objectMaps = buildObjectMaps(parsedDocument.objects);
    const encryptRef = dictGet(parsedDocument.trailer, "Encrypt");
    const encryptObject = resolveReferenceObject(objectMaps, encryptRef);

    if (!encryptObject || !encryptObject.value || encryptObject.value.type !== "dict") {
      throw new Error("Expected trailer /Encrypt to reference a dictionary object.");
    }

    const encryptDictionary = encryptObject.value;
    const version = dictGetInteger(encryptDictionary, "V");
    const revision = dictGetInteger(encryptDictionary, "R");
    const permissions = dictGetInteger(encryptDictionary, "P");
    const fileId = getTrailerFileId(parsedDocument);

    if (version === null || revision === null || permissions === null) {
      throw new Error("Encryption dictionary is missing V, R, or P.");
    }

    let keyLengthBits = 40;

    if (version === 2 || version === 4) {
      keyLengthBits = dictGetInteger(encryptDictionary, "Length") || keyLengthBits;

      if (keyLengthBits < 40) {
        keyLengthBits *= 8;
      }
    } else if (version === 5) {
      keyLengthBits = 256;
    }

    const defaultMethod =
      version === 4 ? "aesv2" :
      version === 5 ? "aesv3" :
      "rc4";
    const stringMethod = parseCryptFilterMethod(
      encryptDictionary,
      dictGetName(encryptDictionary, "StrF"),
      objectMaps,
      defaultMethod
    );
    const streamMethod = parseCryptFilterMethod(
      encryptDictionary,
      dictGetName(encryptDictionary, "StmF"),
      objectMaps,
      defaultMethod
    );

    if (stringMethod !== streamMethod) {
      throw new Error("Different string and stream crypt filters are not yet supported.");
    }

    return {
      version,
      revision,
      permissions,
      keyLengthBits,
      method: stringMethod,
      encryptMetadata: dictGetBoolean(encryptDictionary, "EncryptMetadata", true),
      fileId,
      O: dictGetStringBytes(encryptDictionary, "O"),
      U: dictGetStringBytes(encryptDictionary, "U"),
      OE: dictGetStringBytes(encryptDictionary, "OE"),
      UE: dictGetStringBytes(encryptDictionary, "UE"),
      Perms: dictGetStringBytes(encryptDictionary, "Perms"),
      encryptObjectNumber: encryptObject.objectNumber,
      encryptObjectGeneration: encryptObject.generationNumber,
      encryptObjectRef: encryptRef,
      encryptDictionary: cloneValue(encryptDictionary),
    };
  }

export {
  getPdfLib,
  isWhiteSpace,
  isDelimiter,
  isDigit,
  isOctalDigit,
  isHexDigit,
  bytesToAscii,
  asciiBytes,
  isIntegerToken,
  makeName,
  makeNumber,
  makeString,
  makeRef,
  cloneValue,
  dictIndexOf,
  dictGet,
  dictSet,
  dictDelete,
  dictGetName,
  dictGetInteger,
  dictGetBoolean,
  dictGetStringBytes,
  serializeNameToken,
  serializeValue,
  PdfReader,
  parseName,
  parseHexString,
  parseLiteralString,
  parseArray,
  parseDictionary,
  parseValue,
  findLastKeyword,
  parsePdfDocument,
  createEncryptionDictionaryValue,
  isSignatureDictionary,
  isMetadataStreamObject,
  buildObjectMaps,
  resolveReferenceObject,
  resolveReferenceValue,
  getTrailerFileId,
  parseCryptMethod,
  parseCryptFilterMethod,
  parseEncryptionDictionary
};

