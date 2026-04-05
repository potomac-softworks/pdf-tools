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

import {
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
} from "./document.js";

async function authenticateUserPassword(crypt, passwordBytes) {
    if (crypt.revision === 2) {
      const userResult = await computeUserPassword(crypt, passwordBytes);

      if (!equalBytes(userResult.entry, crypt.U, 32)) {
        return null;
      }

      return {
        access: "user",
        fileKey: userResult.fileKey,
      };
    }

    if (crypt.revision === 3 || crypt.revision === 4) {
      const userResult = await computeUserPassword(crypt, passwordBytes);

      if (!equalBytes(userResult.entry, crypt.U, 16)) {
        return null;
      }

      return {
        access: "user",
        fileKey: userResult.fileKey,
      };
    }

    if (crypt.revision === 5) {
      const result = await computeEncryptionKeyR5(crypt, passwordBytes, false);

      if (!equalBytes(result.validationKey, crypt.U, 32)) {
        return null;
      }

      return {
        access: "user",
        fileKey: result.fileKey,
      };
    }

    if (crypt.revision === 6) {
      const result = await computeEncryptionKeyR6(crypt, passwordBytes, false);

      if (!equalBytes(result.validationKey, crypt.U, 32)) {
        return null;
      }

      return {
        access: "user",
        fileKey: result.fileKey,
      };
    }

    throw new Error(`Unsupported encryption revision "${crypt.revision}".`);
  }

  async function authenticateOwnerPassword(crypt, passwordBytes) {
    const keyLength = Math.max(0, Math.min(16, crypt.keyLengthBits / 8));

    if (crypt.revision === 2) {
      let digest = await hashBytes("MD5", padPassword(passwordBytes));
      const userPassword = rc4Encrypt(digest.subarray(0, keyLength), crypt.O);
      const result = await authenticateUserPassword(crypt, userPassword);

      return result ? { access: "owner", fileKey: result.fileKey } : null;
    }

    if (crypt.revision === 3 || crypt.revision === 4) {
      let digest = await hashBytes("MD5", padPassword(passwordBytes));

      for (let i = 0; i < 50; i += 1) {
        digest = await hashBytes("MD5", digest.subarray(0, keyLength));
      }

      let userPassword = new Uint8Array(crypt.O);

      for (let round = 0; round < 20; round += 1) {
        const xorKey = new Uint8Array(keyLength);

        for (let i = 0; i < keyLength; i += 1) {
          xorKey[i] = digest[i] ^ (19 - round);
        }

        userPassword = rc4Encrypt(xorKey, userPassword);
      }

      const result = await authenticateUserPassword(crypt, userPassword);

      return result ? { access: "owner", fileKey: result.fileKey } : null;
    }

    if (crypt.revision === 5) {
      const result = await computeEncryptionKeyR5(crypt, passwordBytes, true);

      if (!equalBytes(result.validationKey, crypt.O, 32)) {
        return null;
      }

      return {
        access: "owner",
        fileKey: result.fileKey,
      };
    }

    if (crypt.revision === 6) {
      const result = await computeEncryptionKeyR6(crypt, passwordBytes, true);

      if (!equalBytes(result.validationKey, crypt.O, 32)) {
        return null;
      }

      return {
        access: "owner",
        fileKey: result.fileKey,
      };
    }

    throw new Error(`Unsupported encryption revision "${crypt.revision}".`);
  }

  async function authenticatePassword(parsedDocument, password) {
    const crypt = parseEncryptionDictionary(parsedDocument);
    const passwordBytes = encodePassword(password || "", crypt.revision);
    const userResult = await authenticateUserPassword(crypt, passwordBytes);
    const ownerResult = await authenticateOwnerPassword(crypt, passwordBytes);

    if (!ownerResult && userResult) {
      return {
        ...crypt,
        access: userResult.access,
        fileKey: userResult.fileKey,
      };
    }

    if (passwordBytes.length === 0 && ownerResult && !userResult) {
      throw new Error("Password required to unlock this PDF.");
    }

    if (ownerResult) {
      return {
        ...crypt,
        access: ownerResult.access,
        fileKey: ownerResult.fileKey,
      };
    }

    throw new Error("Incorrect password.");
  }

  // Whole-document encryption and decryption operations.
  function withCryptFileKey(crypt, fileKey) {
    return {
      ...crypt,
      fileKey: normalizeBytes(fileKey, "file key"),
    };
  }

  async function decryptBytesWithMethod(crypt, method, objectNumber, generationNumber, bytes) {
    const payload = normalizeBytes(bytes, "object bytes");

    if (method === "identity") {
      return new Uint8Array(payload);
    }

    return decryptObjectBytes(
      withCryptFileKey({ ...crypt, method }, crypt.fileKey),
      objectNumber,
      generationNumber,
      payload
    );
  }

  async function decryptValueForObject(crypt, objectNumber, generationNumber, value) {
    if (value.type === "string") {
      if (crypt.method === "identity") {
        return makeString(value.value);
      }

      return makeString(
        await decryptBytesWithMethod(crypt, crypt.method, objectNumber, generationNumber, value.value)
      );
    }

    if (value.type === "array") {
      return {
        type: "array",
        items: await Promise.all(
          value.items.map((item) => decryptValueForObject(crypt, objectNumber, generationNumber, item))
        ),
      };
    }

    if (value.type === "dict") {
      const signatureDictionary = isSignatureDictionary(value);
      const entries = [];

      for (const entry of value.entries) {
        if (signatureDictionary && entry.key === "Contents") {
          entries.push({ key: entry.key, value: cloneValue(entry.value) });
          continue;
        }

        entries.push({
          key: entry.key,
          value: await decryptValueForObject(crypt, objectNumber, generationNumber, entry.value),
        });
      }

      return {
        type: "dict",
        entries,
      };
    }

    return cloneValue(value);
  }

  function writePdfDocument(version, objects, trailer) {
    const sortedObjects = [...objects].sort((left, right) => left.objectNumber - right.objectNumber);
    const maxObjectNumber = sortedObjects.reduce(
      (currentMax, objectRecord) => Math.max(currentMax, objectRecord.objectNumber),
      0
    );
    const writer = new PdfWriter();
    const offsets = new Array(maxObjectNumber + 1).fill(0);
    const objectMap = new Map(sortedObjects.map((objectRecord) => [objectRecord.objectNumber, objectRecord]));

    writer.pushString(`%PDF-${version}\n%\u00b5\u00b6\n\n`);

    for (const objectRecord of sortedObjects) {
      offsets[objectRecord.objectNumber] = writer.tell();
      writer.pushString(`${objectRecord.objectNumber} ${objectRecord.generationNumber} obj\n`);
      writer.pushString(serializeValue(objectRecord.value));

      if (objectRecord.streamBytes) {
        writer.pushString("\nstream\n");
        writer.pushBytes(objectRecord.streamBytes);
        writer.pushString("\nendstream");
      }

      writer.pushString("\nendobj\n\n");
    }

    const startXref = writer.tell();
    writer.pushString(`xref\n0 ${offsets.length}\n`);
    writer.pushString("0000000000 65535 f \n");

    for (let objectNumber = 1; objectNumber < offsets.length; objectNumber += 1) {
      const objectRecord = objectMap.get(objectNumber);

      if (objectRecord) {
        writer.pushString(
          `${String(offsets[objectNumber]).padStart(10, "0")} ${String(objectRecord.generationNumber).padStart(5, "0")} n \n`
        );
      } else {
        writer.pushString("0000000000 00000 f \n");
      }
    }

    writer.pushString(`trailer\n${serializeValue(trailer)}\nstartxref\n${startXref}\n%%EOF`);

    return writer.toUint8Array();
  }

  async function decryptPdfBytes(pdfBytes, options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("decryptPdfBytes expects an options object.");
    }

    const parsed = parsePdfDocument(pdfBytes);
    const crypt = await authenticatePassword(parsed, options.password ?? options.userPassword ?? "");
    const decryptedObjects = [];

    for (const objectRecord of parsed.objects) {
      if (
        objectRecord.objectNumber === crypt.encryptObjectNumber &&
        objectRecord.generationNumber === crypt.encryptObjectGeneration
      ) {
        continue;
      }

      const decryptedValue = await decryptValueForObject(
        crypt,
        objectRecord.objectNumber,
        objectRecord.generationNumber,
        objectRecord.value
      );
      let streamBytes = objectRecord.streamBytes ? new Uint8Array(objectRecord.streamBytes) : null;

      if (streamBytes && !(!crypt.encryptMetadata && isMetadataStreamObject(objectRecord))) {
        streamBytes = await decryptBytesWithMethod(
          crypt,
          crypt.method,
          objectRecord.objectNumber,
          objectRecord.generationNumber,
          streamBytes
        );
      }

      if (streamBytes) {
        dictSet(decryptedValue, "Length", makeNumber(streamBytes.length));
      }

      decryptedObjects.push({
        objectNumber: objectRecord.objectNumber,
        generationNumber: objectRecord.generationNumber,
        value: decryptedValue,
        streamBytes,
      });
    }

    const trailer = cloneValue(parsed.trailer);
    dictDelete(trailer, "Encrypt");
    dictDelete(trailer, "Prev");
    dictDelete(trailer, "XRefStm");
    dictSet(
      trailer,
      "Size",
      makeNumber(
        decryptedObjects.reduce(
          (currentMax, objectRecord) => Math.max(currentMax, objectRecord.objectNumber),
          0
        ) + 1
      )
    );

    return writePdfDocument(parsed.version, decryptedObjects, trailer);
  }

  // Public product-level operations used by the password page.
  function hasEncryption(value) {
    const parsedDocument = value && value.trailer ? value : parsePdfDocument(value);
    const encryptValue = dictGet(parsedDocument.trailer, "Encrypt");
    return Boolean(encryptValue);
  }

  function getAlgorithmNameForCrypt(crypt) {
    if (crypt.revision === 2 && crypt.method === "rc4") return "rc4-40";
    if (crypt.revision === 3 && crypt.method === "rc4") return "rc4-128";
    if (crypt.revision === 4 && crypt.method === "aesv2") return "aes-128";
    if ((crypt.revision === 5 || crypt.revision === 6) && crypt.method === "aesv3") return "aes-256";
    return "aes-256";
  }

  function inspectPdfPasswordState(pdfBytes) {
    const parsed = parsePdfDocument(pdfBytes);

    if (!hasEncryption(parsed)) {
      return {
        encrypted: false,
        algorithm: null,
        revision: null,
        permissions: null,
        encryptMetadata: null,
      };
    }

    const crypt = parseEncryptionDictionary(parsed);

    return {
      encrypted: true,
      algorithm: getAlgorithmNameForCrypt(crypt),
      revision: crypt.revision,
      permissions: crypt.permissions,
      encryptMetadata: crypt.encryptMetadata,
    };
  }

  async function addPasswordToPdfBytes(pdfBytes, options) {
    return encryptPdfBytes(pdfBytes, options);
  }

  async function removePasswordFromPdfBytes(pdfBytes, options) {
    return decryptPdfBytes(pdfBytes, options);
  }

  async function updatePasswordOnPdfBytes(pdfBytes, options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("updatePasswordOnPdfBytes expects an options object.");
    }

    const parsed = parsePdfDocument(pdfBytes);

    if (!hasEncryption(parsed)) {
      throw new Error("This PDF is not password-protected.");
    }

    const currentCrypt = await authenticatePassword(parsed, options.password ?? options.currentPassword ?? "");
    const decryptedBytes = await decryptPdfBytes(pdfBytes, {
      password: options.password ?? options.currentPassword ?? "",
    });

    return encryptPdfBytes(decryptedBytes, {
      encrypt: options.encrypt || getAlgorithmNameForCrypt(currentCrypt),
      userPassword: options.userPassword ?? options.newUserPassword ?? "",
      ownerPassword:
        options.ownerPassword ??
        options.newOwnerPassword ??
        options.userPassword ??
        options.newUserPassword ??
        "",
      permissions:
        typeof options.permissions === "number"
          ? options.permissions
          : currentCrypt.permissions,
      encryptMetadata:
        typeof options.encryptMetadata === "boolean"
          ? options.encryptMetadata
          : currentCrypt.encryptMetadata,
      randomBytes: options.randomBytes,
      fileId: options.fileId,
      secondFileId: options.secondFileId,
    });
  }

  async function encryptValueForObject(crypt, objectNumber, generationNumber, value) {
    if (value.type === "string") {
      return makeString(await encryptObjectBytes(crypt, objectNumber, generationNumber, value.value));
    }

    if (value.type === "array") {
      return {
        type: "array",
        items: await Promise.all(
          value.items.map((item) => encryptValueForObject(crypt, objectNumber, generationNumber, item))
        ),
      };
    }

    if (value.type === "dict") {
      const signatureDictionary = isSignatureDictionary(value);
      const entries = [];

      for (const entry of value.entries) {
        if (signatureDictionary && entry.key === "Contents") {
          entries.push({ key: entry.key, value: cloneValue(entry.value) });
          continue;
        }

        entries.push({
          key: entry.key,
          value: await encryptValueForObject(crypt, objectNumber, generationNumber, entry.value),
        });
      }

      return {
        type: "dict",
        entries,
      };
    }

    return cloneValue(value);
  }

  async function normalizePdfBytes(bytes) {
    const pdfLib = getPdfLib();

    if (!pdfLib || !pdfLib.PDFDocument) {
      throw new Error("pdf-lib is required to normalize PDFs before encryption.");
    }

    const input = normalizeBytes(bytes, "PDF bytes");
    const document = await pdfLib.PDFDocument.load(input, { updateMetadata: false });
    const normalized = await document.save({ useObjectStreams: false });

    return new Uint8Array(normalized);
  }

  class PdfWriter {
    constructor() {
      this.parts = [];
      this.length = 0;
    }

    pushString(value) {
      const bytes = textEncoder.encode(value);
      this.parts.push(bytes);
      this.length += bytes.length;
    }

    pushBytes(value) {
      const bytes = normalizeBytes(value, "PDF output bytes");
      this.parts.push(bytes);
      this.length += bytes.length;
    }

    tell() {
      return this.length;
    }

    toUint8Array() {
      const output = new Uint8Array(this.length);
      let offset = 0;

      for (const part of this.parts) {
        output.set(part, offset);
        offset += part.length;
      }

      return output;
    }
  }

  async function encryptPdfBytes(pdfBytes, options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("encryptPdfBytes expects an options object.");
    }

    const normalizedPdf = await normalizePdfBytes(pdfBytes);
    const parsed = parsePdfDocument(normalizedPdf);
    const randomBytes = typeof options.randomBytes === "function" ? options.randomBytes : defaultRandomBytes;
    const fileId = options.fileId ? normalizeBytes(options.fileId, "fileId") : getRandomBytes(randomBytes, 16);
    const secondFileId = options.secondFileId ? normalizeBytes(options.secondFileId, "secondFileId") : getRandomBytes(randomBytes, 16);
    const crypt = await createEncryptionContext({
      ...options,
      fileId,
      randomBytes,
    });
    const maxObjectNumber = parsed.objects.reduce(
      (currentMax, objectRecord) => Math.max(currentMax, objectRecord.objectNumber),
      0
    );
    const encryptObjectNumber = maxObjectNumber + 1;
    const encryptedObjects = [];

    for (const objectRecord of parsed.objects) {
      const encryptedValue = await encryptValueForObject(
        crypt,
        objectRecord.objectNumber,
        objectRecord.generationNumber,
        objectRecord.value
      );
      let streamBytes = objectRecord.streamBytes ? new Uint8Array(objectRecord.streamBytes) : null;

      if (streamBytes && !(!crypt.encryptMetadata && isMetadataStreamObject(objectRecord))) {
        streamBytes = await encryptObjectBytes(
          crypt,
          objectRecord.objectNumber,
          objectRecord.generationNumber,
          streamBytes,
          randomBytes
        );
      }

      if (streamBytes) {
        dictSet(encryptedValue, "Length", makeNumber(streamBytes.length));
      }

      encryptedObjects.push({
        objectNumber: objectRecord.objectNumber,
        generationNumber: objectRecord.generationNumber,
        value: encryptedValue,
        streamBytes,
      });
    }

    encryptedObjects.push({
      objectNumber: encryptObjectNumber,
      generationNumber: 0,
      value: createEncryptionDictionaryValue(crypt),
      streamBytes: null,
    });

    const trailer = cloneValue(parsed.trailer);
    dictDelete(trailer, "Prev");
    dictDelete(trailer, "XRefStm");
    dictSet(trailer, "Size", makeNumber(encryptObjectNumber + 1));
    dictSet(trailer, "Encrypt", makeRef(encryptObjectNumber, 0));
    dictSet(trailer, "ID", {
      type: "array",
      items: [makeString(fileId), makeString(secondFileId)],
    });

    const writer = new PdfWriter();
    const offsets = new Array(encryptObjectNumber + 1).fill(0);
    const objectMap = new Map(encryptedObjects.map((objectRecord) => [objectRecord.objectNumber, objectRecord]));

    writer.pushString(`%PDF-${parsed.version}\n%\u00b5\u00b6\n\n`);

    encryptedObjects.sort((left, right) => left.objectNumber - right.objectNumber);

    for (const objectRecord of encryptedObjects) {
      offsets[objectRecord.objectNumber] = writer.tell();
      writer.pushString(`${objectRecord.objectNumber} ${objectRecord.generationNumber} obj\n`);
      writer.pushString(serializeValue(objectRecord.value));

      if (objectRecord.streamBytes) {
        writer.pushString("\nstream\n");
        writer.pushBytes(objectRecord.streamBytes);
        writer.pushString("\nendstream");
      }

      writer.pushString("\nendobj\n\n");
    }

    const startXref = writer.tell();
    writer.pushString(`xref\n0 ${offsets.length}\n`);
    writer.pushString("0000000000 65535 f \n");

    for (let objectNumber = 1; objectNumber < offsets.length; objectNumber += 1) {
      const objectRecord = objectMap.get(objectNumber);

      if (objectRecord) {
        writer.pushString(
          `${String(offsets[objectNumber]).padStart(10, "0")} ${String(objectRecord.generationNumber).padStart(5, "0")} n \n`
        );
      } else {
        writer.pushString("0000000000 00000 f \n");
      }
    }

    writer.pushString(`trailer\n${serializeValue(trailer)}\nstartxref\n${startXref}\n%%EOF`);

    return writer.toUint8Array();
  }

  function buildPermissions(config) {
    if (!config || typeof config !== "object") {
      throw new TypeError("buildPermissions expects an object.");
    }

    let permissions = 0;

    if (config.print) permissions |= PERMISSIONS.PRINT;
    if (config.modify) permissions |= PERMISSIONS.MODIFY;
    if (config.copy) permissions |= PERMISSIONS.COPY;
    if (config.annotate) permissions |= PERMISSIONS.ANNOTATE;
    if (config.form) permissions |= PERMISSIONS.FORM;
    if (config.accessibility) permissions |= PERMISSIONS.ACCESSIBILITY;
    if (config.assemble) permissions |= PERMISSIONS.ASSEMBLE;
    if (config.printHighQuality || config.printHq) permissions |= PERMISSIONS.PRINT_HQ;

    return permissions;
  }

export {
  authenticateUserPassword,
  authenticateOwnerPassword,
  authenticatePassword,
  withCryptFileKey,
  decryptBytesWithMethod,
  decryptValueForObject,
  writePdfDocument,
  decryptPdfBytes,
  hasEncryption,
  getAlgorithmNameForCrypt,
  inspectPdfPasswordState,
  addPasswordToPdfBytes,
  removePasswordFromPdfBytes,
  updatePasswordOnPdfBytes,
  encryptValueForObject,
  normalizePdfBytes,
  PdfWriter,
  encryptPdfBytes,
  buildPermissions
};

