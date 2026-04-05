import {
  ALGORITHMS,
  PERMISSIONS,
  bytesToHex,
  createEncryptionContext,
  createEncryptionDictionary,
  computeObjectKey,
  encryptObjectBytes,
  decryptObjectBytes,
  serializeEncryptionDictionary,
} from "./utils/crypto.js";

import { parsePdfDocument } from "./utils/document.js";

import {
  addPasswordToPdfBytes,
  authenticatePassword,
  buildPermissions,
  decryptPdfBytes,
  encryptPdfBytes,
  getAlgorithmNameForCrypt,
  hasEncryption,
  inspectPdfPasswordState,
  normalizePdfBytes,
  removePasswordFromPdfBytes,
  updatePasswordOnPdfBytes,
} from "./utils/workflow.js";

export {
  ALGORITHMS,
  PERMISSIONS,
  addPasswordToPdfBytes,
  authenticatePassword,
  buildPermissions,
  bytesToHex,
  createEncryptionContext,
  createEncryptionDictionary,
  computeObjectKey,
  decryptPdfBytes,
  encryptObjectBytes,
  decryptObjectBytes,
  encryptPdfBytes,
  getAlgorithmNameForCrypt,
  hasEncryption,
  inspectPdfPasswordState,
  normalizePdfBytes,
  parsePdfDocument,
  removePasswordFromPdfBytes,
  serializeEncryptionDictionary,
  updatePasswordOnPdfBytes,
};

export const encryptStringBytes = encryptObjectBytes;
export const encryptStreamBytes = encryptObjectBytes;

