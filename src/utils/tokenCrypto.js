const crypto = require("crypto");

/**
 * AES-256-GCM encryption for third party refresh tokens stored in the database.
 *
 * The key comes from INTEGRATION_ENCRYPTION_KEY and must decode to exactly 32 bytes.
 * Generate one on the server with:  openssl rand -base64 32
 *
 * Stored format:  v1.<iv>.<authTag>.<ciphertext>   (each part base64url)
 */

const VERSION = "v1";
const IV_BYTES = 12;

function decodeKey(raw) {
  const value = String(raw || "").trim();
  if (!value) return null;
  const key = /^[0-9a-fA-F]{64}$/.test(value)
    ? Buffer.from(value, "hex")
    : Buffer.from(value, "base64");
  return key.length === 32 ? key : null;
}

function getKey() {
  const key = decodeKey(process.env.INTEGRATION_ENCRYPTION_KEY);
  if (!key) {
    throw new Error(
      "INTEGRATION_ENCRYPTION_KEY is missing or invalid. It must decode to 32 bytes (openssl rand -base64 32)."
    );
  }
  return key;
}

function isConfigured() {
  return decodeKey(process.env.INTEGRATION_ENCRYPTION_KEY) !== null;
}

function encrypt(plainText) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url"),
  ].join(".");
}

function decrypt(payload) {
  const key = getKey();
  const parts = String(payload || "").split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("Unsupported encrypted token format");
  }
  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const data = Buffer.from(parts[3], "base64url");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

module.exports = { encrypt, decrypt, isConfigured };
