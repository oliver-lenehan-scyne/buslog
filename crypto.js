/**
 * @typedef {object} DerivedKey
 * @property {ArrayLike<number>} key
 * @property {ArrayLike<number>} salt
 */
/**
 * @typedef {object} EncryptedMessage
 * @property {ArrayLike<number>} ciphertext
 * @property {ArrayLike<number>} iv
 * @property {ArrayLike<number>} salt
 */

/**
 * @param {string} password
 * @param {{ salt: ArrayLike<number> }} options
 * @returns {DerivedKey}
 */
async function derive(password, { salt = crypto.getRandomValues(new Uint8Array(16)) } = {}) {
  password = new TextEncoder().encode(password);

  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: Uint8Array.from(salt), iterations: 1000000 },
    await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveKey"]),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  return { key, salt: [...salt] };
}

/**
 * @param {string} plaintext
 * @param {DerivedKey} key
 * @returns {EncryptedMessage}
 */
async function encrypt(plaintext, { key, salt }) {
  plaintext = new TextEncoder().encode(plaintext);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext,
  ));

  return { ciphertext: [...ciphertext], iv: [...iv], salt };
}

/**
 * @param {Omit<EncryptedMessage, "salt">} message
 * @param {Omit<DerivedKey, "salt">} key
 * @returns {EncryptedMessage}
 */
async function decrypt({ ciphertext, iv }, { key }) {
  return new TextDecoder().decode(new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Uint8Array.from(iv) },
    key,
    Uint8Array.from(ciphertext)
  )));
}
