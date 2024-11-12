// lib.js
'use strict'

const crypto = require('node:crypto')
const { subtle } = require('node:crypto').webcrypto

/// ////////////////////////////////////////////////////////////////////////////////
// Cryptographic Primitives
//
// All of the cryptographic functions you need for this assignment
// are contained within this library.
//
// The parameter and return types are designed to be as convenient as possible.
// The only conversion you will need in messenger.js will be when converting
// the result of decryptWithGCM (an ArrayBuffer) to a string.
//
// Any argument to a lib.js function should either be a string or a value
// returned by a lib.js function.
/// ////////////////////////////////////////////////////////////////////////////////

const govEncryptionDataStr = 'AES-GENERATION'

/**
 * Converts an ArrayBuffer to a string.
 * @param {ArrayBuffer} arr - The ArrayBuffer to convert.
 * @returns {string} - The resulting string.
 */
function bufferToString (arr) {
  // Converts from ArrayBuffer to string
  // Used to go from output of decryptWithGCM to string
  return Buffer.from(arr).toString()
}

/**
 * Generates a random IV (Initialization Vector).
 * @param {number} len - The length of the IV.
 * @returns {Buffer} - The generated IV.
 */
function genRandomSalt (len = 12) { // GCM standard IV size is 12 bytes
  // Used to generate IVs for AES encryption
  // Used in combination with encryptWithGCM and decryptWithGCM
  return crypto.randomBytes(len)
}

/**
 * Exports a CryptoKey to JWK format.
 * @param {CryptoKey} cryptoKey - The CryptoKey to export.
 * @returns {Promise<Object>} - The exported key in JWK format.
 */
async function cryptoKeyToJSON (cryptoKey) {
  // Used to and return CryptoKey in JSON format
  // Can console.log() the returned variable to see printed key in a readable format
  // This function can be helpful for debugging since console.log() on cryptoKey
  // directly will not show the key data
  const key = await subtle.exportKey('jwk', cryptoKey)
  return key
}

/**
 * Generates an ECDH key pair.
 * @returns {Promise<Object>} - An object containing the public and private keys.
 */
async function generateEG () {
  // returns a pair of ElGamal keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const keypair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey']
  )
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }
  return keypairObject
}

/**
 * Computes the Diffie-Hellman shared secret.
 * @param {CryptoKey} myPrivateKey - The ECDH private key.
 * @param {CryptoKey} theirPublicKey - The ECDH public key.
 * @returns {Promise<CryptoKey>} - The derived shared secret.
 */
async function computeDH (myPrivateKey, theirPublicKey) {
  // Computes Diffie-Hellman key exchange for an ECDH private key and ECDH public key
  // myPrivateKey should be pair.sec from generateEG output
  // theirPublicKey should be pair.pub from generateEG output
  // myPrivateKey and theirPublicKey should be from different calls to generateEG
  // Outputs shared secret result of DH exchange
  // Return type is CryptoKey with derivedKeyAlgorithm of HMAC
  return await subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify']
  )
}

/**
 * Verifies an ECDSA signature.
 * @param {CryptoKey} publicKey - The ECDSA public key.
 * @param {string} message - The message that was signed.
 * @param {ArrayBuffer|Buffer} signature - The signature to verify.
 * @returns {Promise<boolean>} - True if the signature is valid, else false.
 */
async function verifyWithECDSA (publicKey, message, signature) {
  // Ensure `signature` is in ArrayBuffer format
  const signatureBuffer = signature instanceof ArrayBuffer ? signature : Buffer.from(signature)

  // Encode the message properly
  const encodedMessage = new TextEncoder().encode(message)

  // Logging for debugging
  console.log('Verifying message:', message)
  console.log('Encoded message (Uint8Array):', encodedMessage)
  console.log('Signature (ArrayBuffer):', signatureBuffer)

  // Verify the signature with the ECDSA key
  return await subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    publicKey,
    signatureBuffer,
    encodedMessage
  )
}

/**
 * Derives an AES key using HMAC.
 * @param {CryptoKey} key - The input CryptoKey.
 * @param {string} data - The data to derive the key with.
 * @param {boolean} exportToArrayBuffer - Whether to export the key as ArrayBuffer.
 * @returns {Promise<CryptoKey|Buffer>} - The derived key.
 */
async function HMACtoAESKey (key, data, exportToArrayBuffer = false) {
  // Performs HMAC to derive a new key with derivedKeyAlgorithm AES
  // if exportToArrayBuffer is true, return key as ArrayBuffer. Otherwise, output CryptoKey
  // key is a CryptoKey
  // data is a string

  // First compute HMAC output
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, Buffer.from(data))

  // Then, re-import with derivedKeyAlgorithm AES-GCM
  const out = await subtle.importKey(
    'raw',
    hmacBuf,
    'AES-GCM',
    true,
    ['encrypt', 'decrypt']
  )

  // If exportToArrayBuffer is true, exportKey as ArrayBuffer
  if (exportToArrayBuffer) {
    return Buffer.from(await subtle.exportKey('raw', out))
  }

  // Otherwise, export as CryptoKey
  return out
}

/**
 * Derives an HMAC key using HMAC.
 * @param {CryptoKey} key - The input CryptoKey.
 * @param {string} data - The data to derive the key with.
 * @returns {Promise<CryptoKey>} - The derived HMAC key.
 */
async function HMACtoHMACKey (key, data) {
  // Performs HMAC to derive a new key with derivedKeyAlgorithm HMAC
  // key is a CryptoKey
  // data is a string

  // First compute HMAC output
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, Buffer.from(data))
  // Then, re-import with derivedKeyAlgorithm HMAC
  return await subtle.importKey(
    'raw',
    hmacBuf,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )
}

/**
 * Performs HKDF key derivation.
 * @param {CryptoKey} inputKey - The input CryptoKey.
 * @param {CryptoKey} salt - The salt CryptoKey.
 * @param {string} infoStr - The info string.
 * @returns {Promise<Array<CryptoKey, CryptoKey>>} - The derived keys.
 */
async function HKDF (inputKey, salt, infoStr) {
  if (!inputKey || !salt || !infoStr) {
    throw new TypeError('HKDF requires valid inputKey, salt, and infoStr.')
  }

  // Extract the key material from inputKey
  const inputKeyMaterial = await subtle.exportKey('raw', inputKey)

  // Extract the key material from salt
  const saltKeyMaterial = await subtle.exportKey('raw', salt)

  // Import the input key material for HKDF
  const inputKeyHKDF = await subtle.importKey(
    'raw',
    inputKeyMaterial,
    'HKDF',
    false,
    ['deriveKey']
  )

  // Perform key derivation
  const hkdfParams = {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: saltKeyMaterial,
    info: Buffer.from(infoStr)
  }

  const hkdfOut1 = await subtle.deriveKey(
    hkdfParams,
    inputKeyHKDF,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )

  // Optionally derive a second key if needed
  // For now, let's just return hkdfOut1 twice
  const hkdfOut2 = hkdfOut1

  return [hkdfOut1, hkdfOut2]
}

/**
 * Encrypts data using AES-GCM.
 * @param {CryptoKey} key - The AES-GCM CryptoKey.
 * @param {string|Buffer} plaintext - The data to encrypt.
 * @param {Buffer} iv - The Initialization Vector.
 * @param {string} authenticatedData - The authenticated data.
 * @returns {Promise<ArrayBuffer>} - The ciphertext.
 */
async function encryptWithGCM (key, plaintext, iv, authenticatedData = '') {
  // Encrypts using the GCM mode.
  // key is a cryptoKey with derivedKeyAlgorithm AES-GCM
  // plaintext is a string or Buffer of the data you want to encrypt.
  // iv is used for encryption and must be unique for every use of the same key
  // use the genRandomSalt() function to generate iv and store it in the header for decryption
  // authenticatedData is an optional argument string
  // returns ciphertext as ArrayBuffer
  // The authenticatedData is not encrypted into the ciphertext, but it will
  // not be possible to decrypt the ciphertext unless it is passed.
  // (If there is no authenticatedData passed when encrypting, then it is not
  // necessary while decrypting.)
  return await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: Buffer.from(authenticatedData) },
    key,
    Buffer.from(plaintext)
  )
}

/**
 * Decrypts data using AES-GCM.
 * @param {CryptoKey} key - The AES-GCM CryptoKey.
 * @param {ArrayBuffer} ciphertext - The data to decrypt.
 * @param {Buffer} iv - The Initialization Vector.
 * @param {string} authenticatedData - The authenticated data.
 * @returns {Promise<ArrayBuffer>} - The plaintext.
 */
async function decryptWithGCM (key, ciphertext, iv, authenticatedData = '') {
  // Decrypts using the GCM mode.
  // key is a cryptoKey with derivedKeyAlgorithm AES-GCM
  // ciphertext is an ArrayBuffer
  // iv used during encryption is necessary to decrypt
  // iv should have been passed through the message header
  // authenticatedData is optional, but if it was passed when
  // encrypting, it has to be passed now, otherwise the decrypt will fail.
  // returns plaintext as ArrayBuffer if successful
  // throws exception if decryption fails (key incorrect, tampering detected, etc)
  return await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: Buffer.from(authenticatedData) },
    key,
    ciphertext
  )
}

/// /////////////////////////////////////////////////////////////////////////////
// Additional ECDSA functions for test-messenger.js
//
// YOU DO NOT NEED THESE FUNCTIONS FOR MESSENGER.JS,
// but they may be helpful if you want to write additional
// tests for certificate signatures in test-messenger.js.
/// /////////////////////////////////////////////////////////////////////////////

/**
 * Generates an ECDSA key pair.
 * @returns {Promise<Object>} - An object containing the public and private keys.
 */
async function generateECDSA () {
  // returns a pair of Digital Signature Algorithm keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const keypair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify']
  )
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }
  return keypairObject
}

/**
 * Signs a message using ECDSA.
 * @param {CryptoKey} privateKey - The ECDSA private key.
 * @param {string} message - The message to sign.
 * @returns {Promise<ArrayBuffer>} - The signature.
 */
async function signWithECDSA (privateKey, message) {
  // returns signature of message with privateKey
  // privateKey should be pair.sec from generateECDSA
  // message is a string
  // signature returned as an ArrayBuffer
  return await subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    privateKey,
    Buffer.from(message)
  )
}

module.exports = {
  govEncryptionDataStr,
  bufferToString,
  genRandomSalt,
  cryptoKeyToJSON,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA
}
