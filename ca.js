// ca.js
'use strict'

const fs = require('fs')
const { subtle } = require('node:crypto').webcrypto

let caPrivateKey = null
let caPublicKey = null

/**
 * Loads a CryptoKey from a JWK JSON file.
 * @param {string} filename - The filename of the JWK.
 * @param {boolean} isPrivate - Indicates if the key is private.
 * @returns {Promise<CryptoKey>}
 */
async function loadKey (filename, isPrivate) {
  const jwk = JSON.parse(fs.readFileSync(filename, 'utf8'))
  const keyUsages = isPrivate ? ['sign'] : ['verify']

  const key = await subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    keyUsages
  )
  return key
}

/**
 * Initializes and loads the CA keys.
 */
async function initializeCA () {
  if (!caPrivateKey || !caPublicKey) {
    caPrivateKey = await loadKey('ca_private.json', true)
    caPublicKey = await loadKey('ca_public.json', false)
  }
}

/**
 * Gets the CA Private Key. Only the server should use this.
 * @returns {Promise<CryptoKey>}
 */
async function getCAPrivateKey () {
  await initializeCA()
  return caPrivateKey
}

/**
 * Gets the CA Public Key. Both server and clients use this.
 * @returns {Promise<CryptoKey>}
 */
async function getCAPublicKey () {
  await initializeCA()
  return caPublicKey
}

module.exports = {
  getCAPrivateKey,
  getCAPublicKey
}
