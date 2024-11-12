// messenger.js
'use strict'

/** ******* Imports ********/
const {
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoHMACKey, // async
  HMACtoAESKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM, // async,
  govEncryptionDataStr
} = require('./lib')

const { subtle } = require('node:crypto').webcrypto
const crypto = require('node:crypto')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {}
    this.certs = {}
    this.EGKeyPair = {}
    this.receivedMessages = new Set()
  }

  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()

    // Export public key in raw format, then encode it as base64
    const publicKeyRaw = await subtle.exportKey('raw', this.EGKeyPair.pub)
    const publicKey = Buffer.from(publicKeyRaw).toString('base64')
    console.log(`Generated publicKey for ${username}:`, publicKey)

    // Create the certificate with a base64 public key
    const certificate = { username, publicKey }
    return certificate
  }

  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    console.log(`Receiving certificate for ${certificate.username}:`, certificate)

    // Decode the base64 public key
    const publicKeyBuffer = Buffer.from(certificate.publicKey, 'base64')
    const publicKey = await subtle.importKey(
      'raw',
      publicKeyBuffer,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )

    // Re-create certificate with `CryptoKey` format
    const certWithCryptoKey = { username: certificate.username, publicKey }

    // Verify the certificate using the CA public key and signature
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isValid) throw new Error('Certificate verification failed!')

    this.certs[certificate.username] = certWithCryptoKey
    console.log(`Certificate verified and stored for ${certificate.username}`)
  }

  async sendMessage (name, plaintext) {
    if (!this.certs[name]) {
      throw new Error("Recipient's certificate not found!")
    }

    const recipientCert = this.certs[name]
    const recipientPublicKey = recipientCert.publicKey

    const dhKeyPair = await generateEG()
    const sharedSecret = await computeDH(dhKeyPair.sec, recipientPublicKey)

    const salt = await HMACtoHMACKey(sharedSecret, 'salt')
    const [derivedKey1] = await HKDF(sharedSecret, salt, 'ratchet-str')
    const iv = genRandomSalt()

    const govEphemeralKeyPair = await generateEG()
    const govSharedSecret = await computeDH(govEphemeralKeyPair.sec, this.govPublicKey)
    const govSymmetricKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const cGov = Buffer.from(await encryptWithGCM(govSymmetricKey, Buffer.from(await subtle.exportKey('raw', derivedKey1)), ivGov))

    const header = {
      dhPublicKey: Buffer.from(await subtle.exportKey('raw', dhKeyPair.pub)).toString('base64'),
      iv: iv.toString('base64'),
      vGov: Buffer.from(await subtle.exportKey('raw', govEphemeralKeyPair.pub)).toString('base64'),
      ivGov: ivGov.toString('base64'),
      cGov: cGov.toString('base64')
    }

    const ciphertext = Buffer.from(await encryptWithGCM(derivedKey1, plaintext, iv, JSON.stringify(header)))

    return [header, ciphertext]
  }

  async receiveMessage (name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error("Sender's certificate not found!")
    }

    // Compute a unique message ID for replay attack prevention
    const messageId = crypto.createHash('sha256')
      .update(JSON.stringify(header))
      .update(Buffer.from(ciphertext))
      .digest('hex')

    if (this.receivedMessages.has(messageId)) {
      throw new Error('Replay attack detected: message has already been received.')
    }

    // Store the message ID to prevent future replays
    this.receivedMessages.add(messageId)

    const senderDhPublicKeyBuffer = Buffer.from(header.dhPublicKey, 'base64')
    const senderDhPublicKey = await subtle.importKey(
      'raw',
      senderDhPublicKeyBuffer,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )

    // Compute shared secret using the own private key and sender's DH public key
    const sharedSecret = await computeDH(this.EGKeyPair.sec, senderDhPublicKey)

    // Generate a salt for HKDF
    const salt = await HMACtoHMACKey(sharedSecret, 'salt')

    // Derive decryption keys
    const [recvKey] = await HKDF(sharedSecret, salt, 'ratchet-str')

    // Decode IV from base64
    const iv = Buffer.from(header.iv, 'base64')

    // Decode authenticated data (header)
    const authenticatedData = JSON.stringify(header)

    // Convert ciphertext Buffer to ArrayBuffer
    const ciphertextArrayBuffer = ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength)

    // Decrypt the message using the derived key and including the header as authenticated data
    const plaintextBuffer = await decryptWithGCM(recvKey, ciphertextArrayBuffer, iv, authenticatedData)
    return bufferToString(plaintextBuffer)
  }
}

module.exports = {
  MessengerClient
}
