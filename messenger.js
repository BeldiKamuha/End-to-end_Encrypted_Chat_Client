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
  decryptWithGCM, // async
  govEncryptionDataStr
} = require('./lib')

// Import subtle for cryptographic operations
const { subtle } = require('node:crypto').webcrypto

// Import the crypto module for hashing
const crypto = require('node:crypto')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // Active connections
    this.certs = {} // Certificates of other users
    this.EGKeyPair = {} // ElGamal key pair
    this.receivedMessages = new Set() // Initialize the set for received message IDs
  }

  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()
    const publicKey = this.EGKeyPair.pub

    if (!publicKey) throw new Error('Public key generation failed.')

    // Create certificate containing username and public key
    const certificate = { username, publicKey }
    return certificate
  }

  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)

    if (!isValid) throw new Error('Certificate verification failed!')

    // Store the valid certificate
    this.certs[certificate.username] = certificate
  }

  async sendMessage (name, plaintext) {
    if (!this.certs[name]) {
      throw new Error("Recipient's certificate not found!")
    }

    const recipientCert = this.certs[name]
    const recipientPublicKey = recipientCert.publicKey

    // Generate DH key pair and compute shared secret with recipient
    const dhKeyPair = await generateEG()
    const sharedSecret = await computeDH(dhKeyPair.sec, recipientPublicKey)

    // Generate a salt for HKDF
    const salt = await HMACtoHMACKey(sharedSecret, 'salt')

    // Derive encryption keys using HKDF
    const [, sendKey] = await HKDF(sharedSecret, salt, 'ratchet-str')

    // Export sendKey to raw format
    const sendKeyRaw = await subtle.exportKey('raw', sendKey)

    // Generate 'iv' for message encryption
    const iv = genRandomSalt() // Define 'iv' before using it

    // *** Government Backdoor Implementation ***

    // 1. Generate an ephemeral ECDH key pair for the government
    const govEphemeralKeyPair = await generateEG()

    // 2. Compute shared secret with government's public key
    const govSharedSecret = await computeDH(govEphemeralKeyPair.sec, this.govPublicKey)

    // 3. Derive symmetric key from shared secret
    const govSymmetricKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr)

    // 4. Encrypt the message key for the government
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govSymmetricKey, sendKeyRaw, ivGov)

    // Create message header including the government fields
    const header = {
      dhPublicKey: dhKeyPair.pub,
      iv,
      vGov: govEphemeralKeyPair.pub,
      ivGov,
      cGov
    }

    // Now, include the header as authenticatedData when encrypting the message
    const ciphertext = await encryptWithGCM(sendKey, plaintext, iv, JSON.stringify(header))

    return [header, ciphertext]
  }

  async receiveMessage (name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error("Sender's certificate not found!")
    }

    // Compute a hash of the header and ciphertext to create a unique message ID
    const messageId = crypto.createHash('sha256')
      .update(JSON.stringify(header))
      .update(Buffer.from(ciphertext))
      .digest('hex')

    // Check if the message has already been processed
    if (this.receivedMessages.has(messageId)) {
      throw new Error('Replay attack detected: message has already been received.')
    }

    // Store the message ID to prevent future replays
    this.receivedMessages.add(messageId)

    const senderDhPublicKey = header.dhPublicKey

    // Compute shared secret using own private key and sender's DH public key
    const sharedSecret = await computeDH(this.EGKeyPair.sec, senderDhPublicKey)

    // Generate a salt for HKDF
    const salt = await HMACtoHMACKey(sharedSecret, 'salt')

    // Derive decryption keys
    const [, recvKey] = await HKDF(sharedSecret, salt, 'ratchet-str')

    // Decrypt the message, including the header as authenticatedData
    const plaintextBuffer = await decryptWithGCM(recvKey, ciphertext, header.iv, JSON.stringify(header))
    return bufferToString(plaintextBuffer)
  }
}

module.exports = {
  MessengerClient
}
