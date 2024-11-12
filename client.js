// client.js
'use strict'

const net = require('net')
const readline = require('readline')
const { MessengerClient } = require('./messenger.js')
const { getCAPublicKey } = require('./ca.js')
const { generateEG } = require('./lib.js');

(async () => {
  try {
    // Get the CA public key
    const caPublicKey = await getCAPublicKey()

    // Initialize MessengerClient with shared CA public key
    const govKeyPair = await generateEG()
    const client = new MessengerClient(caPublicKey, govKeyPair.pub)

    // Generate your certificate
    const username = process.argv[2] // Get username from command-line argument
    if (!username) {
      console.error('Please provide a username as a command-line argument.')
      process.exit(1)
    }
    const certificate = await client.generateCertificate(username)
    const certString = JSON.stringify(certificate)

    // Connect to the server
    const clientSocket = net.connect(3000, 'localhost', () => {
      clientSocket.setEncoding('utf8')
      // Send the username and certificate to the server
      clientSocket.write(`${username}||${certString}\n`)
    })

    // Create readline interface for incoming data
    const rl = readline.createInterface({
      input: clientSocket,
      crlfDelay: Infinity
    })

    // Store certificates of other users
    const userCerts = {}

    // Handle incoming lines
    rl.on('line', async (line) => {
      line = line.trim()
      if (!line) return // Skip empty lines

      console.log('Received data:', line) // Debugging line to print the received data

      // Check if the line contains a certificate message or a regular message
      if (line.startsWith('CERT||')) {
        // Incoming certificate message format: "CERT||username||certificate||signature"
        const parts = line.split('||')
        if (parts.length !== 4) {
          console.error(`Received malformed certificate data: ${line}`)
          return
        }

        const [, certUser, cert, certSignature] = parts

        if (!cert || !certSignature) {
          console.error(`Received incomplete certificate data from ${certUser}`)
          return
        }

        try {
          const certParsed = JSON.parse(cert)
          const decodedSignature = Buffer.from(certSignature, 'base64') // Decode the base64 signature

          // Import certificate and store it
          await client.receiveCertificate(certParsed, decodedSignature) // Use the decoded signature
          userCerts[certUser] = certParsed
          console.log(`Received and verified certificate for ${certUser}`)
        } catch (error) {
          console.error(`Error parsing certificate data for ${certUser}:`, error.message)
        }

        return
      }

      // Handle regular messages
      try {
        // Split only on the first colon to prevent issues with colons in the message payload
        const firstColonIndex = line.indexOf(':')
        if (firstColonIndex === -1) {
          console.error('Received malformed message (no colon found):', line)
          return
        }

        const from = line.substring(0, firstColonIndex)
        const message = line.substring(firstColonIndex + 1)

        // Parse the JSON payload
        const parsedMessage = JSON.parse(message)
        if (!Array.isArray(parsedMessage) || parsedMessage.length !== 2) {
          throw new Error('Malformed message payload')
        }

        const [header, ciphertextBase64] = parsedMessage
        const ciphertext = Buffer.from(ciphertextBase64, 'base64')

        const plaintext = await client.receiveMessage(from, [header, ciphertext])
        console.log(`${from}: ${plaintext}`)
      } catch (error) {
        console.error('Failed to process incoming message:', error.message)
      }
    })

    // Read input from the console
    const rlInput = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    })

    rlInput.on('line', async (line) => {
      const firstColonIndex = line.indexOf(':')
      if (firstColonIndex === -1) {
        console.log('Please use the format recipient:message')
        return
      }

      const recipient = line.substring(0, firstColonIndex).trim()
      const message = line.substring(firstColonIndex + 1).trim()

      if (!recipient || !message) {
        console.log('Please use the format recipient:message')
        return
      }
      if (!userCerts[recipient]) {
        console.log(`No certificate for ${recipient}`)
        return
      }

      try {
        // Encrypt the message
        const encryptedMessage = await client.sendMessage(recipient, message)
        const payload = JSON.stringify([
          encryptedMessage[0],
          Buffer.from(encryptedMessage[1]).toString('base64')
        ])
        clientSocket.write(`${recipient}:${payload}\n`) // Ensure newline
      } catch (error) {
        console.error('Error sending message:', error.message)
      }
    })

    // Handle socket errors
    clientSocket.on('error', (err) => {
      console.error('Socket error:', err.message)
    })

    // Handle socket closure
    clientSocket.on('close', () => {
      console.log('Disconnected from server.')
      rl.close()
      rlInput.close()
      process.exit(0)
    })
  } catch (error) {
    console.error('Error initializing client:', error.message)
    process.exit(1)
  }
})()
