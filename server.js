// server.js
'use strict'

const net = require('net')
const readline = require('readline')
const { getCAPrivateKey } = require('./ca.js')
const { signWithECDSA } = require('./lib.js')

const clients = new Map(); // Map to store client sockets and their info

(async () => {
  const caPrivateKey = await getCAPrivateKey() // Get the CA's private key

  const server = net.createServer((socket) => {
    socket.setEncoding('utf8')
    let clientUsername = null

    // Create a readline interface for each socket
    const rl = readline.createInterface({
      input: socket,
      crlfDelay: Infinity
    })

    rl.on('line', async (line) => {
      line = line.trim()
      if (!line) return // Skip empty lines

      // Initial connection data: username||certificate
      if (!clientUsername) {
        const parts = line.split('||')
        if (parts.length !== 2) {
          console.error('Malformed initial connection data:', line)
          socket.write('ERROR||Malformed initial connection data\n')
          return
        }

        const [username, certString] = parts
        clientUsername = username

        // Sign the certificate with the CA private key
        const signature = await signWithECDSA(caPrivateKey, certString)
        const signatureBase64 = Buffer.from(signature).toString('base64')

        // Store the client information
        clients.set(username, { socket, certString, signatureBase64 })

        // Broadcast the certificate and signature to all other clients
        for (const [otherUsername, clientInfo] of clients.entries()) {
          if (otherUsername !== username) {
            // Send the new client's certificate to existing clients
            clientInfo.socket.write(`CERT||${username}||${certString}||${signatureBase64}\n`)

            // Send existing clients' certificates to the new client
            socket.write(`CERT||${otherUsername}||${clientInfo.certString}||${clientInfo.signatureBase64}\n`)
          }
        }

        console.log(`${username} connected.`)
      } else {
        // Forward messages to the intended recipient
        const firstColonIndex = line.indexOf(':')
        if (firstColonIndex === -1) {
          console.error('Received malformed message (no colon found):', line)
          socket.write('ERROR||Malformed message format\n')
          return
        }

        const recipient = line.substring(0, firstColonIndex)
        const message = line.substring(firstColonIndex + 1)

        if (clients.has(recipient)) {
          // Forward the message to the recipient
          clients.get(recipient).socket.write(`${clientUsername}:${message}\n`)
          console.log(`Forwarded message from ${clientUsername} to ${recipient}`)
        } else {
          console.error(`Recipient ${recipient} not found.`)
          socket.write(`ERROR||Recipient ${recipient} not found\n`)
        }
      }
    })

    socket.on('end', () => {
      if (clientUsername) {
        clients.delete(clientUsername)
        console.log(`${clientUsername} disconnected.`)
      }
    })

    socket.on('error', (err) => {
      console.error(`Error with client ${clientUsername}:`, err.message)
    })
  })

  server.listen(3000, () => {
    console.log('Server listening on port 3000')
  })
})()
