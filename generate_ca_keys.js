// generate_ca_keys.js
'use strict'

const fs = require('fs')
const { generateECDSA, cryptoKeyToJSON } = require('./lib.js');

(async () => {
  // Generate CA ECDSA Key Pair
  const caKeyPair = await generateECDSA()

  // Export the CA Public Key to JWK format
  const caPublicJWK = await cryptoKeyToJSON(caKeyPair.pub)

  // Export the CA Private Key to JWK format
  const caPrivateJWK = await cryptoKeyToJSON(caKeyPair.sec)

  // Save the CA Public Key
  fs.writeFileSync('ca_public.json', JSON.stringify(caPublicJWK, null, 2))
  console.log('CA Public Key saved to ca_public.json')

  // Save the CA Private Key
  fs.writeFileSync('ca_private.json', JSON.stringify(caPrivateJWK, null, 2))
  console.log('CA Private Key saved to ca_private.json')
})()
