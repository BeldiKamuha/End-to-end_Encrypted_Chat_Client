const { subtle } = require('crypto').webcrypto

const ecdsaTest = async function (message) {
  console.log('====================================================')
  console.log('Testing ECDSA on message:', message)
  console.log('----------------------------------------------------')

  console.time('ECDSA Key Generation Total Time')
  const ecdsaKey = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
  console.timeEnd('ECDSA Key Generation Total Time')

  console.time('ECDSA Signing Total Time')
  const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, ecdsaKey.privateKey, Buffer.from(message))
  console.timeEnd('ECDSA Signing Total Time')

  console.time('ECDSA Verify Total Time')
  const isVerified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, ecdsaKey.publicKey, signature, Buffer.from(message))
  console.timeEnd('ECDSA Verify Total Time')
  if (!isVerified) {
    throw new Error('ECDSA verify function failed')
  }

  console.log('ECDSA Signature Byte Length:', signature.byteLength)
  console.log('====================================================')
}

const rsaTest = async function (message) {
  console.log('====================================================')
  console.log('Testing RSA on message:', message)
  console.log('----------------------------------------------------')

  console.time('RSA Key Generation Total Time')
  const rsaKey = await subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  )
  console.timeEnd('RSA Key Generation Total Time')

  console.time('RSA Signing Total Time')
  const signature = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsaKey.privateKey, Buffer.from(message))
  console.timeEnd('RSA Signing Total Time')

  console.time('RSA Verify Total Time')
  const isVerified = await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, rsaKey.publicKey, signature, Buffer.from(message))
  console.timeEnd('RSA Verify Total Time')
  if (!isVerified) {
    throw new Error('RSA verify function failed')
  }

  console.log('RSA Signature Byte Length:', signature.byteLength)
  console.log('====================================================')
}

const main = async function () {
  const message = 'using cryptography correctly is important'
  await rsaTest(message)
  await ecdsaTest(message)
}

main()
