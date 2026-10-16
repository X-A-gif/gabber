import { ed25519, x25519 } from '@noble/curves/ed25519.js'

// Simple helper to convert Uint8Array to hex
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

function bytesToBase64Url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function recoveryChecksum(bytes) {
  let checksum = 0xffffffff
  for (const byte of bytes) {
    checksum ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      checksum = (checksum >>> 1) ^ (0xedb88320 & -(checksum & 1))
    }
  }
  checksum = (checksum ^ 0xffffffff) >>> 0
  return Uint8Array.of(checksum >>> 24, checksum >>> 16, checksum >>> 8, checksum)
}

function recoveryKeyToBytes(recoveryKey) {
  if (typeof recoveryKey !== 'string' || !/^[A-Za-z0-9_-]{136}$/u.test(recoveryKey)) {
    throw new Error('Recovery key is invalid')
  }
  const binary = atob(recoveryKey.replaceAll('-', '+').replaceAll('_', '/'))
  if (binary.length !== 102) throw new Error('Recovery key is invalid')
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
  if (bytesToBase64Url(bytes) !== recoveryKey) throw new Error('Recovery key is invalid')
  const payload = bytes.slice(0, 98)
  const expectedChecksum = recoveryChecksum(payload)
  if (!expectedChecksum.every((byte, index) => byte === bytes[index + 98])) {
    throw new Error('Recovery key checksum is invalid; check for typing errors')
  }
  return payload
}

function validateHandle(handle) {
  if (typeof handle !== 'string' || !/^[\w.-]{1,32}$/u.test(handle)) {
    throw new Error('Handle must use 1–32 letters, digits, dots, dashes, or underscores')
  }
}

export async function generateIdentity() {
  const signKey = ed25519.keygen()
  const encKey = x25519.keygen()

  return {
    privateKeySign: bytesToHex(signKey.secretKey),
    publicKeySign: bytesToHex(signKey.publicKey),
    privateKeyEnc: bytesToHex(encKey.secretKey),
    publicKeyEnc: bytesToHex(encKey.publicKey),
    createdAt: new Date().toISOString()
  }
}

export async function generateRecoveryIdentity(handle) {
  validateHandle(handle)
  const identity = { handle, ...await generateIdentity() }
  const recoveryKey = createRecoveryKey(identity)
  return { identity, recoveryKey }
}

export function createRecoveryKey(identity) {
  if (
    typeof identity?.handle !== 'string' ||
    !/^[\w.-]{1,32}$/u.test(identity.handle) ||
    !/^[0-9a-f]{64}$/iu.test(identity?.privateKeySign) ||
    !/^[0-9a-f]{64}$/iu.test(identity?.privateKeyEnc) ||
    !/^[0-9a-f]{64}$/iu.test(identity?.publicKeySign) ||
    !/^[0-9a-f]{64}$/iu.test(identity?.publicKeyEnc)
  ) {
    throw new Error('Identity keys are invalid')
  }
  const handleBytes = Uint8Array.from(identity.handle, character => character.charCodeAt(0))
  const signingSecret = Uint8Array.from(identity.privateKeySign.match(/.{2}/gu), byte => Number.parseInt(byte, 16))
  const encryptionSecret = Uint8Array.from(identity.privateKeyEnc.match(/.{2}/gu), byte => Number.parseInt(byte, 16))
  if (
    !ed25519.getPublicKey(signingSecret).every((byte, index) => byte === Number.parseInt(identity.publicKeySign.slice(index * 2, index * 2 + 2), 16)) ||
    !x25519.getPublicKey(encryptionSecret).every((byte, index) => byte === Number.parseInt(identity.publicKeyEnc.slice(index * 2, index * 2 + 2), 16))
  ) {
    throw new Error('Identity public keys do not match their private keys')
  }
  const payload = new Uint8Array(98)
  payload[0] = 1
  payload[1] = handleBytes.length
  payload.set(handleBytes, 2)
  payload.set(signingSecret, 34)
  payload.set(encryptionSecret, 66)
  return bytesToBase64Url(Uint8Array.from([...payload, ...recoveryChecksum(payload)]))
}

export function recoverIdentity(recoveryKey) {
  const payload = recoveryKeyToBytes(recoveryKey)
  const handleLength = payload[1]
  if (
    payload[0] !== 1 ||
    handleLength < 1 ||
    handleLength > 32 ||
    payload.slice(2 + handleLength, 34).some(byte => byte !== 0)
  ) {
    throw new Error('Recovery key contents are invalid')
  }
  const handle = String.fromCharCode(...payload.slice(2, 2 + handleLength))
  validateHandle(handle)
  const privateKeySign = payload.slice(34, 66)
  const privateKeyEnc = payload.slice(66, 98)
  return {
    handle,
    privateKeySign: bytesToHex(privateKeySign),
    publicKeySign: bytesToHex(ed25519.getPublicKey(privateKeySign)),
    privateKeyEnc: bytesToHex(privateKeyEnc),
    publicKeyEnc: bytesToHex(x25519.getPublicKey(privateKeyEnc)),
    createdAt: new Date().toISOString(),
  }
}

export function fingerprint(hexKey, length = 16) {
  return hexKey.slice(0, length).match(/.{1,4}/g)?.join(' ') || hexKey
}