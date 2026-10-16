import { ed25519 } from '@noble/curves/ed25519.js'

const encoder = new TextEncoder()
const DEVICE_LINK_DOMAIN = 'gabber:mls-device-link:v1'
const CONTACT_DOMAIN = 'gabber:contact-card:v1'
const INVITATION_DOMAIN = 'gabber:mls-invitation:v1'

function hexToBytes(hex) {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(hex)) {
    throw new Error('Invalid account signing key')
  }
  return Uint8Array.from(hex.match(/.{2}/g), byte => Number.parseInt(byte, 16))
}

function accountSigningKey(identity) {
  if (!/^[\w.-]{1,32}$/u.test(identity.handle)) {
    throw new Error('Handle must use 1–32 letters, digits, dots, dashes, or underscores')
  }
  const privateKey = hexToBytes(identity.privateKeySign)
  const publicKey = hexToBytes(identity.publicKeySign)
  if (
    privateKey.length !== 32 ||
    publicKey.length !== 32 ||
    !ed25519.getPublicKey(privateKey).every((byte, index) => byte === publicKey[index])
  ) {
    throw new Error('Account signing key does not match the saved public identity')
  }
  return privateKey
}

function bytesToBase64Url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function base64UrlToBytes(value, maxBytes = 128 * 1024) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error('Invalid base64url data')
  }
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '='))
  if (binary.length > maxBytes) throw new Error('Bundle data is too large')
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
  if (bytesToBase64Url(bytes) !== value) throw new Error('Invalid base64url data')
  return bytes
}

function signatureBytes(value) {
  const bytes = base64UrlToBytes(value, 64)
  if (bytes.length !== 64) throw new Error('Invalid signature')
  return bytes
}

function parseBundle(value, type, expectedFields) {
  let bundle
  try {
    bundle = typeof value === 'string' ? JSON.parse(value) : value
  } catch {
    throw new Error('Bundle must be valid JSON')
  }
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new Error('Bundle must be a JSON object')
  }
  const keys = Object.keys(bundle).sort()
  if (keys.join(',') !== [...expectedFields].sort().join(',')) {
    throw new Error(`Invalid ${type} bundle fields`)
  }
  if (bundle.version !== 1 || bundle.type !== type) throw new Error(`Unsupported ${type} bundle`)
  if (typeof bundle.handle !== 'string' || !/^[\w.-]{1,32}$/u.test(bundle.handle)) {
    throw new Error('Invalid handle in bundle')
  }
  if (typeof bundle.accountPublicKey !== 'string' || !/^[0-9a-f]{64}$/iu.test(bundle.accountPublicKey)) {
    throw new Error('Invalid account identity key')
  }
  if (typeof bundle.devicePublicKey !== 'string') throw new Error('Invalid device signing key')
  if (base64UrlToBytes(bundle.devicePublicKey, 64).length !== 32) {
    throw new Error('Invalid device signing key')
  }
  if (typeof bundle.deviceBindingSignature !== 'string') throw new Error('Missing device identity signature')
  return bundle
}

function verifyDeviceBinding(bundle) {
  const publicKey = hexToBytes(bundle.accountPublicKey)
  const message = encoder.encode([
    DEVICE_LINK_DOMAIN,
    bundle.handle,
    bundle.devicePublicKey,
  ].join('\n'))
  if (!ed25519.verify(signatureBytes(bundle.deviceBindingSignature), message, publicKey)) {
    throw new Error('MLS device key is not signed by this Gabber identity')
  }
}

function contactPayload(bundle) {
  return JSON.stringify([
    CONTACT_DOMAIN,
    bundle.handle,
    bundle.accountPublicKey,
    bundle.devicePublicKey,
    bundle.deviceBindingSignature,
    bundle.keyPackage,
  ])
}

function invitationPayload(bundle) {
  return JSON.stringify([
    INVITATION_DOMAIN,
    bundle.handle,
    bundle.accountPublicKey,
    bundle.devicePublicKey,
    bundle.deviceBindingSignature,
    bundle.roomId,
    bundle.welcome,
  ])
}

export function createContactBundle(identity, mlsDevicePublicKey, keyPackage) {
  const handle = identity.handle
  const accountPrivateKey = accountSigningKey(identity)
  if (mlsDevicePublicKey.length !== 32 || keyPackage.length === 0) {
    throw new Error('Invalid MLS device key or KeyPackage')
  }
  const base = {
    version: 1,
    type: 'gabber-contact',
    handle,
    accountPublicKey: identity.publicKeySign,
    devicePublicKey: bytesToBase64Url(mlsDevicePublicKey),
    deviceBindingSignature: '',
    keyPackage: bytesToBase64Url(keyPackage),
    signature: '',
  }
  base.deviceBindingSignature = bytesToBase64Url(ed25519.sign(
    encoder.encode([DEVICE_LINK_DOMAIN, handle, base.devicePublicKey].join('\n')),
    accountPrivateKey,
  ))
  base.signature = bytesToBase64Url(ed25519.sign(encoder.encode(contactPayload(base)), accountPrivateKey))
  return JSON.stringify(base)
}

export function verifyContactBundle(value) {
  const bundle = parseBundle(value, 'gabber-contact', [
    'version',
    'type',
    'handle',
    'accountPublicKey',
    'devicePublicKey',
    'deviceBindingSignature',
    'keyPackage',
    'signature',
  ])
  verifyDeviceBinding(bundle)
  const keyPackage = base64UrlToBytes(bundle.keyPackage)
  if (keyPackage.length === 0) throw new Error('Contact has an empty MLS KeyPackage')
  if (!ed25519.verify(
    signatureBytes(bundle.signature),
    encoder.encode(contactPayload(bundle)),
    hexToBytes(bundle.accountPublicKey),
  )) {
    throw new Error('Contact card signature is invalid')
  }
  return {
    handle: bundle.handle,
    accountPublicKey: bundle.accountPublicKey,
    devicePublicKey: base64UrlToBytes(bundle.devicePublicKey, 64),
    keyPackage,
  }
}

export function createInvitationBundle(identity, mlsDevicePublicKey, roomId, welcome) {
  const accountPrivateKey = accountSigningKey(identity)
  if (mlsDevicePublicKey.length !== 32 || !/^[A-Za-z0-9_-]{22,64}$/u.test(roomId) || welcome.length === 0) {
    throw new Error('Invalid MLS device key, room ID, or Welcome')
  }
  const base = {
    version: 1,
    type: 'gabber-invitation',
    handle: identity.handle,
    accountPublicKey: identity.publicKeySign,
    devicePublicKey: bytesToBase64Url(mlsDevicePublicKey),
    deviceBindingSignature: '',
    roomId,
    welcome: bytesToBase64Url(welcome),
    signature: '',
  }
  base.deviceBindingSignature = bytesToBase64Url(ed25519.sign(
    encoder.encode([DEVICE_LINK_DOMAIN, base.handle, base.devicePublicKey].join('\n')),
    accountPrivateKey,
  ))
  base.signature = bytesToBase64Url(ed25519.sign(encoder.encode(invitationPayload(base)), accountPrivateKey))
  return JSON.stringify(base)
}

export function verifyInvitationBundle(value) {
  const bundle = parseBundle(value, 'gabber-invitation', [
    'version',
    'type',
    'handle',
    'accountPublicKey',
    'devicePublicKey',
    'deviceBindingSignature',
    'roomId',
    'welcome',
    'signature',
  ])
  verifyDeviceBinding(bundle)
  if (!/^[A-Za-z0-9_-]{22,64}$/u.test(bundle.roomId)) throw new Error('Invalid relay room ID')
  const welcome = base64UrlToBytes(bundle.welcome)
  if (welcome.length === 0) throw new Error('Invitation has an empty MLS Welcome')
  if (!ed25519.verify(
    signatureBytes(bundle.signature),
    encoder.encode(invitationPayload(bundle)),
    hexToBytes(bundle.accountPublicKey),
  )) {
    throw new Error('Invitation signature is invalid')
  }
  return {
    handle: bundle.handle,
    accountPublicKey: bundle.accountPublicKey,
    devicePublicKey: base64UrlToBytes(bundle.devicePublicKey, 64),
    roomId: bundle.roomId,
    welcome,
  }
}
