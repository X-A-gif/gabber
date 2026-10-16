import { scrypt as scryptCallback, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto'
import { promisify } from 'node:util'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'

const scrypt = promisify(scryptCallback)
const VAULT_FORMAT = 'gabber-identity-vault'
const FORMAT_VERSION = 1
const KDF_PARAMETERS = { N: 32768, r: 8, p: 1 }
const KEY_BYTES = 32
const SALT_BYTES = 16
const NONCE_BYTES = 12
const TAG_BYTES = 16
const MAX_ENVELOPE_BYTES = 64 * 1024
const CHAT_ARCHIVE_FORMAT = 'gabber-chat-archive'
const CHAT_ARCHIVE_VERSION = 1
const MAX_CHAT_ARCHIVE_BYTES = 44 * 1024 * 1024
const MAX_CHAT_ENVELOPE_BYTES = 64 * 1024 * 1024
const encoder = new TextEncoder()
const VAULT_AAD = encoder.encode(`${VAULT_FORMAT}:v${FORMAT_VERSION}`)
const CHAT_ARCHIVE_AAD = encoder.encode(`${CHAT_ARCHIVE_FORMAT}:v${CHAT_ARCHIVE_VERSION}`)

function bytesToBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

function base64UrlToBytes(value, expectedBytes, label, maxBytes = 128 * 1024) {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    Buffer.from(value, 'base64url').toString('base64url') !== value
  ) {
    throw new Error(`Invalid ${label}`)
  }
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length > maxBytes) throw new Error(`${label} exceeds the size limit`)
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) throw new Error(`Invalid ${label}`)
  return bytes
}

function validatePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12 || Buffer.byteLength(passphrase, 'utf8') > 1024) {
    throw new Error('Passphrase must be at least 12 characters and no more than 1024 bytes')
  }
}

export function validateIdentity(identity) {
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('Identity data is invalid')
  }
  if (typeof identity.handle !== 'string' || !/^[\w.-]{1,32}$/u.test(identity.handle)) {
    throw new Error('Identity handle is invalid')
  }
  const keyFields = ['privateKeySign', 'publicKeySign', 'privateKeyEnc', 'publicKeyEnc']
  for (const field of keyFields) {
    if (typeof identity[field] !== 'string' || !/^[0-9a-f]{64}$/iu.test(identity[field])) {
      throw new Error(`Identity ${field} is invalid`)
    }
  }
  const privateSigningKey = Buffer.from(identity.privateKeySign, 'hex')
  const publicSigningKey = Buffer.from(identity.publicKeySign, 'hex')
  const privateEncryptionKey = Buffer.from(identity.privateKeyEnc, 'hex')
  const publicEncryptionKey = Buffer.from(identity.publicKeyEnc, 'hex')
  if (
    !Buffer.from(ed25519.getPublicKey(privateSigningKey)).equals(publicSigningKey) ||
    !Buffer.from(x25519.getPublicKey(privateEncryptionKey)).equals(publicEncryptionKey)
  ) {
    throw new Error('Identity public keys do not match their private keys')
  }
  if (
    typeof identity.createdAt !== 'string' ||
    !Number.isFinite(Date.parse(identity.createdAt))
  ) {
    throw new Error('Identity creation time is invalid')
  }
  return {
    handle: identity.handle,
    privateKeySign: identity.privateKeySign.toLowerCase(),
    publicKeySign: identity.publicKeySign.toLowerCase(),
    privateKeyEnc: identity.privateKeyEnc.toLowerCase(),
    publicKeyEnc: identity.publicKeyEnc.toLowerCase(),
    createdAt: identity.createdAt,
  }
}

async function encryptWithPassphrase(plaintext, passphrase, aad) {
  validatePassphrase(passphrase)
  const salt = randomBytes(SALT_BYTES)
  const nonce = randomBytes(NONCE_BYTES)
  const key = await scrypt(passphrase, salt, KEY_BYTES, {
    N: KDF_PARAMETERS.N,
    r: KDF_PARAMETERS.r,
    p: KDF_PARAMETERS.p,
    maxmem: 64 * 1024 * 1024,
  })
  try {
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    return {
      kdf: 'scrypt',
      kdfParameters: KDF_PARAMETERS,
      salt: bytesToBase64Url(salt),
      cipher: 'aes-256-gcm',
      nonce: bytesToBase64Url(nonce),
      tag: bytesToBase64Url(cipher.getAuthTag()),
      ciphertext: bytesToBase64Url(ciphertext),
    }
  } finally {
    key.fill(0)
  }
}

async function decryptWithPassphrase(envelope, passphrase, aad, maxCiphertextBytes = MAX_ENVELOPE_BYTES) {
  validatePassphrase(passphrase)
  if (
    envelope.kdf !== 'scrypt' ||
    envelope.cipher !== 'aes-256-gcm' ||
    envelope.kdfParameters?.N !== KDF_PARAMETERS.N ||
    envelope.kdfParameters?.r !== KDF_PARAMETERS.r ||
    envelope.kdfParameters?.p !== KDF_PARAMETERS.p
  ) {
    throw new Error('Unsupported encrypted identity format')
  }
  const salt = base64UrlToBytes(envelope.salt, SALT_BYTES, 'salt')
  const nonce = base64UrlToBytes(envelope.nonce, NONCE_BYTES, 'nonce')
  const tag = base64UrlToBytes(envelope.tag, TAG_BYTES, 'authentication tag')
  const ciphertext = base64UrlToBytes(envelope.ciphertext, undefined, 'encrypted data')
  if (ciphertext.length === 0 || ciphertext.length > maxCiphertextBytes) {
    throw new Error('Encrypted data has an invalid size')
  }
  const key = await scrypt(passphrase, salt, KEY_BYTES, {
    N: KDF_PARAMETERS.N,
    r: KDF_PARAMETERS.r,
    p: KDF_PARAMETERS.p,
    maxmem: 64 * 1024 * 1024,
  })
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(aad)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch (error) {
    throw new Error('Passphrase is incorrect or encrypted data is damaged', { cause: error })
  } finally {
    key.fill(0)
  }
}

export async function encryptLocalIdentity(identity, passphrase) {
  const validatedIdentity = validateIdentity(identity)
  const plaintext = Buffer.from(JSON.stringify(validatedIdentity), 'utf8')
  try {
    const envelope = {
      format: VAULT_FORMAT,
      version: FORMAT_VERSION,
      ...await encryptWithPassphrase(plaintext, passphrase, VAULT_AAD),
    }
    return Buffer.from(JSON.stringify(envelope), 'utf8')
  } finally {
    plaintext.fill(0)
  }
}

export async function decryptLocalIdentity(encryptedVault, passphrase) {
  if (!Buffer.isBuffer(encryptedVault) || encryptedVault.length > MAX_ENVELOPE_BYTES) {
    throw new Error('Encrypted identity vault has an invalid size')
  }
  let envelope
  try {
    envelope = JSON.parse(encryptedVault.toString('utf8'))
  } catch (error) {
    throw new Error('Encrypted identity vault is not valid JSON', { cause: error })
  }
  if (
    envelope.format !== VAULT_FORMAT ||
    envelope.version !== FORMAT_VERSION ||
    Object.keys(envelope).sort().join(',') !== [
      'cipher',
      'ciphertext',
      'format',
      'kdf',
      'kdfParameters',
      'nonce',
      'salt',
      'tag',
      'version',
    ].sort().join(',')
  ) {
    throw new Error('Unsupported encrypted identity vault format')
  }
  const plaintext = await decryptWithPassphrase(envelope, passphrase, VAULT_AAD)
  try {
    return validateIdentity(JSON.parse(plaintext.toString('utf8')))
  } catch (error) {
    throw new Error(`Decrypted identity data is invalid: ${error.message}`, { cause: error })
  } finally {
    plaintext.fill(0)
  }
}

export function identityStorageMode(electronSafeStorage, platform = process.platform) {
  if (!electronSafeStorage.isEncryptionAvailable()) {
    return { mode: 'passphrase', backend: 'unavailable' }
  }
  if (
    platform === 'linux' &&
    !['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6'].includes(
      electronSafeStorage.getSelectedStorageBackend(),
    )
  ) {
    return { mode: 'passphrase', backend: electronSafeStorage.getSelectedStorageBackend() }
  }
  return {
    mode: 'safeStorage',
    backend: platform === 'linux' ? electronSafeStorage.getSelectedStorageBackend() : platform,
  }
}

export async function encryptIdentityVault(identity, {
  safeStorage,
  passphrase,
  platform = process.platform,
}) {
  const validatedIdentity = validateIdentity(identity)
  const storage = identityStorageMode(safeStorage, platform)
  if (typeof passphrase === 'string' && passphrase.length > 0) {
    const encrypted = await encryptLocalIdentity(validatedIdentity, passphrase)
    return Buffer.from(JSON.stringify({
      ...JSON.parse(encrypted.toString('utf8')),
      backend: 'passphrase-scrypt-aes-256-gcm',
    }), 'utf8')
  }
  if (storage.mode === 'passphrase') return encryptLocalIdentity(validatedIdentity, passphrase)
  const ciphertext = safeStorage.encryptString(JSON.stringify(validatedIdentity))
  return Buffer.from(JSON.stringify({
    format: VAULT_FORMAT,
    version: FORMAT_VERSION,
    backend: 'safeStorage',
    ciphertext: bytesToBase64Url(ciphertext),
  }), 'utf8')
}

export async function decryptIdentityVault(encryptedVault, {
  safeStorage,
  passphrase,
  platform = process.platform,
}) {
  if (!Buffer.isBuffer(encryptedVault) || encryptedVault.length > MAX_ENVELOPE_BYTES) {
    throw new Error('Encrypted identity vault has an invalid size')
  }
  let envelope
  try {
    envelope = JSON.parse(encryptedVault.toString('utf8'))
  } catch (error) {
    throw new Error('Identity vault is not valid JSON', { cause: error })
  }
  if (envelope.format !== VAULT_FORMAT || envelope.version !== FORMAT_VERSION) {
    throw new Error('Unsupported identity vault format')
  }

  if (envelope.backend === 'safeStorage') {
    if (Object.keys(envelope).sort().join(',') !== ['backend', 'ciphertext', 'format', 'version'].sort().join(',')) {
      throw new Error('Unsupported operating-system identity vault format')
    }
    const storage = identityStorageMode(safeStorage, platform)
    if (storage.mode !== 'safeStorage') {
      throw new Error('This identity vault was encrypted with the operating system keyring, which is not available')
    }
    const ciphertext = base64UrlToBytes(envelope.ciphertext, undefined, 'encrypted identity')
    let identity
    try {
      identity = JSON.parse(safeStorage.decryptString(ciphertext))
    } catch (error) {
      throw new Error('Could not decrypt the identity with the operating system keyring', { cause: error })
    }
    return validateIdentity(identity)
  }
  if (envelope.backend === 'passphrase-scrypt-aes-256-gcm') {
    if (Object.keys(envelope).sort().join(',') !== [
      'backend',
      'ciphertext',
      'cipher',
      'format',
      'kdf',
      'kdfParameters',
      'nonce',
      'salt',
      'tag',
      'version',
    ].sort().join(',')) {
      throw new Error('Unsupported passphrase identity vault format')
    }
    if (typeof envelope.ciphertext !== 'string') throw new Error('Invalid encrypted identity')
    return decryptLocalIdentity(Buffer.from(JSON.stringify({
      format: VAULT_FORMAT,
      version: FORMAT_VERSION,
      kdf: envelope.kdf,
      kdfParameters: envelope.kdfParameters,
      salt: envelope.salt,
      cipher: envelope.cipher,
      nonce: envelope.nonce,
      tag: envelope.tag,
      ciphertext: envelope.ciphertext,
    }), 'utf8'), passphrase)
  }
  throw new Error('Unsupported identity vault encryption backend')
}

function validateChatArchive(archive) {
  if (!archive || typeof archive !== 'object' || Array.isArray(archive)) {
    throw new Error('Chat archive is invalid')
  }
  if (
    Object.keys(archive).sort().join(',') !== 'conversation,format,messages,ownerHandle,ownerPublicKey,session,version' ||
    archive.format !== CHAT_ARCHIVE_FORMAT ||
    archive.version !== CHAT_ARCHIVE_VERSION ||
    typeof archive.ownerHandle !== 'string' ||
    !/^[\w.-]{1,32}$/u.test(archive.ownerHandle) ||
    typeof archive.ownerPublicKey !== 'string' ||
    !/^[0-9a-f]{64}$/iu.test(archive.ownerPublicKey) ||
    !Array.isArray(archive.messages) ||
    archive.messages.length > 100_000
  ) {
    throw new Error('Unsupported or invalid chat archive')
  }

  if (archive.session === null) {
    if (archive.conversation !== null || archive.messages.length !== 0) {
      throw new Error('Chat archive without an MLS session cannot contain conversation history')
    }
  } else {
    const state = archive.session
    const legacySessionKeys = [
      'groupId',
      'invitationBundle',
      'peerAccountPublicKey',
      'peerHandle',
      'publicSignatureKey',
      'roomId',
      'storageSnapshot',
    ].sort().join(',')
    const currentSessionKeys = [
      ...legacySessionKeys.split(','),
      'pendingMessages',
      'receivedMessageIds',
    ].sort().join(',')
    if (
      !state ||
      typeof state !== 'object' ||
      Array.isArray(state) ||
      ![legacySessionKeys, currentSessionKeys].includes(Object.keys(state).sort().join(',')) ||
      typeof state.peerHandle !== 'string' ||
      !/^[\w.-]{1,32}$/u.test(state.peerHandle) ||
      typeof state.peerAccountPublicKey !== 'string' ||
      !/^[0-9a-f]{64}$/iu.test(state.peerAccountPublicKey) ||
      typeof state.roomId !== 'string' ||
      !/^[A-Za-z0-9_-]{22,64}$/u.test(state.roomId) ||
      typeof state.invitationBundle !== 'string' ||
      Buffer.byteLength(state.invitationBundle, 'utf8') > 256 * 1024
    ) {
      throw new Error('Saved MLS session metadata is invalid')
    }
    if (
      (state.pendingMessages !== undefined && (!Array.isArray(state.pendingMessages) || state.pendingMessages.length > 1000)) ||
      (state.receivedMessageIds !== undefined && (
        !Array.isArray(state.receivedMessageIds) ||
        state.receivedMessageIds.length > 100_000 ||
        state.receivedMessageIds.some(id => typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id))
      ))
    ) {
      throw new Error('Saved message queue metadata is invalid')
    }
    base64UrlToBytes(state.groupId, 32, 'MLS group ID')
    base64UrlToBytes(state.publicSignatureKey, 32, 'MLS signature key')
    base64UrlToBytes(state.storageSnapshot, undefined, 'MLS storage snapshot', 32 * 1024 * 1024)
    for (const pending of state.pendingMessages || []) {
      if (
        !pending ||
        typeof pending !== 'object' ||
        Array.isArray(pending) ||
        Object.keys(pending).sort().join(',') !== 'accepted,createdAt,id,payload,text' ||
        typeof pending.id !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(pending.id) ||
        typeof pending.accepted !== 'boolean' ||
        typeof pending.createdAt !== 'string' ||
        !Number.isFinite(Date.parse(pending.createdAt)) ||
        typeof pending.text !== 'string' ||
        Buffer.byteLength(pending.text, 'utf8') > 64 * 1024 ||
        typeof pending.payload !== 'string' ||
        !/^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$/u.test(pending.payload)
      ) {
        throw new Error('Saved pending message is invalid')
      }
      base64UrlToBytes(pending.payload, undefined, 'pending encrypted message', 128 * 1024)
    }
    const conversation = archive.conversation
    if (
      !conversation ||
      typeof conversation !== 'object' ||
      Array.isArray(conversation) ||
      Object.keys(conversation).sort().join(',') !== 'accountPublicKey,handle' ||
      conversation.handle !== state.peerHandle ||
      conversation.accountPublicKey !== state.peerAccountPublicKey
    ) {
      throw new Error('Saved conversation metadata does not match its MLS session')
    }
  }

  for (const message of archive.messages) {
    if (
      !message ||
      typeof message !== 'object' ||
      Array.isArray(message) ||
      !['from,id,sentAt,text', 'deliveryStatus,from,id,sentAt,text'].includes(Object.keys(message).sort().join(',')) ||
      typeof message.id !== 'string' ||
      message.id.length === 0 ||
      message.id.length > 128 ||
      !['me', 'them'].includes(message.from) ||
      (message.deliveryStatus !== undefined && !['device-queued', 'relay-queued', 'delivered'].includes(message.deliveryStatus)) ||
      typeof message.text !== 'string' ||
      Buffer.byteLength(message.text, 'utf8') > 64 * 1024 ||
      typeof message.sentAt !== 'string' ||
      !Number.isFinite(Date.parse(message.sentAt))
    ) {
      throw new Error('Chat archive contains an invalid message')
    }
  }

  const plaintext = Buffer.from(JSON.stringify(archive), 'utf8')
  if (plaintext.length > MAX_CHAT_ARCHIVE_BYTES) {
    throw new Error('Chat archive exceeds the 44 MiB limit')
  }
  return plaintext
}

export async function encryptChatArchive(archive, {
  safeStorage,
  passphrase,
  platform = process.platform,
}) {
  const plaintext = validateChatArchive(archive)
  try {
    if (typeof passphrase === 'string' && passphrase.length > 0) {
      const fields = await encryptWithPassphrase(plaintext, passphrase, CHAT_ARCHIVE_AAD)
      return Buffer.from(JSON.stringify({
        format: CHAT_ARCHIVE_FORMAT,
        version: CHAT_ARCHIVE_VERSION,
        backend: 'passphrase-scrypt-aes-256-gcm',
        ...fields,
      }), 'utf8')
    }
    const storage = identityStorageMode(safeStorage, platform)
    if (storage.mode !== 'safeStorage') {
      throw new Error('A local vault passphrase is required to encrypt chat history')
    }
    return Buffer.from(JSON.stringify({
      format: CHAT_ARCHIVE_FORMAT,
      version: CHAT_ARCHIVE_VERSION,
      backend: 'safeStorage',
      ciphertext: bytesToBase64Url(safeStorage.encryptString(plaintext.toString('utf8'))),
    }), 'utf8')
  } finally {
    plaintext.fill(0)
  }
}

export async function decryptChatArchive(encryptedArchive, {
  safeStorage,
  passphrase,
  platform = process.platform,
}) {
  if (!Buffer.isBuffer(encryptedArchive) || encryptedArchive.length > MAX_CHAT_ENVELOPE_BYTES) {
    throw new Error('Encrypted chat archive exceeds the 64 MiB limit')
  }
  let envelope
  try {
    envelope = JSON.parse(encryptedArchive.toString('utf8'))
  } catch (error) {
    throw new Error('Encrypted chat archive is not valid JSON', { cause: error })
  }
  if (envelope.format !== CHAT_ARCHIVE_FORMAT || envelope.version !== CHAT_ARCHIVE_VERSION) {
    throw new Error('Unsupported encrypted chat archive format')
  }

  let plaintext
  if (envelope.backend === 'safeStorage') {
    if (Object.keys(envelope).sort().join(',') !== 'backend,ciphertext,format,version') {
      throw new Error('Unsupported operating-system chat archive format')
    }
    const storage = identityStorageMode(safeStorage, platform)
    if (storage.mode !== 'safeStorage') {
      throw new Error('This chat archive was encrypted with an OS keyring that is unavailable')
    }
    const ciphertext = base64UrlToBytes(
      envelope.ciphertext,
      undefined,
      'encrypted chat archive',
      MAX_CHAT_ENVELOPE_BYTES,
    )
    try {
      plaintext = Buffer.from(safeStorage.decryptString(ciphertext), 'utf8')
    } catch (error) {
      throw new Error('Could not decrypt the chat archive with the OS keyring', { cause: error })
    }
  } else if (envelope.backend === 'passphrase-scrypt-aes-256-gcm') {
    if (Object.keys(envelope).sort().join(',') !== [
      'backend',
      'cipher',
      'ciphertext',
      'format',
      'kdf',
      'kdfParameters',
      'nonce',
      'salt',
      'tag',
      'version',
    ].sort().join(',')) {
      throw new Error('Unsupported passphrase chat archive format')
    }
    plaintext = await decryptWithPassphrase(envelope, passphrase, CHAT_ARCHIVE_AAD, MAX_CHAT_ARCHIVE_BYTES)
  } else {
    throw new Error('Unsupported chat archive encryption backend')
  }

  try {
    if (plaintext.length > MAX_CHAT_ARCHIVE_BYTES) {
      throw new Error('Decrypted chat archive exceeds the 44 MiB limit')
    }
    let archive
    try {
      archive = JSON.parse(plaintext.toString('utf8'))
    } catch (error) {
      throw new Error('Decrypted chat archive is not valid JSON', { cause: error })
    }
    validateChatArchive(archive).fill(0)
    return archive
  } finally {
    plaintext.fill(0)
  }
}
