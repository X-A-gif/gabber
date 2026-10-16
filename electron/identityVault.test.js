import test from 'node:test'
import assert from 'node:assert/strict'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import {
  decryptIdentityVault,
  decryptChatArchive,
  encryptChatArchive,
  encryptIdentityVault,
  identityStorageMode,
  validateIdentity,
} from './identityVault.js'

const PASSPHRASE = 'correct-horse-battery-staple'

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex')
}

function makeIdentity() {
  const signingKeys = ed25519.keygen()
  const encryptionKeys = x25519.keygen()
  return {
    handle: 'test-user',
    privateKeySign: toHex(signingKeys.secretKey),
    publicKeySign: toHex(signingKeys.publicKey),
    privateKeyEnc: toHex(encryptionKeys.secretKey),
    publicKeyEnc: toHex(encryptionKeys.publicKey),
    createdAt: new Date('2025-01-01T00:00:00.000Z').toISOString(),
  }
}

function makeChatArchive() {
  const toBase64Url = bytes => Buffer.from(bytes).toString('base64url')
  return {
    format: 'gabber-chat-archive',
    version: 1,
    ownerHandle: 'test-user',
    ownerPublicKey: 'ab'.repeat(32),
    session: {
      storageSnapshot: toBase64Url(Buffer.from('saved MLS provider state')),
      publicSignatureKey: toBase64Url(Buffer.alloc(32, 1)),
      groupId: toBase64Url(Buffer.alloc(32, 2)),
      roomId: toBase64Url(Buffer.alloc(32, 3)),
      peerHandle: 'peer-user',
      peerAccountPublicKey: 'cd'.repeat(32),
      invitationBundle: '',
    },
    conversation: {
      handle: 'peer-user',
      accountPublicKey: 'cd'.repeat(32),
    },
    messages: [{
      id: 'message-1',
      from: 'them',
      text: 'persistent encrypted history',
      sentAt: new Date('2025-01-01T00:00:00.000Z').toISOString(),
    }],
  }
}

const passphraseStorage = {
  isEncryptionAvailable: () => true,
  getSelectedStorageBackend: () => 'basic_text',
}

test('encrypts and decrypts MLS state and chat history with a passphrase', async () => {
  const archive = makeChatArchive()
  const encrypted = await encryptChatArchive(archive, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  assert.equal(JSON.parse(encrypted.toString('utf8')).format, 'gabber-chat-archive')
  assert.deepEqual(await decryptChatArchive(encrypted, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  }), archive)
  await assert.rejects(decryptChatArchive(encrypted, {
    safeStorage: passphraseStorage,
    passphrase: 'a-different-passphrase',
    platform: 'linux',
  }), /incorrect or encrypted data is damaged/)
})

test('validates encrypted local outbox and processed-message receipt state', async () => {
  const archive = makeChatArchive()
  archive.session.pendingMessages = [{
    id: '2ad46824-21df-4e22-afcf-5f1ccdfb52ee',
    payload: Buffer.from('opaque MLS ciphertext').toString('base64url'),
    createdAt: new Date('2025-01-01T00:00:00.000Z').toISOString(),
    text: 'stored locally before relay acceptance',
    accepted: false,
  }]
  archive.session.receivedMessageIds = ['7f308b08-3274-45a2-a87f-ff2de907b0be']
  const encrypted = await encryptChatArchive(archive, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  assert.deepEqual(await decryptChatArchive(encrypted, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  }), archive)
  await assert.rejects(encryptChatArchive({
    ...archive,
    session: {
      ...archive.session,
      pendingMessages: [{ ...archive.session.pendingMessages[0], accepted: 'yes' }],
    },
  }, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  }), /pending message is invalid/u)
})

test('encrypts larger chat histories through safeStorage and rejects malformed archives', async () => {
  const safeStorage = {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: value => Buffer.from(value, 'utf8').reverse(),
    decryptString: value => Buffer.from(value).reverse().toString('utf8'),
  }
  const archive = makeChatArchive()
  archive.messages = Array.from({ length: 5 }, (_, index) => ({
    id: `message-${index}`,
    from: 'me',
    text: 'x'.repeat(60 * 1024),
    sentAt: new Date('2025-01-01T00:00:00.000Z').toISOString(),
  }))
  const encrypted = await encryptChatArchive(archive, { safeStorage, platform: 'linux' })
  assert.deepEqual(await decryptChatArchive(encrypted, { safeStorage, platform: 'linux' }), archive)
  await assert.rejects(
    encryptChatArchive({ ...archive, session: { ...archive.session, roomId: 'invalid' } }, { safeStorage, platform: 'linux' }),
    /session metadata is invalid/,
  )
})

test('validates identity key pairs and rejects malformed or mismatched keys', () => {
  const identity = makeIdentity()
  assert.equal(validateIdentity(identity).handle, identity.handle)
  assert.throws(() => validateIdentity({ ...identity, privateKeySign: 'bad' }), /privateKeySign/)
  assert.throws(() => validateIdentity({ ...identity, publicKeySign: identity.publicKeyEnc }), /do not match/)
})

test('encrypts and decrypts a local vault with a passphrase', async () => {
  const identity = makeIdentity()
  const encrypted = await encryptIdentityVault(identity, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  assert.equal(JSON.parse(encrypted.toString('utf8')).format, 'gabber-identity-vault')
  assert.deepEqual(await decryptIdentityVault(encrypted, {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  }), identity)
})

test('rejects wrong passphrases and tampered vaults', async () => {
  const encrypted = await encryptIdentityVault(makeIdentity(), {
    safeStorage: passphraseStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  await assert.rejects(
    decryptIdentityVault(encrypted, {
      safeStorage: passphraseStorage,
      passphrase: 'a-different-passphrase',
      platform: 'linux',
    }),
    /incorrect or encrypted data is damaged/,
  )

  const tampered = Buffer.from(encrypted)
  tampered[tampered.length - 3] = tampered[tampered.length - 3] === 65 ? 66 : 65
  await assert.rejects(
    decryptIdentityVault(tampered, {
      safeStorage: passphraseStorage,
      passphrase: PASSPHRASE,
      platform: 'linux',
    }),
  )
})

test('uses strong OS key storage only when supported', () => {
  assert.deepEqual(identityStorageMode({
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
  }, 'linux'), { mode: 'safeStorage', backend: 'gnome_libsecret' })
  assert.deepEqual(identityStorageMode(passphraseStorage, 'linux'), { mode: 'passphrase', backend: 'basic_text' })
  assert.deepEqual(identityStorageMode({
    isEncryptionAvailable: () => false,
    getSelectedStorageBackend: () => 'unknown',
  }, 'linux'), { mode: 'passphrase', backend: 'unavailable' })
})

test('encrypts identities with safeStorage when a strong keyring is available', async () => {
  const safeStorage = {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: value => Buffer.from(value, 'utf8').reverse(),
    decryptString: value => Buffer.from(value).reverse().toString('utf8'),
  }
  const identity = makeIdentity()
  const encrypted = await encryptIdentityVault(identity, { safeStorage, platform: 'linux' })
  assert.equal(JSON.parse(encrypted.toString('utf8')).backend, 'safeStorage')
  assert.deepEqual(await decryptIdentityVault(encrypted, { safeStorage, platform: 'linux' }), identity)

  const passphraseVault = await encryptIdentityVault(identity, {
    safeStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  assert.equal(JSON.parse(passphraseVault.toString('utf8')).backend, 'passphrase-scrypt-aes-256-gcm')
  assert.deepEqual(await decryptIdentityVault(passphraseVault, {
    safeStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  }), identity)
})
