import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { encryptChatArchive } from './identityVault.js'
import { createChatArchiveStore } from './chatArchiveStore.js'

const PASSPHRASE = 'correct-horse-battery-staple'
const safeStorage = {
  isEncryptionAvailable: () => true,
  getSelectedStorageBackend: () => 'basic_text',
}

function makeArchive(ownerHandle, ownerPublicKey, text) {
  const toBase64Url = bytes => Buffer.from(bytes).toString('base64url')
  const peerAccountPublicKey = 'cd'.repeat(32)
  return {
    format: 'gabber-chat-archive',
    version: 1,
    ownerHandle,
    ownerPublicKey,
    session: {
      storageSnapshot: toBase64Url(Buffer.from('saved MLS provider state')),
      publicSignatureKey: toBase64Url(Buffer.alloc(32, 1)),
      groupId: toBase64Url(Buffer.alloc(32, 2)),
      roomId: toBase64Url(Buffer.alloc(32, 3)),
      peerHandle: 'peer-user',
      peerAccountPublicKey,
      invitationBundle: '',
    },
    conversation: { handle: 'peer-user', accountPublicKey: peerAccountPublicKey },
    messages: [{
      id: `message-${ownerHandle}`,
      from: 'them',
      text,
      sentAt: new Date('2025-01-01T00:00:00.000Z').toISOString(),
    }],
  }
}

async function writeAtomically(filePath, data) {
  await mkdir(dirname(filePath), { recursive: true })
  const temporaryPath = `${filePath}.tmp`
  await writeFile(temporaryPath, data)
  await rename(temporaryPath, filePath)
}

test('keeps each account chat archive separate and migrates the legacy archive', async t => {
  const userDataPath = await mkdtemp(join(tmpdir(), 'gabber-chat-archive-test-'))
  t.after(() => rm(userDataPath, { recursive: true, force: true }))
  const archiveA = makeArchive('alice', 'ab'.repeat(32), 'alice history')
  const archiveB = makeArchive('bob', 'ef'.repeat(32), 'bob history')
  const legacyFile = join(userDataPath, 'chat-history.json')
  const legacyEncrypted = await encryptChatArchive(archiveA, {
    safeStorage,
    passphrase: PASSPHRASE,
    platform: 'linux',
  })
  await writeFile(legacyFile, legacyEncrypted)

  const store = createChatArchiveStore({
    userDataPath,
    safeStorage,
    writeAtomically,
    platform: 'linux',
  })

  assert.deepEqual(await store.load(archiveA.ownerPublicKey, PASSPHRASE), archiveA)
  assert.equal(await store.load(archiveB.ownerPublicKey, PASSPHRASE), null)

  await store.save(archiveB, PASSPHRASE)
  assert.deepEqual(await store.load(archiveA.ownerPublicKey, PASSPHRASE), archiveA)
  assert.deepEqual(await store.load(archiveB.ownerPublicKey, PASSPHRASE), archiveB)
  assert.deepEqual(await readFile(legacyFile), legacyEncrypted)
})

test('rejects invalid archive owner keys before using them as storage identities', async t => {
  const userDataPath = await mkdtemp(join(tmpdir(), 'gabber-chat-archive-test-'))
  t.after(() => rm(userDataPath, { recursive: true, force: true }))
  const store = createChatArchiveStore({
    userDataPath,
    safeStorage,
    writeAtomically,
    platform: 'linux',
  })

  await assert.rejects(store.load('../../identity.json', PASSPHRASE), /owner key is invalid/u)
  await assert.rejects(store.save({ ownerPublicKey: 'invalid' }, PASSPHRASE), /owner key is invalid/u)
})
