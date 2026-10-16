import assert from 'node:assert/strict'
import test from 'node:test'
import { createRecoveryKey, generateRecoveryIdentity, recoverIdentity } from './identity.js'

test('recovery key restores the same account keys for a fresh device', async () => {
  const original = await generateRecoveryIdentity('alice')
  assert.match(original.recoveryKey, /^[A-Za-z0-9_-]{136}$/u)

  const restored = recoverIdentity(original.recoveryKey)
  assert.equal(restored.handle, original.identity.handle)
  assert.equal(restored.privateKeySign, original.identity.privateKeySign)
  assert.equal(restored.publicKeySign, original.identity.publicKeySign)
  assert.equal(restored.privateKeyEnc, original.identity.privateKeyEnc)
  assert.equal(restored.publicKeyEnc, original.identity.publicKeyEnc)
  assert.equal(createRecoveryKey(restored), original.recoveryKey)
})

test('rejects malformed recovery keys and handles', async () => {
  const { recoveryKey } = await generateRecoveryIdentity('alice')
  assert.throws(() => recoverIdentity(`${recoveryKey.slice(0, -1)}!`), /Recovery key is invalid/u)
  const replacement = recoveryKey[10] === 'A' ? 'B' : 'A'
  assert.throws(
    () => recoverIdentity(`${recoveryKey.slice(0, 10)}${replacement}${recoveryKey.slice(11)}`),
    /checksum is invalid/u,
  )
  await assert.rejects(generateRecoveryIdentity('bad handle'), /Handle must use/u)
})
