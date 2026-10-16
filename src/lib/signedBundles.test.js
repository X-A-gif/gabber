import assert from 'node:assert/strict'
import test from 'node:test'
import { generateIdentity } from './identity.js'
import {
  createContactBundle,
  createInvitationBundle,
  verifyContactBundle,
  verifyInvitationBundle,
} from './signedBundles.js'

test('contact cards bind an MLS device key and KeyPackage to the account signature', async () => {
  const identity = { ...await generateIdentity(), handle: 'alice' }
  const deviceKey = new Uint8Array(32).fill(4)
  const keyPackage = new Uint8Array(256).fill(9)
  const bundle = createContactBundle(identity, deviceKey, keyPackage)

  const verified = verifyContactBundle(bundle)
  assert.equal(verified.handle, 'alice')
  assert.equal(verified.accountPublicKey, identity.publicKeySign)
  assert.deepEqual(verified.devicePublicKey, deviceKey)
  assert.deepEqual(verified.keyPackage, keyPackage)

  const tampered = JSON.parse(bundle)
  tampered.keyPackage = `${tampered.keyPackage.slice(0, -1)}A`
  assert.throws(() => verifyContactBundle(tampered), /signature is invalid/u)
})

test('invitations authenticate the Welcome and room ID with the account key', async () => {
  const identity = { ...await generateIdentity(), handle: 'alice' }
  const roomId = 'A'.repeat(43)
  const welcome = new Uint8Array([1, 2, 3, 4])
  const bundle = createInvitationBundle(identity, new Uint8Array(32).fill(7), roomId, welcome)

  const verified = verifyInvitationBundle(bundle)
  assert.equal(verified.handle, 'alice')
  assert.equal(verified.accountPublicKey, identity.publicKeySign)
  assert.equal(verified.roomId, roomId)
  assert.deepEqual(verified.welcome, welcome)

  const tampered = JSON.parse(bundle)
  tampered.roomId = 'B'.repeat(43)
  assert.throws(() => verifyInvitationBundle(tampered), /signature is invalid/u)
})
