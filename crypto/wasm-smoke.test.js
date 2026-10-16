import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import init, { MlsClient } from './pkg/gabber_mls.js'

const wasmBytes = new Uint8Array(await readFile(new URL('./pkg/gabber_mls_bg.wasm', import.meta.url)))
await init({ module_or_path: wasmBytes })

test('WASM MLS encrypts for a group member and rejects an unrelated group', () => {
  const alice = new MlsClient('alice')
  const bob = new MlsClient('bob')
  const mallory = new MlsClient('mallory')
  const aliceGroup = alice.create_group(new TextEncoder().encode('gabber-wasm-smoke'))
  const unrelatedGroup = mallory.create_group(new TextEncoder().encode('unrelated-wasm-group'))
  const plaintext = new TextEncoder().encode('secret WASM MLS message')
  const plaintextText = new TextDecoder().decode(plaintext)

  try {
    const invitation = aliceGroup.add_member(alice, bob.create_key_package())
    aliceGroup.merge_pending_commit(alice)
    const bobGroup = bob.join_group(invitation.welcome)
    const ciphertext = aliceGroup.encrypt(alice, plaintext)

    try {
      assert.notDeepEqual(ciphertext, plaintext)
      assert.equal(new TextDecoder().decode(bobGroup.decrypt(bob, ciphertext)), plaintextText)
      assert.throws(() => unrelatedGroup.decrypt(mallory, ciphertext))

      const restoredAlice = MlsClient.restore(
        'alice',
        alice.export_storage(),
        alice.public_signature_key(),
      )
      const restoredGroup = restoredAlice.load_group(aliceGroup.group_id())
      try {
        const resumedCiphertext = restoredGroup.encrypt(
          restoredAlice,
          new TextEncoder().encode('message after client restart'),
        )
        assert.equal(
          new TextDecoder().decode(bobGroup.decrypt(bob, resumedCiphertext)),
          'message after client restart',
        )
      } finally {
        restoredGroup.free()
        restoredAlice.free()
      }
    } finally {
      invitation.free()
      bobGroup.free()
    }
  } finally {
    unrelatedGroup.free()
    aliceGroup.free()
    alice.free()
    bob.free()
    mallory.free()
  }
})
