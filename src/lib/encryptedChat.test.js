import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { once } from 'node:events'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import initMls, { MlsClient } from '../../crypto/pkg/gabber_mls.js'
import { WebSocket } from 'ws'
import { createRelayServer } from '../../relay/server.js'
import { generateIdentity } from './identity.js'
import { EncryptedChatClient } from './encryptedChat.js'
import { createContactBundle, createInvitationBundle, verifyContactBundle, verifyInvitationBundle } from './signedBundles.js'

const wasmBytes = new Uint8Array(await readFile(new URL('../../crypto/pkg/gabber_mls_bg.wasm', import.meta.url)))
await initMls({ module_or_path: wasmBytes })

function waitForMessage(promise) {
  let timer
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Timed out waiting for encrypted message')), 3000) }),
  ]).finally(() => clearTimeout(timer))
}

async function createTestRelay(t) {
  const directory = await mkdtemp(join(tmpdir(), 'gabber-client-relay-test-'))
  const relay = createRelayServer({ port: 0, queueFile: join(directory, 'relay-queue.json') })
  const address = await relay.listen()
  t.after(async () => {
    await relay.close()
    await rm(directory, { recursive: true, force: true })
  })
  return { relay, address }
}

test('two account-linked clients exchange encrypted messages through the loopback relay', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  let alice
  let bob

  try {
    let receiveAtAlice
    let receiveAtBob
    let rejectAtAlice
    let rejectAtBob
    const aliceMessage = new Promise((resolve, reject) => {
      receiveAtAlice = resolve
      rejectAtAlice = reject
    })
    const bobMessage = new Promise((resolve, reject) => {
      receiveAtBob = resolve
      rejectAtBob = reject
    })
    const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
    const bobIdentity = { ...await generateIdentity(), handle: 'bob' }

    alice = new EncryptedChatClient(aliceIdentity, {
      MlsClientClass: MlsClient,
      WebSocketClass: WebSocket,
      relayUrl,
      onMessage: receiveAtAlice,
      onError: rejectAtAlice,
    })
    bob = new EncryptedChatClient(bobIdentity, {
      MlsClientClass: MlsClient,
      WebSocketClass: WebSocket,
      relayUrl,
      onMessage: receiveAtBob,
      onError: rejectAtBob,
    })

    const contactCard = bob.createContactCard()
    const invitation = await alice.createInvitation(contactCard)
    const peer = await bob.acceptInvitation(invitation)
    assert.equal(peer.handle, 'alice')

    await alice.send('hello over MLS')
    assert.equal((await waitForMessage(bobMessage)).text, 'hello over MLS')

    await bob.send('reply over MLS')
    assert.equal((await waitForMessage(aliceMessage)).text, 'reply over MLS')
  } finally {
    alice?.close()
    bob?.close()
    await relay.close()
  }
})

test('queues messages for offline peers and retries locally queued messages after reconnect', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
  const bobIdentity = { ...await generateIdentity(), handle: 'bob' }
  let aliceSavedState
  let alice
  let bob
  let resolveReceived
  const waitForNextBobMessage = () => new Promise(resolve => { resolveReceived = resolve })
  const createAlice = savedState => new EncryptedChatClient(aliceIdentity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    relayUrl,
    savedState,
    onStateChange: state => { aliceSavedState = state },
  })

  try {
    alice = createAlice()
    bob = new EncryptedChatClient(bobIdentity, {
      MlsClientClass: MlsClient,
      WebSocketClass: WebSocket,
      relayUrl,
      onMessage: message => resolveReceived?.(message),
    })
    const invitation = await alice.createInvitation(bob.createContactCard())
    await bob.acceptInvitation(invitation)

    const queuedForBob = waitForNextBobMessage()
    const bobClosed = once(bob.socket, 'close')
    bob.socket.close()
    await bobClosed
    const first = await alice.send('recipient is offline')
    assert.equal(first.deliveryStatus, 'relay-queued')
    await bob.reconnect()
    assert.equal((await waitForMessage(queuedForBob)).text, 'recipient is offline')
    await alice.finalizeOutgoing(first.id)

    const queuedOnAlice = waitForNextBobMessage()
    const aliceClosed = once(alice.socket, 'close')
    alice.socket.close()
    await aliceClosed
    const second = await alice.send('sender was offline')
    assert.equal(second.deliveryStatus, 'device-queued')
    assert.equal(aliceSavedState.pendingMessages[0].text, 'sender was offline')
    await alice.reconnect()
    assert.equal((await waitForMessage(queuedOnAlice)).text, 'sender was offline')
    assert.equal(aliceSavedState.pendingMessages[0].accepted, true)
  } finally {
    alice?.close()
    bob?.close()
    await relay.close()
  }
})

test('retries queued messages after local message persistence fails', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
  const bobIdentity = { ...await generateIdentity(), handle: 'bob' }
  let alice
  let bob
  let shouldFailToSave = true
  let failedMessageResolve
  let receivedMessageResolve
  let deliveredResolve
  const failedMessage = new Promise(resolve => { failedMessageResolve = resolve })
  const receivedMessage = new Promise(resolve => { receivedMessageResolve = resolve })
  const delivered = new Promise(resolve => { deliveredResolve = resolve })
  alice = new EncryptedChatClient(aliceIdentity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    relayUrl,
    onDeliveryStatus: (_messageId, status) => {
      if (status === 'delivered') deliveredResolve(status)
    },
  })
  bob = new EncryptedChatClient(bobIdentity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    relayUrl,
    onMessage: async message => {
      if (shouldFailToSave) throw new Error('Archive write failed')
      receivedMessageResolve(message)
    },
    onError: error => {
      if (error.message.includes('Could not save received relay message')) failedMessageResolve(error)
    },
  })

  try {
    const invitation = await alice.createInvitation(bob.createContactCard())
    await bob.acceptInvitation(invitation)
    const bobClosed = once(bob.socket, 'close')
    bob.socket.close()
    await bobClosed
    const sentMessage = await alice.send('queued while bob was offline')
    await bob.reconnect()
    const failedSocket = bob.socket
    await waitForMessage(failedMessage)
    await waitForMessage(once(failedSocket, 'close'))
    assert.notEqual(alice.deliveryStatuses.get(sentMessage.id), 'delivered')

    shouldFailToSave = false
    await bob.reconnect()
    assert.equal((await waitForMessage(receivedMessage)).text, 'queued while bob was offline')
    assert.equal(await waitForMessage(delivered), 'delivered')
  } finally {
    alice?.close()
    bob?.close()
    await relay.close()
  }
})

test('restores a saved client session and continues messaging after reconstruction', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
  const bobIdentity = { ...await generateIdentity(), handle: 'bob' }
  let aliceSavedState
  let alice
  let bob
  let receiveAtBob

  const nextBobMessage = () => new Promise((resolve, reject) => {
    let timer
    receiveAtBob = message => {
      clearTimeout(timer)
      resolve(message)
    }
    timer = setTimeout(() => reject(new Error('Timed out waiting for encrypted message')), 3000)
  })
  const createAlice = savedState => new EncryptedChatClient(aliceIdentity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    relayUrl,
    savedState,
    onStateChange: state => { aliceSavedState = state },
  })

  try {
    alice = createAlice()
    bob = new EncryptedChatClient(bobIdentity, {
      MlsClientClass: MlsClient,
      WebSocketClass: WebSocket,
      relayUrl,
      onMessage: message => receiveAtBob?.(message),
    })
    const invitation = await alice.createInvitation(bob.createContactCard())
    await bob.acceptInvitation(invitation)

    let messageReceived = nextBobMessage()
    await alice.send('before restart')
    assert.equal((await waitForMessage(messageReceived)).text, 'before restart')
    assert.ok(aliceSavedState?.storageSnapshot)

    alice.close()
    alice = createAlice(aliceSavedState)
    await alice.restoreSavedState(aliceSavedState)
    messageReceived = nextBobMessage()
    await alice.send('after restart')
    assert.equal((await waitForMessage(messageReceived)).text, 'after restart')
  } finally {
    alice?.close()
    bob?.close()
    await relay.close()
  }
})

test('restored clients can send while their relay connections are still joining', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
  const bobIdentity = { ...await generateIdentity(), handle: 'bob' }
  let aliceSavedState
  let bobSavedState
  let alice
  let bob
  let resolveBobMessage
  const bobMessage = new Promise(resolve => { resolveBobMessage = resolve })
  const createClient = (identity, savedState, onStateChange, onMessage = () => {}) => new EncryptedChatClient(identity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    relayUrl,
    savedState,
    onStateChange,
    onMessage,
  })

  try {
    alice = createClient(aliceIdentity, null, state => { aliceSavedState = state })
    bob = createClient(bobIdentity, null, state => { bobSavedState = state })
    const invitation = await alice.createInvitation(bob.createContactCard())
    await bob.acceptInvitation(invitation)

    const aliceSocketClosed = once(alice.socket, 'close')
    const bobSocketClosed = once(bob.socket, 'close')
    alice.close()
    bob.close()
    await Promise.all([aliceSocketClosed, bobSocketClosed])

    alice = createClient(aliceIdentity, aliceSavedState, state => { aliceSavedState = state })
    bob = createClient(
      bobIdentity,
      bobSavedState,
      state => { bobSavedState = state },
      message => resolveBobMessage(message),
    )
    await Promise.all([
      alice.restoreSavedState(aliceSavedState),
      bob.restoreSavedState(bobSavedState),
    ])

    await alice.send('sent during relay reconnect')
    assert.equal((await waitForMessage(bobMessage)).text, 'sent during relay reconnect')
  } finally {
    alice?.close()
    bob?.close()
    await relay.close()
  }
})

test('account-signed bundles cannot misbind KeyPackages or Welcome senders to device keys', async t => {
  const { relay, address } = await createTestRelay(t)
  const relayUrl = `ws://127.0.0.1:${address.port}/v1/rooms`
  const aliceIdentity = { ...await generateIdentity(), handle: 'alice' }
  const bobIdentity = { ...await generateIdentity(), handle: 'bob' }
  const alice = new EncryptedChatClient(aliceIdentity, { MlsClientClass: MlsClient, WebSocketClass: WebSocket, relayUrl })
  const bob = new EncryptedChatClient(bobIdentity, { MlsClientClass: MlsClient, WebSocketClass: WebSocket, relayUrl })

  try {
    const contactCard = bob.createContactCard()
    const contact = verifyContactBundle(contactCard)
    const mismatchedContact = createContactBundle(bobIdentity, new Uint8Array(32).fill(3), contact.keyPackage)
    await assert.rejects(() => alice.createInvitation(mismatchedContact), /does not match/u)

    const invitation = await alice.createInvitation(contactCard)
    const verifiedInvitation = verifyInvitationBundle(invitation)
    const mismatchedInvitation = createInvitationBundle(
      aliceIdentity,
      new Uint8Array(32).fill(5),
      verifiedInvitation.roomId,
      verifiedInvitation.welcome,
    )
    await assert.rejects(() => bob.acceptInvitation(mismatchedInvitation), /one-time contact key was consumed/u)
  } finally {
    alice.close()
    bob.close()
    await relay.close()
  }
})

test('Tor mode only accepts an onion relay and exposes no direct-relay fallback', async () => {
  const identity = { ...await generateIdentity(), handle: 'alice' }
  const relayUrl = `ws://${'a'.repeat(56)}.onion/v1/rooms`
  const torClient = new EncryptedChatClient(identity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    mode: 'tor',
    relayUrl,
  })
  assert.equal(torClient.mode, 'tor')
  assert.equal(torClient.relayUrl, relayUrl)
  torClient.close()

  assert.throws(() => new EncryptedChatClient(identity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    mode: 'tor',
    relayUrl: 'ws://127.0.0.1:8787/v1/rooms',
  }), /version 3 onion relay/u)
  assert.throws(() => new EncryptedChatClient(identity, {
    MlsClientClass: MlsClient,
    WebSocketClass: WebSocket,
    mode: 'local',
    relayUrl,
  }), /loopback relay/u)
})

test('Tor badge transitions to connected only after the onion relay acknowledges the room join', async () => {
  class MockWebSocket {
    static OPEN = 1

    constructor(url) {
      this.url = url
      this.readyState = MockWebSocket.OPEN
      this.listeners = new Map()
      queueMicrotask(() => this.emit('open', {}))
    }

    addEventListener(type, callback) {
      const listeners = this.listeners.get(type) || []
      listeners.push(callback)
      this.listeners.set(type, listeners)
    }

    send(serialized) {
      const message = JSON.parse(serialized)
      if (message.type === 'join') {
        queueMicrotask(() => this.emit('message', {
          data: JSON.stringify({ type: 'joined', roomId: message.roomId }),
        }))
      }
    }

    close() {
      this.readyState = 3
      this.emit('close', {})
    }

    emit(type, event) {
      for (const listener of this.listeners.get(type) || []) listener(event)
    }
  }

  const identity = { ...await generateIdentity(), handle: 'alice' }
  const statuses = []
  const relayUrl = `ws://${'b'.repeat(56)}.onion/v1/rooms`
  const client = new EncryptedChatClient(identity, {
    MlsClientClass: MlsClient,
    WebSocketClass: MockWebSocket,
    mode: 'tor',
    relayUrl,
    onConnectionStatus: status => statuses.push(status),
  })

  try {
    await client.connect('A'.repeat(43))
    assert.deepEqual(statuses, ['connecting', 'connected'])
    assert.equal(client.socket.url, relayUrl)
  } finally {
    client.close()
  }
})
