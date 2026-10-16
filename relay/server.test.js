import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { WebSocket } from 'ws'
import { createRelayServer } from './server.js'

const roomId = '0123456789abcdefghijkl'
const aliceId = 'a'.repeat(64)
const bobId = 'b'.repeat(64)
const receivedMessages = new WeakMap()

async function makeRelay(t, queueFile) {
  const directory = queueFile ? null : await mkdtemp(join(tmpdir(), 'gabber-relay-test-'))
  const relay = createRelayServer({
    port: 0,
    queueFile: queueFile || join(directory, 'relay-queue.json'),
  })
  const address = await relay.listen()
  if (directory) t.after(() => rm(directory, { recursive: true, force: true }))
  t.after(async () => relay.close())
  return { relay, address, queueFile: queueFile || join(directory, 'relay-queue.json') }
}

async function connect(address) {
  const socket = new WebSocket(`ws://127.0.0.1:${address.port}/v1/rooms`)
  await once(socket, 'open')
  receivedMessages.set(socket, { queued: [], waiters: [] })
  socket.on('message', data => {
    const messages = receivedMessages.get(socket)
    const waiter = messages.waiters.shift()
    if (waiter) waiter(data)
    else messages.queued.push(data)
  })
  return socket
}

async function receiveJson(socket) {
  const messages = receivedMessages.get(socket)
  const data = messages.queued.length
    ? messages.queued.shift()
    : await new Promise(resolve => messages.waiters.push(resolve))
  return JSON.parse(data.toString())
}

async function joinRoom(socket, memberId, expected = roomId) {
  socket.send(JSON.stringify({ type: 'join', roomId: expected, memberId }))
  assert.deepEqual(await receiveJson(socket), { type: 'joined', roomId: expected })
}

function expectNoMessage(socket, timeoutMs = 50) {
  return new Promise((resolve, reject) => {
    const onMessage = () => {
      clearTimeout(timeout)
      reject(new Error('Unexpected relay message'))
    }
    const timeout = setTimeout(() => {
      socket.off('message', onMessage)
      resolve()
    }, timeoutMs)
    socket.once('message', onMessage)
  })
}

test('queues opaque ciphertext for an offline recipient and removes it after recipient acknowledgement', async t => {
  const { address } = await makeRelay(t)
  const alice = await connect(address)
  const stranger = await connect(address)
  t.after(() => {
    alice.close()
    stranger.close()
  })
  await joinRoom(alice, aliceId)
  await joinRoom(stranger, 'c'.repeat(64), 'abcdefghijklmnopqrstuv')

  const messageId = randomUUID()
  const ciphertext = Buffer.from('opaque-encrypted-payload').toString('base64url')
  alice.send(JSON.stringify({
    type: 'message',
    id: messageId,
    roomId,
    recipientId: bobId,
    payload: ciphertext,
  }))
  assert.deepEqual(await receiveJson(alice), { type: 'accepted', roomId, messageId })
  await expectNoMessage(stranger)

  const bob = await connect(address)
  t.after(() => bob.close())
  await joinRoom(bob, bobId)
  assert.deepEqual(await receiveJson(bob), {
    type: 'message',
    roomId,
    messageId,
    payload: ciphertext,
  })
  bob.send(JSON.stringify({ type: 'ack', roomId, messageId }))
  assert.deepEqual(await receiveJson(bob), { type: 'acknowledged', roomId, messageId })

  bob.close()
  const reconnectedBob = await connect(address)
  t.after(() => reconnectedBob.close())
  await joinRoom(reconnectedBob, bobId)
  await expectNoMessage(reconnectedBob)
})

test('persists unacknowledged ciphertext across relay restarts and deduplicates sender retries', async t => {
  const { address, queueFile, relay } = await makeRelay(t)
  const alice = await connect(address)
  t.after(() => alice.close())
  await joinRoom(alice, aliceId)

  const messageId = randomUUID()
  const payload = Buffer.from('ciphertext that survives process restart').toString('base64url')
  const outgoing = JSON.stringify({ type: 'message', id: messageId, roomId, recipientId: bobId, payload })
  alice.send(outgoing)
  assert.deepEqual(await receiveJson(alice), { type: 'accepted', roomId, messageId })
  await relay.close()

  const restarted = createRelayServer({ port: 0, queueFile })
  const restartedAddress = await restarted.listen()
  t.after(async () => restarted.close())
  const bob = await connect(restartedAddress)
  t.after(() => bob.close())
  await joinRoom(bob, bobId)
  assert.deepEqual(await receiveJson(bob), { type: 'message', roomId, messageId, payload })
  bob.send(JSON.stringify({ type: 'ack', roomId, messageId }))
  assert.deepEqual(await receiveJson(bob), { type: 'acknowledged', roomId, messageId })

  const restartedAgain = createRelayServer({ port: 0, queueFile })
  const finalAddress = await restartedAgain.listen()
  t.after(async () => restartedAgain.close())
  const aliceRetry = await connect(finalAddress)
  t.after(() => aliceRetry.close())
  await joinRoom(aliceRetry, aliceId)
  assert.deepEqual(await receiveJson(aliceRetry), { type: 'delivered', roomId, messageId })
  aliceRetry.send(outgoing)
  assert.deepEqual(await receiveJson(aliceRetry), { type: 'accepted', roomId, messageId })
  const bobAgain = await connect(finalAddress)
  t.after(() => bobAgain.close())
  await joinRoom(bobAgain, bobId)
  await expectNoMessage(bobAgain)
})

test('migrates valid older queue records without losing offline messages', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'gabber-relay-migration-test-'))
  const queueFile = join(directory, 'relay-queue.json')
  const legacyId = randomUUID()
  const acknowledgedId = randomUUID()
  const payload = Buffer.from('queued before format migration').toString('base64url')
  const now = new Date().toISOString()
  await writeFile(queueFile, JSON.stringify({
    format: 'gabber-relay-queue',
    version: 1,
    messages: [
      { id: legacyId, roomId, senderId: aliceId, recipientId: bobId, payload, createdAt: now },
      {
        id: acknowledgedId,
        roomId,
        senderId: aliceId,
        recipientId: bobId,
        payload,
        createdAt: now,
        acknowledged: true,
        acknowledgedAt: now,
      },
    ],
  }))
  t.after(() => rm(directory, { recursive: true, force: true }))

  const relay = createRelayServer({ port: 0, queueFile })
  const address = await relay.listen()
  t.after(async () => relay.close())
  const migrated = JSON.parse(await readFile(queueFile, 'utf8'))
  assert.equal(migrated.messages.length, 2)
  assert.ok(migrated.messages.every(message => typeof message.payloadHash === 'string'))
  assert.equal(migrated.messages.find(message => message.id === acknowledgedId).payload, '')

  const bob = await connect(address)
  t.after(() => bob.close())
  await joinRoom(bob, bobId)
  assert.deepEqual(await receiveJson(bob), {
    type: 'message',
    roomId,
    messageId: legacyId,
    payload,
  })
})

test('only the queued recipient can acknowledge a message', async t => {
  const { address } = await makeRelay(t)
  const alice = await connect(address)
  const stranger = await connect(address)
  t.after(() => {
    alice.close()
    stranger.close()
  })
  await joinRoom(alice, aliceId)
  await joinRoom(stranger, 'c'.repeat(64))
  const messageId = randomUUID()
  alice.send(JSON.stringify({
    type: 'message',
    id: messageId,
    roomId,
    recipientId: bobId,
    payload: Buffer.from('ciphertext').toString('base64url'),
  }))
  assert.deepEqual(await receiveJson(alice), { type: 'accepted', roomId, messageId })

  stranger.send(JSON.stringify({ type: 'ack', roomId, messageId }))
  assert.deepEqual(await receiveJson(stranger), { type: 'acknowledged', roomId, messageId })
  const bob = await connect(address)
  t.after(() => bob.close())
  await joinRoom(bob, bobId)
  assert.equal((await receiveJson(bob)).messageId, messageId)
})

test('rejects relay use before room join', async t => {
  const { address } = await makeRelay(t)
  const client = await connect(address)
  t.after(() => client.close())

  client.send(JSON.stringify({
    type: 'message',
    id: randomUUID(),
    roomId,
    recipientId: bobId,
    payload: Buffer.from('ciphertext').toString('base64url'),
  }))

  assert.deepEqual(await receiveJson(client), { type: 'error', code: 'join_room_first' })
})

test('refuses to bind the prototype relay beyond loopback', () => {
  assert.throws(
    () => createRelayServer({ host: '0.0.0.0' }),
    /only bind to loopback/,
  )
})
