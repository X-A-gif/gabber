import { createHash, randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { WebSocketServer, WebSocket } from 'ws'

const MAX_FRAME_BYTES = 256 * 1024
const MAX_PAYLOAD_BYTES = 128 * 1024
const MAX_QUEUE_PER_ROOM = 1000
const MAX_QUEUE_TOTAL = 10_000
const MAX_RECEIPTS = 20_000
const MAX_QUEUE_BYTES = 128 * 1024 * 1024
const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000
const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{22,64}$/
const ACCOUNT_ID_PATTERN = /^[0-9a-f]{64}$/iu
const MESSAGE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const BASE64URL_PATTERN = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$/
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost'])

export function createRelayServer({
  host = '127.0.0.1',
  port = 8787,
  queueFile = process.env.GABBER_RELAY_QUEUE_FILE || join(homedir(), '.gabber', 'relay-queue.json'),
} = {}) {
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error('Prototype relay can only bind to loopback')
  }

  const resolvedQueueFile = resolve(queueFile)
  const rooms = new Map()
  const queuedMessages = new Map()
  const mutationQueue = { current: Promise.resolve() }
  let queueWrite = Promise.resolve()
  let initialization
  let closePromise
  let expiredOnLoad = false
  let queueNeedsMigration = false
  const webSocketServer = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES })
  const httpServer = createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      response.end(JSON.stringify({ ok: true, mode: 'prototype', persistence: 'disk-queue' }))
      return
    }

    response.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    response.end(JSON.stringify({ error: 'not_found' }))
  })

  async function loadQueue() {
    try {
      const serialized = await readFile(resolvedQueueFile, 'utf8')
      const parsed = JSON.parse(serialized)
      if (
        !parsed ||
        parsed.format !== 'gabber-relay-queue' ||
        parsed.version !== 1 ||
        !Array.isArray(parsed.messages) ||
        parsed.messages.length > MAX_QUEUE_TOTAL + MAX_RECEIPTS
      ) {
        throw new Error('Unsupported or invalid persisted relay queue')
      }
      for (const message of parsed.messages) {
        const { normalized, migrated } = normalizeQueuedMessage(message)
        queueNeedsMigration ||= migrated
        if (Date.now() - Date.parse(normalized.createdAt) < MESSAGE_TTL_MS) {
          queuedMessages.set(normalized.id, normalized)
        } else expiredOnLoad = true
      }
      enforceQueueLimits()
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw new Error(`Could not load persisted relay queue: ${error.message}`, { cause: error })
      }
    }
    if (queuedMessages.size || expiredOnLoad || queueNeedsMigration) await persistQueue()
  }

  function ensureInitialized() {
    initialization ??= loadQueue()
    return initialization
  }

  function persistQueue() {
    const snapshot = JSON.stringify({ format: 'gabber-relay-queue', version: 1, messages: [...queuedMessages.values()] })
    queueWrite = queueWrite.catch(() => {}).then(async () => {
      await mkdir(dirname(resolvedQueueFile), { recursive: true, mode: 0o700 })
      const temporaryFile = `${resolvedQueueFile}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
      let file
      try {
        file = await open(temporaryFile, 'wx', 0o600)
        await file.writeFile(snapshot, 'utf8')
        await file.sync()
        await file.close()
        file = null
        await rename(temporaryFile, resolvedQueueFile)
        const directory = await open(dirname(resolvedQueueFile), 'r')
        try {
          await directory.sync()
        } finally {
          await directory.close()
        }
      } catch (error) {
        if (file) await file.close().catch(() => {})
        await rm(temporaryFile, { force: true }).catch(() => {})
        throw error
      }
    })
    return queueWrite
  }

  function pruneExpiredMessages() {
    const cutoff = Date.now() - MESSAGE_TTL_MS
    let changed = false
    for (const [id, message] of queuedMessages) {
      if (Date.parse(message.createdAt) <= cutoff) {
        queuedMessages.delete(id)
        changed = true
      }
    }
    return changed
  }

  function hasExpiredMessages() {
    const cutoff = Date.now() - MESSAGE_TTL_MS
    return [...queuedMessages.values()].some(message => Date.parse(message.createdAt) <= cutoff)
  }

  function enforceQueueLimits() {
    const byRoom = new Map()
    let totalBytes = 0
    const messages = [...queuedMessages.values()].sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt))
    const receipts = messages.filter(message => message.acknowledged)
    for (const message of receipts.slice(0, Math.max(0, receipts.length - MAX_RECEIPTS))) {
      queuedMessages.delete(message.id)
    }
    for (const message of messages.filter(item => !item.acknowledged)) {
      const roomCount = byRoom.get(message.roomId) || 0
      const messageBytes = Buffer.byteLength(message.payload, 'base64url')
      if (roomCount >= MAX_QUEUE_PER_ROOM || totalBytes + messageBytes > MAX_QUEUE_BYTES) {
        queuedMessages.delete(message.id)
        continue
      }
      byRoom.set(message.roomId, roomCount + 1)
      totalBytes += messageBytes
    }
  }

  function storeMutation(mutation) {
    const operation = mutationQueue.current.catch(() => {}).then(async () => {
      const previous = new Map(queuedMessages)
      mutation()
      enforceQueueLimits()
      try {
        await persistQueue()
      } catch (error) {
        queuedMessages.clear()
        for (const [id, message] of previous) queuedMessages.set(id, message)
        throw error
      }
    })
    mutationQueue.current = operation
    return operation
  }

  const expiryTimer = setInterval(() => {
    if (!initialization) return
    void initialization
      .then(() => hasExpiredMessages() ? storeMutation(pruneExpiredMessages) : undefined)
      .catch(error => console.error('Relay queue expiry cleanup failed:', error.message))
  }, 60_000)
  expiryTimer.unref()

  httpServer.on('upgrade', (request, socket, head) => {
    if (request.url !== '/v1/rooms') {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      return
    }

    webSocketServer.handleUpgrade(request, socket, head, webSocket => {
      webSocketServer.emit('connection', webSocket, request)
    })
  })

  webSocketServer.on('connection', webSocket => {
    const joinedRooms = new Map()
    let incomingMessages = Promise.resolve()
    webSocket.on('error', error => {
      console.error('Relay WebSocket error:', error.message)
    })

    webSocket.on('message', (data, isBinary) => {
      incomingMessages = incomingMessages
        .then(() => handleMessage(webSocket, joinedRooms, data, isBinary))
        .catch(error => {
          console.error('Relay queue operation failed:', error.message)
          sendError(webSocket, 'queue_storage_failed')
        })
    })

    webSocket.on('close', () => {
      for (const [roomId, memberId] of joinedRooms) {
        const members = rooms.get(roomId)
        const sockets = members?.get(memberId)
        sockets?.delete(webSocket)
        if (sockets?.size === 0) members.delete(memberId)
        if (members?.size === 0) rooms.delete(roomId)
      }
    })
  })

  async function handleMessage(webSocket, joinedRooms, data, isBinary) {
    await ensureInitialized()
    if (isBinary) {
      sendError(webSocket, 'text_frames_required')
      return
    }

    let message
    try {
      message = JSON.parse(data.toString())
    } catch {
      sendError(webSocket, 'invalid_json')
      return
    }

    if (message?.type === 'join') {
      if (
        typeof message.roomId !== 'string' ||
        !ROOM_ID_PATTERN.test(message.roomId) ||
        typeof message.memberId !== 'string' ||
        !ACCOUNT_ID_PATTERN.test(message.memberId)
      ) {
        sendError(webSocket, 'invalid_room_or_member_id')
        return
      }

      let members = rooms.get(message.roomId)
      if (!members) {
        members = new Map()
        rooms.set(message.roomId, members)
      }
      let sockets = members.get(message.memberId)
      if (!sockets) {
        sockets = new Set()
        members.set(message.memberId, sockets)
      }
      sockets.add(webSocket)
      joinedRooms.set(message.roomId, message.memberId)
      sendJson(webSocket, { type: 'joined', roomId: message.roomId })

      if (hasExpiredMessages()) await storeMutation(pruneExpiredMessages)
      const pending = [...queuedMessages.values()]
        .filter(item => item.roomId === message.roomId)
        .sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt))
      for (const item of pending) {
        if (item.acknowledged && item.senderId === message.memberId) {
          sendJson(webSocket, { type: 'delivered', roomId: item.roomId, messageId: item.id })
        } else if (!item.acknowledged && item.recipientId === message.memberId) {
          sendQueuedMessage(webSocket, item)
        }
      }
      return
    }

    if (message?.type === 'message') {
      if (typeof message.roomId !== 'string' || !joinedRooms.has(message.roomId)) {
        sendError(webSocket, 'join_room_first')
        return
      }
      const senderId = joinedRooms.get(message.roomId)
      if (
        typeof message.id !== 'string' ||
        !MESSAGE_ID_PATTERN.test(message.id) ||
        typeof message.recipientId !== 'string' ||
        !ACCOUNT_ID_PATTERN.test(message.recipientId) ||
        message.recipientId === senderId ||
        typeof message.payload !== 'string' ||
        !BASE64URL_PATTERN.test(message.payload)
      ) {
        sendError(webSocket, 'invalid_message')
        return
      }

      const payloadBytes = Buffer.from(message.payload, 'base64url')
      if (
        payloadBytes.length === 0 ||
        payloadBytes.length > MAX_PAYLOAD_BYTES ||
        payloadBytes.toString('base64url') !== message.payload
      ) {
        sendError(webSocket, 'invalid_payload')
        return
      }
      const queuedMessage = {
        id: message.id,
        roomId: message.roomId,
        senderId,
        recipientId: message.recipientId,
        payload: message.payload,
        payloadHash: hashPayload(message.payload),
        createdAt: new Date().toISOString(),
        acknowledged: false,
        acknowledgedAt: null,
      }
      if (hasExpiredMessages()) await storeMutation(pruneExpiredMessages)
      const existing = queuedMessages.get(message.id)
      if (existing) {
        if (
          existing.roomId !== queuedMessage.roomId ||
          existing.senderId !== queuedMessage.senderId ||
          existing.recipientId !== queuedMessage.recipientId ||
          existing.payloadHash !== queuedMessage.payloadHash
        ) {
          sendError(webSocket, 'message_id_conflict')
          return
        }
      } else {
        const activeMessages = [...queuedMessages.values()].filter(item => !item.acknowledged)
        const roomCount = activeMessages.filter(item => item.roomId === message.roomId).length
        const totalBytes = activeMessages.reduce((sum, item) => sum + Buffer.byteLength(item.payload, 'base64url'), 0)
        if (roomCount >= MAX_QUEUE_PER_ROOM || activeMessages.length >= MAX_QUEUE_TOTAL || totalBytes + payloadBytes.length > MAX_QUEUE_BYTES) {
          sendError(webSocket, 'queue_full')
          return
        }
        await storeMutation(() => queuedMessages.set(message.id, queuedMessage))
      }

      sendJson(webSocket, { type: 'accepted', roomId: message.roomId, messageId: message.id })
      for (const recipientSocket of rooms.get(message.roomId)?.get(message.recipientId) || []) {
        sendQueuedMessage(recipientSocket, queuedMessages.get(message.id))
      }
      return
    }

    if (message?.type === 'ack') {
      if (typeof message.roomId !== 'string' || !joinedRooms.has(message.roomId)) {
        sendError(webSocket, 'join_room_first')
        return
      }
      const memberId = joinedRooms.get(message.roomId)
      if (
        typeof message.messageId !== 'string' ||
        !MESSAGE_ID_PATTERN.test(message.messageId)
      ) {
        sendError(webSocket, 'invalid_ack')
        return
      }
      const queuedMessage = queuedMessages.get(message.messageId)
      if (
        queuedMessage &&
        !queuedMessage.acknowledged &&
        queuedMessage.roomId === message.roomId &&
        queuedMessage.recipientId === memberId
      ) {
        await storeMutation(() => queuedMessages.set(message.messageId, {
          ...queuedMessage,
          payload: '',
          acknowledged: true,
          acknowledgedAt: new Date().toISOString(),
        }))
        for (const senderSocket of rooms.get(message.roomId)?.get(queuedMessage.senderId) || []) {
          sendJson(senderSocket, { type: 'delivered', roomId: message.roomId, messageId: message.messageId })
        }
      }
      sendJson(webSocket, { type: 'acknowledged', roomId: message.roomId, messageId: message.messageId })
      return
    }

    sendError(webSocket, 'unsupported_message')
  }

  return {
    httpServer,
    webSocketServer,
    async listen() {
      await ensureInitialized()
      return new Promise((resolveListen, reject) => {
        httpServer.once('error', reject)
        httpServer.listen(port, host, () => {
          httpServer.off('error', reject)
          resolveListen(httpServer.address())
        })
      })
    },
    close() {
      closePromise ??= (async () => {
        clearInterval(expiryTimer)
        let persistenceError
        await mutationQueue.current.catch(error => { persistenceError = error })
        await queueWrite.catch(error => { persistenceError ??= error })
        for (const client of webSocketServer.clients) client.close()
        await new Promise((resolveClose, reject) => {
          webSocketServer.close(error => {
            if (error) {
              reject(error)
              return
            }
            if (!httpServer.listening) {
              resolveClose()
              return
            }
            httpServer.close(serverError => serverError ? reject(serverError) : resolveClose())
          })
        })
        if (persistenceError) throw persistenceError
      })()
      return closePromise
    },
  }
}

function normalizeQueuedMessage(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    throw new Error('Persisted relay queue contains an invalid message')
  }

  const keys = Object.keys(message).sort().join(',')
  const legacyKeys = 'createdAt,id,payload,recipientId,roomId,senderId'
  const acknowledgedKeys = 'acknowledged,acknowledgedAt,createdAt,id,payload,recipientId,roomId,senderId'
  const currentKeys = 'acknowledged,acknowledgedAt,createdAt,id,payload,payloadHash,recipientId,roomId,senderId'
  if (![legacyKeys, acknowledgedKeys, currentKeys].includes(keys)) {
    throw new Error('Persisted relay queue contains an invalid message')
  }

  const wasLegacyShape = keys !== currentKeys
  const hadAcknowledgedPayload = message.acknowledged === true && message.payload !== ''
  const normalized = {
    id: message.id,
    roomId: message.roomId,
    senderId: message.senderId,
    recipientId: message.recipientId,
    payload: message.payload,
    payloadHash: message.payloadHash,
    createdAt: message.createdAt,
    acknowledged: message.acknowledged ?? false,
    acknowledgedAt: message.acknowledgedAt ?? null,
  }

  if (normalized.payloadHash === undefined) {
    if (typeof normalized.payload !== 'string' || !BASE64URL_PATTERN.test(normalized.payload)) {
      throw new Error('Persisted relay queue contains an invalid message')
    }
    normalized.payloadHash = hashPayload(normalized.payload)
  }

  if (normalized.acknowledged && normalized.payload !== '') {
    normalized.payload = ''
  }

  validateQueuedMessage(normalized)
  return { normalized, migrated: wasLegacyShape || hadAcknowledgedPayload }
}

function validateQueuedMessage(message) {
  if (
    !message ||
    typeof message !== 'object' ||
    Array.isArray(message) ||
    Object.keys(message).sort().join(',') !== 'acknowledged,acknowledgedAt,createdAt,id,payload,payloadHash,recipientId,roomId,senderId' ||
    typeof message.id !== 'string' ||
    !MESSAGE_ID_PATTERN.test(message.id) ||
    typeof message.roomId !== 'string' ||
    !ROOM_ID_PATTERN.test(message.roomId) ||
    typeof message.senderId !== 'string' ||
    !ACCOUNT_ID_PATTERN.test(message.senderId) ||
    typeof message.recipientId !== 'string' ||
    !ACCOUNT_ID_PATTERN.test(message.recipientId) ||
    message.recipientId === message.senderId ||
    typeof message.payload !== 'string' ||
    typeof message.payloadHash !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(message.payloadHash) ||
    typeof message.createdAt !== 'string' ||
    !Number.isFinite(Date.parse(message.createdAt)) ||
    typeof message.acknowledged !== 'boolean' ||
    (message.acknowledged
      ? typeof message.acknowledgedAt !== 'string' ||
        !Number.isFinite(Date.parse(message.acknowledgedAt)) ||
        message.payload !== ''
      : message.acknowledgedAt !== null ||
        !BASE64URL_PATTERN.test(message.payload) ||
        Buffer.from(message.payload, 'base64url').toString('base64url') !== message.payload ||
        Buffer.byteLength(message.payload, 'base64url') === 0 ||
        Buffer.byteLength(message.payload, 'base64url') > MAX_PAYLOAD_BYTES ||
        hashPayload(message.payload) !== message.payloadHash)
  ) {
    throw new Error('Persisted relay queue contains an invalid message')
  }
}

function hashPayload(payload) {
  return createHash('sha256').update(Buffer.from(payload, 'base64url')).digest('hex')
}

function sendQueuedMessage(webSocket, message) {
  if (!message || message.acknowledged) return
  sendJson(webSocket, {
    type: 'message',
    roomId: message.roomId,
    messageId: message.id,
    payload: message.payload,
  })
}

function sendError(webSocket, code) {
  sendJson(webSocket, { type: 'error', code })
}

function sendJson(webSocket, value) {
  if (webSocket.readyState === WebSocket.OPEN) {
    webSocket.send(JSON.stringify(value))
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const relay = createRelayServer({
    host: process.env.GABBER_RELAY_HOST || '127.0.0.1',
    port: Number(process.env.GABBER_RELAY_PORT || 8787),
  })

  relay.listen()
    .then(address => {
      console.log(`Prototype relay listening at http://${address.address}:${address.port}`)
      console.log('Loopback-only; queued MLS ciphertext is persisted locally for up to seven days.')
    })
    .catch(error => {
      console.error('Failed to start relay:', error)
      process.exitCode = 1
    })
}
