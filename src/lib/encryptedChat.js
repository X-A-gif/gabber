import initMls, { MlsClient } from '../../crypto/pkg/gabber_mls.js'
import {
  createContactBundle,
  createInvitationBundle,
  verifyContactBundle,
  verifyInvitationBundle,
} from './signedBundles.js'

const encoder = new TextEncoder()
const MAX_MESSAGE_BYTES = 64 * 1024
const DEFAULT_RELAY_URL = 'ws://127.0.0.1:8787/v1/rooms'
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost'])
const V3_ONION_HOST = /^[a-z2-7]{56}\.onion$/iu
let wasmReady

function decodeBase64Url(value) {
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '='))
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}

function encodeBase64Url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function decodeUtf8(value) {
  return new TextDecoder('utf-8', { fatal: true }).decode(value)
}

function createRoomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return encodeBase64Url(bytes)
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

function validateRelayUrl(relayUrl, mode) {
  const url = new URL(relayUrl)
  const validCommon = ['/v1/rooms'].includes(url.pathname) && !url.username && !url.password && !url.search && !url.hash
  if (mode === 'tor') {
    if (!['ws:', 'wss:'].includes(url.protocol) || !V3_ONION_HOST.test(url.hostname) || !validCommon) {
      throw new Error('Tor mode requires a version 3 onion relay at /v1/rooms; direct network relays are not allowed')
    }
  } else if (mode !== 'local' || url.protocol !== 'ws:' || !LOOPBACK_HOSTS.has(url.hostname) || !validCommon) {
    throw new Error('Local mode only supports a loopback relay at /v1/rooms')
  }
  return url.href
}

export class EncryptedChatClient {
  constructor(identity, {
    MlsClientClass = MlsClient,
    WebSocketClass = globalThis.WebSocket,
    mode = 'local',
    relayUrl = DEFAULT_RELAY_URL,
    onMessage = () => {},
    onError = () => {},
    onConnectionStatus = () => {},
    onDeliveryStatus = () => {},
    onStateChange = async () => {},
    savedState = null,
  } = {}) {
    if (!identity?.handle || !identity.privateKeySign || !identity.publicKeySign) {
      throw new Error('A loaded Gabber account identity is required')
    }
    if (!WebSocketClass) throw new Error('WebSocket is unavailable in this environment')
    const validatedRelayUrl = validateRelayUrl(relayUrl, mode)
    this.identity = identity
    this.client = savedState
      ? MlsClientClass.restore(
        identity.handle,
        decodeBase64Url(savedState.storageSnapshot),
        decodeBase64Url(savedState.publicSignatureKey),
      )
      : new MlsClientClass(identity.handle)
    this.WebSocketClass = WebSocketClass
    this.mode = mode
    this.relayUrl = validatedRelayUrl
    this.onMessage = onMessage
    this.onError = onError
    this.onConnectionStatus = onConnectionStatus
    this.onDeliveryStatus = onDeliveryStatus
    this.onStateChange = onStateChange
    this.group = null
    this.roomId = null
    this.socket = null
    this.closed = false
    this.invitationBundle = ''
    this.pendingMessages = new Map((savedState?.pendingMessages || []).map(message => [message.id, message]))
    this.receivedMessageIds = new Set(savedState?.receivedMessageIds || [])
    this.uncommittedReceived = new Map()
    this.acceptanceWaiters = new Map()
    this.deliveryStatuses = new Map()
  }

  async restoreSavedState(savedState) {
    this.ensureOpen()
    const group = this.client.load_group(decodeBase64Url(savedState.groupId))
    if (encodeBase64Url(group.group_id()) !== savedState.groupId) {
      group.free()
      throw new Error('Saved MLS group ID does not match the loaded group')
    }
    this.group = group
    this.roomId = savedState.roomId
    this.peerHandle = savedState.peerHandle
    this.peerAccountPublicKey = savedState.peerAccountPublicKey
    this.invitationBundle = savedState.invitationBundle || ''
    void this.reconnect().catch(error => this.onError(error))
  }

  async reconnect() {
    this.ensureOpen()
    if (!this.group || !this.roomId) throw new Error('No saved encrypted conversation to reconnect')
    if (this.socket?.readyState === this.WebSocketClass.OPEN) return
    await this.connect(this.roomId)
  }

  exportState() {
    if (!this.group || !this.roomId) return null
    return {
      storageSnapshot: encodeBase64Url(this.client.export_storage()),
      publicSignatureKey: encodeBase64Url(this.client.public_signature_key()),
      groupId: encodeBase64Url(this.group.group_id()),
      roomId: this.roomId,
      peerHandle: this.peerHandle,
      peerAccountPublicKey: this.peerAccountPublicKey,
      invitationBundle: this.invitationBundle,
      pendingMessages: [...this.pendingMessages.values()],
      receivedMessageIds: [...this.receivedMessageIds],
    }
  }

  async persistState() {
    const state = this.exportState()
    if (state) await this.onStateChange(state)
  }

  createContactCard() {
    this.ensureOpen()
    return createContactBundle(
      this.identity,
      this.client.public_signature_key(),
      this.client.create_key_package(),
    )
  }

  async createInvitation(contactCard) {
    this.ensureOpen()
    if (this.group) throw new Error('This prototype supports one active encrypted conversation at a time')
    const contact = verifyContactBundle(contactCard)
    if (!equalBytes(this.client.key_package_signature_key(contact.keyPackage), contact.devicePublicKey)) {
      throw new Error('The contact KeyPackage signing key does not match its account-signed device key')
    }
    const roomId = createRoomId()
    const group = this.client.create_group(crypto.getRandomValues(new Uint8Array(32)))
    let invitation
    try {
      invitation = group.add_member(this.client, contact.keyPackage)
      group.merge_pending_commit(this.client)
      const bundle = createInvitationBundle(
        this.identity,
        this.client.public_signature_key(),
        roomId,
        invitation.welcome,
      )
      this.group = group
      this.roomId = roomId
      this.peerHandle = contact.handle
      this.peerAccountPublicKey = contact.accountPublicKey
      this.invitationBundle = bundle
      await this.connect(roomId)
      await this.persistState()
      return bundle
    } catch (error) {
      if (this.group === group) {
        this.group = null
        this.roomId = null
      }
      group.free()
      throw error
    } finally {
      invitation?.free()
    }
  }

  async acceptInvitation(invitationBundle) {
    this.ensureOpen()
    if (this.group) throw new Error('This prototype supports one active encrypted conversation at a time')
    const invitation = verifyInvitationBundle(invitationBundle)
    let group
    try {
      group = this.client.join_group(invitation.welcome)
    } catch (error) {
      if (error.message.includes('No matching key package')) {
        throw new Error(
          'This invitation does not match a contact card created in this app session. Ask the peer for a fresh contact card and invitation.',
          { cause: error },
        )
      }
      throw error
    }
    try {
      if (!group.has_member_signature_key(invitation.devicePublicKey)) {
        throw new Error('The MLS Welcome sender key does not match this invitation. Its one-time contact key was consumed; ask the peer for a fresh contact card and invitation.')
      }
      this.group = group
      this.roomId = invitation.roomId
      this.peerHandle = invitation.handle
      this.peerAccountPublicKey = invitation.accountPublicKey
      await this.connect(invitation.roomId)
      await this.persistState()
      return { handle: invitation.handle, accountPublicKey: invitation.accountPublicKey }
    } catch (error) {
      if (this.group === group) {
        this.group = null
        this.roomId = null
      }
      group.free()
      throw error
    }
  }

  async send(text) {
    this.ensureOpen()
    if (!this.group) throw new Error('No active encrypted conversation')
    if (this.pendingMessages.size >= 1000) throw new Error('The local message queue is full; reconnect to deliver pending messages before sending more')
    const messageId = crypto.randomUUID()
    const message = { id: messageId, text, sentAt: new Date().toISOString() }
    const plaintext = encoder.encode(JSON.stringify(message))
    if (plaintext.length > MAX_MESSAGE_BYTES) throw new Error('Message exceeds the 64 KiB prototype limit')
    const payload = this.group.encrypt(this.client, plaintext)
    const pending = {
      id: messageId,
      payload: encodeBase64Url(payload),
      createdAt: message.sentAt,
      text,
      accepted: false,
    }
    this.pendingMessages.set(messageId, pending)
    await this.persistState()
    const accepted = await this.transmitPending(pending)
    return {
      ...message,
      deliveryStatus: this.deliveryStatuses.get(messageId) || (accepted ? 'relay-queued' : 'device-queued'),
    }
  }

  async transmitPending(pending) {
    if (!this.socket || this.socket.readyState !== this.WebSocketClass.OPEN) return false
    if (this.acceptanceWaiters.has(pending.id)) return this.acceptanceWaiters.get(pending.id).promise

    let timer
    let resolveWaiter
    const promise = new Promise(resolve => { resolveWaiter = resolve })
    timer = setTimeout(() => {
      this.acceptanceWaiters.delete(pending.id)
      resolveWaiter(false)
    }, 5000)
    this.acceptanceWaiters.set(pending.id, {
      promise,
      resolve: accepted => {
        clearTimeout(timer)
        this.acceptanceWaiters.delete(pending.id)
        resolveWaiter(accepted)
      },
    })
    try {
      this.socket.send(JSON.stringify({
        type: 'message',
        id: pending.id,
        roomId: this.roomId,
        recipientId: this.peerAccountPublicKey.toLowerCase(),
        payload: pending.payload,
      }))
    } catch (error) {
      this.acceptanceWaiters.get(pending.id)?.resolve(false)
      this.onError(new Error(`Could not submit queued message: ${error.message}`))
      return false
    }
    return promise
  }

  async flushPending() {
    for (const pending of this.pendingMessages.values()) {
      await this.transmitPending(pending)
    }
  }

  async handleAccepted(message) {
    if (message.roomId !== this.roomId) return
    const waiter = this.acceptanceWaiters.get(message.messageId)
    if (!waiter || !this.pendingMessages.has(message.messageId)) return

    const pending = this.pendingMessages.get(message.messageId)
    this.pendingMessages.set(message.messageId, { ...pending, accepted: true })
    try {
      await this.persistState()
    } catch (error) {
      this.pendingMessages.set(message.messageId, pending)
      waiter.resolve(false)
      this.onError(new Error(`Relay accepted the message, but local delivery state could not be saved: ${error.message}`))
      return
    }
    if (this.deliveryStatuses.get(message.messageId) !== 'delivered') {
      this.deliveryStatuses.set(message.messageId, 'relay-queued')
    }
    try {
      await this.onDeliveryStatus(message.messageId, this.deliveryStatuses.get(message.messageId))
    } catch (error) {
      this.onError(new Error(`Could not update message delivery status: ${error.message}`))
    }
    waiter.resolve(true)
  }

  async finalizeOutgoing(messageId) {
    const pending = this.pendingMessages.get(messageId)
    if (!pending?.accepted) return false
    this.pendingMessages.delete(messageId)
    try {
      await this.persistState()
      return true
    } catch (error) {
      this.pendingMessages.set(messageId, pending)
      throw error
    }
  }

  async handleDelivered(message) {
    if (message.roomId !== this.roomId) return
    const pending = this.pendingMessages.get(message.messageId)
    if (pending && !pending.accepted) {
      this.pendingMessages.set(message.messageId, { ...pending, accepted: true })
      try {
        await this.persistState()
      } catch (error) {
        this.pendingMessages.set(message.messageId, pending)
        this.onError(new Error(`Could not save delivered-message state: ${error.message}`))
      }
    }
    this.deliveryStatuses.set(message.messageId, 'delivered')
    try {
      await this.onDeliveryStatus(message.messageId, 'delivered')
    } catch (error) {
      this.onError(new Error(`Could not update message delivery status: ${error.message}`))
    }
  }

  async connect(roomId) {
    this.onConnectionStatus('connecting')
    let socket
    try {
      socket = new this.WebSocketClass(this.relayUrl)
    } catch (error) {
      this.onConnectionStatus('disconnected')
      throw error
    }
    this.socket = socket
    await new Promise((resolve, reject) => {
      let settled = false
      let joinedRelay = false
      let inboundMessages = Promise.resolve()
      const timer = setTimeout(() => finish(new Error(`Timed out joining the ${this.mode === 'tor' ? 'onion relay through Tor' : 'loopback relay'}`)), 15000)
      const finish = error => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) {
          this.onConnectionStatus('disconnected')
          socket.close()
          reject(error)
        } else {
          joinedRelay = true
          this.onConnectionStatus('connected')
          resolve()
        }
      }

      socket.addEventListener('open', () => {
        socket.send(JSON.stringify({
          type: 'join',
          roomId,
          memberId: this.identity.publicKeySign.toLowerCase(),
        }))
      })
      socket.addEventListener('message', event => {
        inboundMessages = inboundMessages.then(async () => {
        let message
        try {
          message = JSON.parse(event.data)
        } catch {
          if (!settled) finish(new Error('Relay returned invalid JSON'))
          else this.onError(new Error('Relay returned invalid JSON'))
          return
        }
        if (message.type === 'joined' && message.roomId === roomId) {
          finish()
          void this.flushPending()
          return
        }
        if (message.type === 'accepted') {
          await this.handleAccepted(message)
          return
        }
        if (message.type === 'delivered' && message.roomId === roomId) {
          await this.handleDelivered(message)
          return
        }
        if (message.type === 'error') {
          const error = new Error(`Relay rejected the request: ${message.code}`)
          if (!settled) finish(error)
          else this.onError(error)
          return
        }
        if (message.type === 'message' && message.roomId === roomId) {
          try {
            if (!this.receivedMessageIds.has(message.messageId)) {
              let value = this.uncommittedReceived.get(message.messageId)
              if (!value) {
                const plaintext = this.group.decrypt(this.client, decodeBase64Url(message.payload))
                value = JSON.parse(decodeUtf8(plaintext))
                if (
                  value.id !== message.messageId ||
                  typeof value.text !== 'string' ||
                  encoder.encode(value.text).length > MAX_MESSAGE_BYTES ||
                  typeof value.sentAt !== 'string' ||
                  !Number.isFinite(Date.parse(value.sentAt))
                ) {
                  throw new Error('Invalid encrypted chat message')
                }
                this.uncommittedReceived.set(message.messageId, value)
              }
              this.receivedMessageIds.add(message.messageId)
              try {
                await this.onMessage(value, this.exportState())
                await this.persistState()
                this.uncommittedReceived.delete(message.messageId)
              } catch (error) {
                this.receivedMessageIds.delete(message.messageId)
                this.onError(new Error(`Could not save received relay message: ${error.message}`))
                socket.close()
                return
              }
            }
            socket.send(JSON.stringify({
              type: 'ack',
              roomId,
              messageId: message.messageId,
            }))
          } catch (error) {
            this.onError(new Error(`Could not process relay message: ${error.message}`))
          }
        }
        }).catch(error => {
          if (!settled) finish(error)
          else this.onError(new Error(`Could not process relay response: ${error.message}`))
        })
      })
      socket.addEventListener('error', () => {
        const error = new Error(this.mode === 'tor'
          ? 'Could not connect to the onion relay through Tor. Confirm Tor is running and the onion relay address is reachable.'
          : 'Could not connect to the loopback relay. Start it with npm run relay.')
        if (!settled) finish(error)
        else if (joinedRelay) {
          this.onConnectionStatus('disconnected')
          this.onError(error)
        }
      })
      socket.addEventListener('close', () => {
        if (!settled) finish(new Error('Relay connection closed before joining'))
        else if (joinedRelay && !this.closed) {
          this.onConnectionStatus('disconnected')
          this.onError(new Error(`${this.mode === 'tor' ? 'Onion relay through Tor' : 'Loopback relay'} connection closed`))
        }
      })
    })
  }

  close() {
    if (this.closed) return
    this.closed = true
    this.socket?.close()
    for (const waiter of this.acceptanceWaiters.values()) waiter.resolve(false)
    this.acceptanceWaiters.clear()
    this.group?.free()
    this.client.free()
  }

  ensureOpen() {
    if (this.closed) throw new Error('Encrypted chat client is closed')
  }
}

export async function createEncryptedChatClient(identity, options) {
  wasmReady ??= (async () => {
    const loadWasm = globalThis.window?.electronAPI?.loadMlsWasm
    if (!loadWasm) throw new Error('Gabber Electron bridge does not expose the MLS WebAssembly loader')
    const result = await loadWasm()
    if (!result.success) throw new Error(`Failed to load local OpenMLS WebAssembly: ${result.error}`)
    await initMls({ module_or_path: result.data })
  })()
  await wasmReady
  const client = new EncryptedChatClient(identity, options)
  if (options?.savedState) {
    try {
      await client.restoreSavedState(options.savedState)
    } catch (error) {
      client.close()
      throw error
    }
  }
  return client
}
