import { useCallback, useEffect, useRef, useState } from 'react'
import { createRecoveryKey, fingerprint } from '../lib/identity'
import { createEncryptedChatClient } from '../lib/encryptedChat'
import { verifyContactBundle, verifyInvitationBundle } from '../lib/signedBundles.js'

function normalizeFingerprint(value) {
  return value.replaceAll(/\s/gu, '').toLowerCase()
}

function accountFingerprint(publicKey) {
  return fingerprint(publicKey, 64)
}

function messageTime(value) {
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

function ChatScreen({ identity, vaultPassphrase, onLock }) {
  const [client, setClient] = useState(null)
  const [networkConfig, setNetworkConfig] = useState(null)
  const [torStatus, setTorStatus] = useState({
    state: 'starting',
    progress: 0,
    message: 'Starting Tor automatically…',
  })
  const [connectionStatus, setConnectionStatus] = useState('idle')
  const [cryptoStatus, setCryptoStatus] = useState('Loading local OpenMLS runtime...')
  const [conversation, setConversation] = useState(null)
  const [messages, setMessages] = useState([])
  const [draft, setDraft] = useState('')
  const [showNewChat, setShowNewChat] = useState(false)
  const [newChatMode, setNewChatMode] = useState('start')
  const [bundleInput, setBundleInput] = useState('')
  const [verifiedPeer, setVerifiedPeer] = useState(null)
  const [fingerprintConfirmation, setFingerprintConfirmation] = useState('')
  const [contactCard, setContactCard] = useState('')
  const [invitationBundle, setInvitationBundle] = useState('')
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [isWorking, setIsWorking] = useState(false)
  const [showRecoveryKey, setShowRecoveryKey] = useState(false)
  const [recoveryKeyCopied, setRecoveryKeyCopied] = useState(false)
  const conversationRef = useRef(null)
  const messagesRef = useRef([])
  const clientRef = useRef(null)
  const sessionRef = useRef(null)
  const archiveWriteQueue = useRef(Promise.resolve())
  const recoveryKey = createRecoveryKey(identity)

  const persistArchive = useCallback((session = sessionRef.current, conversation = conversationRef.current, messages = messagesRef.current) => {
    if (!session) return Promise.resolve()
    const sameSession = sessionRef.current?.roomId === session.roomId
    const nextMessages = [...messages]
    if (sameSession) {
      const messageIndexes = new Map(nextMessages.map((message, index) => [message.id, index]))
      for (const previousMessage of messagesRef.current) {
        const existingIndex = messageIndexes.get(previousMessage.id)
        if (existingIndex === undefined) {
          messageIndexes.set(previousMessage.id, nextMessages.length)
          nextMessages.push(previousMessage)
        } else {
          const currentMessage = nextMessages[existingIndex]
          const deliveryRank = { 'device-queued': 0, 'relay-queued': 1, delivered: 2 }
          if (
            previousMessage.deliveryStatus &&
            (!currentMessage.deliveryStatus ||
              deliveryRank[previousMessage.deliveryStatus] > deliveryRank[currentMessage.deliveryStatus])
          ) {
            nextMessages[existingIndex] = previousMessage
          }
        }
      }
    }
    sessionRef.current = session
    const resolvedConversation = conversation || {
      handle: session.peerHandle,
      accountPublicKey: session.peerAccountPublicKey,
    }
    conversationRef.current = resolvedConversation
    messagesRef.current = nextMessages
    const archive = {
      format: 'gabber-chat-archive',
      version: 1,
      ownerHandle: identity.handle,
      ownerPublicKey: identity.publicKeySign,
      session,
      conversation: resolvedConversation,
      messages: nextMessages,
    }
    const write = archiveWriteQueue.current.catch(() => {}).then(async () => {
      const result = await window.electronAPI.saveChatArchive(archive, vaultPassphrase)
      if (!result.success) throw new Error(result.error || 'Could not save encrypted chat history')
    })
    archiveWriteQueue.current = write
    return write
  }, [identity.handle, identity.publicKeySign, vaultPassphrase])

  useEffect(() => {
    let cancelled = false
    let activeClient
    const unsubscribeTorStatus = window.electronAPI.onTorStatus(status => {
      if (!cancelled) setTorStatus(status)
    })

    async function initializeClient() {
      try {
        const config = await window.electronAPI.getNetworkConfig()
        if (cancelled) return
        setNetworkConfig(config)
        setTorStatus(config.torStatus)
        const archiveResult = await window.electronAPI.loadChatArchive(identity.publicKeySign, vaultPassphrase)
        if (!archiveResult.success) {
          throw new Error(`Saved chat history could not be restored: ${archiveResult.error || 'archive read failed'}. The existing archive was left untouched.`)
        }
        if (cancelled) return
        const storedArchive = archiveResult.data
        const archiveBelongsToAnotherIdentity = storedArchive && (
          storedArchive.ownerHandle !== identity.handle ||
          storedArchive.ownerPublicKey.toLowerCase() !== identity.publicKeySign.toLowerCase()
        )
        if (archiveBelongsToAnotherIdentity) {
          setNotice('An older chat archive belongs to a different account; it was left untouched.')
        }
        const archive = archiveBelongsToAnotherIdentity ? null : storedArchive
        const savedState = archive?.session || null
        if (archive) {
          const restoredMessages = [...archive.messages]
          for (const pending of savedState?.pendingMessages || []) {
            if (!restoredMessages.some(message => message.id === pending.id)) {
              restoredMessages.push({
                id: pending.id,
                from: 'me',
                text: pending.text,
                sentAt: pending.createdAt,
                deliveryStatus: pending.accepted ? 'relay-queued' : 'device-queued',
              })
            }
          }
          conversationRef.current = archive.conversation
          messagesRef.current = restoredMessages
          sessionRef.current = savedState
          setConversation(archive.conversation)
          setMessages(restoredMessages)
          setInvitationBundle(savedState.invitationBundle || '')
          setCryptoStatus('Restoring encrypted chat history and MLS session...')
          if (restoredMessages.length !== archive.messages.length) {
            await persistArchive(savedState, archive.conversation, restoredMessages)
          }
        }
        const createdClient = await createEncryptedChatClient(identity, {
          mode: config.mode,
          relayUrl: config.relayUrl,
          savedState,
          onStateChange: state => persistArchive(state),
          onMessage: async (message, state) => {
            const existingMessage = messagesRef.current.find(entry => entry.id === message.id)
            const nextMessages = existingMessage
              ? messagesRef.current
              : [...messagesRef.current, {
                id: message.id,
                from: 'them',
                text: message.text,
                sentAt: message.sentAt,
                deliveryStatus: 'delivered',
              }]
            const restoredConversation = conversationRef.current || {
              handle: state.peerHandle,
              accountPublicKey: state.peerAccountPublicKey,
            }
            await persistArchive(state, restoredConversation, nextMessages)
            messagesRef.current = nextMessages
            conversationRef.current = restoredConversation
            if (!cancelled) {
              setConversation(restoredConversation)
              setMessages(nextMessages)
            }
          },
          onError: clientError => {
            if (!cancelled) setError(clientError.message)
          },
          onDeliveryStatus: async (messageId, deliveryStatus) => {
            const nextMessages = messagesRef.current.map(message => (
              message.id === messageId ? { ...message, deliveryStatus } : message
            ))
            if (nextMessages.every((message, index) => message === messagesRef.current[index])) return
            await persistArchive(sessionRef.current, conversationRef.current, nextMessages)
            messagesRef.current = nextMessages
            if (!cancelled) setMessages(nextMessages)
            if (clientRef.current && deliveryStatus !== 'device-queued') {
              await clientRef.current.finalizeOutgoing(messageId)
            }
          },
          onConnectionStatus: status => {
            if (!cancelled) setConnectionStatus(status)
          },
        })
        activeClient = createdClient
        if (cancelled) {
          createdClient.close()
        } else {
          clientRef.current = createdClient
          sessionRef.current = createdClient.exportState()
          setClient(createdClient)
          for (const pending of sessionRef.current?.pendingMessages || []) {
            if (pending.accepted && messagesRef.current.some(message => message.id === pending.id)) {
              await createdClient.finalizeOutgoing(pending.id)
            }
          }
          setCryptoStatus(savedState
            ? 'Saved MLS session restored; reconnecting uses its persisted ratchet state.'
            : config.mode === 'tor'
              ? 'OpenMLS ready; waiting for automatic Tor bootstrap.'
              : config.torStatus.state === 'connected'
                ? 'Tor is ready; the local development relay is not routed through Tor.'
                : 'OpenMLS ready; Tor is starting in the background.')
        }
      } catch (loadError) {
        if (!cancelled) {
          setCryptoStatus('OpenMLS or network configuration could not be loaded.')
          setConnectionStatus('disconnected')
          setError(loadError.message)
        }
      }
    }

    initializeClient()

    return () => {
      cancelled = true
      unsubscribeTorStatus()
      clientRef.current = null
      activeClient?.close()
    }
  }, [identity, persistArchive, vaultPassphrase])

  const copyToClipboard = async (value, label) => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable; select and copy the bundle text instead.')
      await navigator.clipboard.writeText(value)
      setNotice(`${label} copied to clipboard.`)
      setError('')
    } catch (copyError) {
      setError(copyError.message)
    }
  }

  const copyRecoveryKey = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable; select and copy the recovery key manually.')
      await navigator.clipboard.writeText(recoveryKey)
      setRecoveryKeyCopied(true)
      setNotice('Recovery key copied. Store it offline; anyone with it can control this account.')
      setError('')
    } catch (copyError) {
      setError(copyError.message)
    }
  }

  const handleCreateContactCard = async () => {
    if (!client) return
    try {
      const card = client.createContactCard()
      setContactCard(card)
      setNotice('One-time MLS contact card created. Share it with your peer.')
      setError('')
      await copyToClipboard(card, 'Contact card')
    } catch (cardError) {
      setError(cardError.message)
    }
  }

  const handleVerifyBundle = () => {
    try {
      const peer = newChatMode === 'start'
        ? verifyContactBundle(bundleInput)
        : verifyInvitationBundle(bundleInput)
      setVerifiedPeer(peer)
      setFingerprintConfirmation('')
      setError('')
      setNotice('Bundle signature verified. This does not prove the account belongs to the person you expect.')
    } catch (verifyError) {
      setVerifiedPeer(null)
      setError(verifyError.message)
    }
  }

  const handleStartConversation = async () => {
    if (!client || !verifiedPeer) return
    if (networkConfig?.mode === 'tor' && torStatus.state !== 'connected') {
      setError('Wait for Tor to finish connecting before starting an onion-relay chat.')
      return
    }
    const expected = accountFingerprint(verifiedPeer.accountPublicKey)
    if (normalizeFingerprint(fingerprintConfirmation) !== normalizeFingerprint(expected)) {
      setError('Fingerprint does not match. Compare it with your peer over a separate trusted channel.')
      return
    }

    setIsWorking(true)
    try {
      const bundle = await client.createInvitation(bundleInput)
      setInvitationBundle(bundle)
      const nextConversation = { handle: verifiedPeer.handle, accountPublicKey: verifiedPeer.accountPublicKey }
      conversationRef.current = nextConversation
      setConversation(nextConversation)
      messagesRef.current = []
      setMessages([])
      setShowNewChat(false)
      setCryptoStatus('MLS group ready; invitation created. Waiting for the peer to join.')
      setNotice('Share the signed invitation bundle with your peer.')
      setError('')
    } catch (startError) {
      setError(startError.message)
    } finally {
      setIsWorking(false)
    }
  }

  const handleJoinConversation = async () => {
    if (!client || !verifiedPeer) return
    if (networkConfig?.mode === 'tor' && torStatus.state !== 'connected') {
      setError('Wait for Tor to finish connecting before joining an onion-relay chat.')
      return
    }
    const expected = accountFingerprint(verifiedPeer.accountPublicKey)
    if (normalizeFingerprint(fingerprintConfirmation) !== normalizeFingerprint(expected)) {
      setError('Fingerprint does not match. Compare it with your peer over a separate trusted channel.')
      return
    }

    setIsWorking(true)
    try {
      const peer = await client.acceptInvitation(bundleInput)
      conversationRef.current = peer
      setConversation(peer)
      messagesRef.current = []
      setMessages([])
      setInvitationBundle('')
      setShowNewChat(false)
      setCryptoStatus(networkConfig?.mode === 'tor'
        ? 'Joined the MLS group through its onion relay.'
        : 'Joined the MLS group; connected to the loopback relay.')
      setNotice('Encrypted conversation joined. History and MLS state are protected in the local encrypted archive.')
      setError('')
    } catch (joinError) {
      setError(joinError.message)
    } finally {
      setIsWorking(false)
    }
  }

  const handleSendMessage = async event => {
    event.preventDefault()
    const text = draft.trim()
    if (!text || !client || !conversation || isWorking) return

    setIsWorking(true)
    try {
      const message = await client.send(text)
      const nextMessages = [...messagesRef.current, {
        id: message.id,
        from: 'me',
        text: message.text,
        sentAt: message.sentAt,
        deliveryStatus: message.deliveryStatus,
      }]
      await persistArchive(client.exportState(), conversationRef.current, nextMessages)
      messagesRef.current = nextMessages
      setMessages(nextMessages)
      await client.finalizeOutgoing(message.id)
      setDraft('')
      setError('')
    } catch (sendError) {
      setError(sendError.message)
    } finally {
      setIsWorking(false)
    }
  }

  const handleReconnect = async () => {
    if (!client || isWorking) return
    if (networkConfig?.mode === 'tor' && torStatus.state !== 'connected') {
      setError('Wait for Tor to finish connecting before reconnecting to the onion relay.')
      return
    }
    setIsWorking(true)
    try {
      await client.reconnect()
      setError('')
      setNotice('Reconnected to the saved MLS room.')
    } catch (reconnectError) {
      setError(reconnectError.message)
    } finally {
      setIsWorking(false)
    }
  }

  const resetBundleDialog = mode => {
    setNewChatMode(mode)
    setBundleInput('')
    setVerifiedPeer(null)
    setFingerprintConfirmation('')
    setError('')
    setShowNewChat(true)
  }

  return (
    <main className="terminal-app flex h-screen overflow-hidden bg-[#090b10] font-mono text-slate-200">
      <aside className="terminal-sidebar flex w-[300px] shrink-0 flex-col border-r border-white/[0.07] bg-[#0d1017] max-[680px]:w-[76px]">
        <div className="flex h-[72px] items-center justify-between border-b border-white/[0.07] px-5 max-[680px]:justify-center max-[680px]:px-2">
          <div className="flex items-center gap-3">
            <img src="/gabber.png" alt="Gabber" className="h-8 w-28 object-contain object-left max-[680px]:hidden" />
            <div className="max-[680px]:hidden">
              <p className="text-[10px] tracking-[0.16em] text-slate-500">MLS // LOCAL RELAY</p>
            </div>
          </div>
          <button
            aria-label="Start a new encrypted chat"
            title="Start a new encrypted chat"
            onClick={() => resetBundleDialog('start')}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-white/10 text-lg text-slate-400 transition hover:border-cyan-400/40 hover:text-cyan-300"
          >
            +
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-5">
          <p className="px-2 text-[10px] font-semibold tracking-[0.18em] text-slate-600 max-[680px]:hidden">SESSION</p>
          {conversation ? (
            <div className="mt-3 flex items-center gap-3 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.06] p-3 max-[680px]:justify-center max-[680px]:px-1">
              <span className="terminal-avatar flex h-10 w-10 shrink-0 items-center justify-center text-xs font-bold">
                {conversation.handle.slice(0, 2).toUpperCase()}
              </span>
              <span className="min-w-0 flex-1 max-[680px]:hidden">
                <span className="block truncate text-xs font-semibold text-cyan-100">@{conversation.handle}</span>
                <span className="mt-1 block text-[9px] text-green-300/80">MLS group active</span>
              </span>
            </div>
          ) : (
            <p className="px-2 py-4 text-[10px] leading-relaxed text-slate-600 max-[680px]:hidden">
              No active conversation. Create a signed contact card, then exchange a one-time invitation.
            </p>
          )}
        </div>

        <div className="space-y-2 border-t border-white/[0.07] p-3 max-[680px]:px-2">
          <button
            onClick={handleCreateContactCard}
            disabled={!client}
            className="w-full border border-cyan-500/50 px-3 py-2 text-left text-[9px] tracking-wide text-cyan-200 hover:bg-cyan-400/[0.07] disabled:opacity-40 max-[680px]:hidden"
          >
            EXPORT ONE-TIME CONTACT CARD
          </button>
          <div className="flex items-center gap-3 rounded-xl bg-white/[0.03] p-3 max-[680px]:justify-center max-[680px]:px-1">
            <span className="terminal-avatar flex h-9 w-9 shrink-0 items-center justify-center text-xs font-bold">
              {(identity.handle || 'G').slice(0, 2).toUpperCase()}
            </span>
            <span className="min-w-0 flex-1 max-[680px]:hidden">
              <span className="block truncate text-xs font-semibold text-slate-200">@{identity.handle}</span>
              <span className="mt-1 flex items-center gap-1.5 text-[9px] text-slate-500">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Account identity
              </span>
            </span>
          </div>
          <button
            onClick={() => { setShowRecoveryKey(true); setRecoveryKeyCopied(false) }}
            className="w-full border border-amber-500/40 px-3 py-2 text-left text-[9px] tracking-wide text-amber-200 hover:bg-amber-500/[0.07]"
          >
            VIEW ACCOUNT RECOVERY KEY
          </button>
        </div>
      </aside>

      <section className="flex min-w-0 flex-1 flex-col">
        <header className="terminal-topbar flex h-[72px] shrink-0 items-center justify-between border-b border-white/[0.07] px-6 max-[680px]:px-4">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-white">
              {conversation ? `@${conversation.handle}` : 'Encrypted chat'}
            </p>
            <p className="mt-0.5 truncate text-[10px] text-slate-500">{cryptoStatus}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <div
              role="status"
              aria-live="polite"
              aria-label={`Tor network ${torStatus.state}: ${torStatus.message}`}
              title={networkConfig?.mode === 'tor'
                ? `Managed Tor daemon status: ${torStatus.message}`
                : `Tor is managed automatically. The local development relay is not routed through Tor. ${torStatus.message}`}
              className={`flex items-center gap-1.5 border px-2 py-1.5 text-[9px] tracking-wide ${
                torStatus.state === 'connected'
                  ? 'border-green-400/30 bg-green-400/[0.06] text-green-200'
                  : ['starting', 'bootstrapping'].includes(torStatus.state)
                    ? 'border-amber-300/25 bg-amber-300/[0.05] text-amber-200'
                    : torStatus.state === 'error' || torStatus.state === 'unavailable'
                      ? 'border-fuchsia-300/25 bg-fuchsia-300/[0.05] text-fuchsia-200'
                      : 'border-white/10 text-slate-500'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${
                torStatus.state === 'connected'
                  ? 'bg-green-400 shadow-[0_0_7px_rgba(74,222,128,0.8)]'
                  : ['starting', 'bootstrapping'].includes(torStatus.state)
                    ? 'animate-pulse bg-amber-300'
                    : torStatus.state === 'error' || torStatus.state === 'unavailable'
                      ? 'bg-fuchsia-300'
                      : 'bg-slate-600'
              }`} />
              {torStatus.state === 'connected'
                ? networkConfig?.mode === 'tor' ? 'TOR CONNECTED' : 'TOR READY'
                : torStatus.state === 'bootstrapping'
                  ? `TOR ${torStatus.progress}%`
                  : torStatus.state === 'starting'
                    ? 'TOR STARTING'
                    : torStatus.state === 'error' || torStatus.state === 'unavailable'
                      ? 'TOR OFFLINE'
                      : 'TOR STOPPED'}
            </div>
            <div
              role="status"
              aria-live="polite"
              aria-label={`${networkConfig?.mode === 'tor' ? 'Onion' : 'Local'} relay connection ${connectionStatus}`}
              title={networkConfig?.mode === 'tor'
                ? 'Relay connected means the onion relay acknowledged the chat join through the managed Tor proxy.'
                : 'Local development relay; chat traffic stays on this machine and is not routed through Tor.'}
              className={`flex items-center gap-1.5 border px-2 py-1.5 text-[9px] tracking-wide ${
                connectionStatus === 'connected'
                  ? 'border-green-400/30 bg-green-400/[0.06] text-green-200'
                  : connectionStatus === 'connecting'
                    ? 'border-amber-300/25 bg-amber-300/[0.05] text-amber-200'
                    : connectionStatus === 'disconnected'
                      ? 'border-fuchsia-300/25 bg-fuchsia-300/[0.05] text-fuchsia-200'
                      : 'border-white/10 text-slate-500'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${
                connectionStatus === 'connected'
                  ? 'bg-green-400 shadow-[0_0_7px_rgba(74,222,128,0.8)]'
                  : connectionStatus === 'connecting'
                    ? 'animate-pulse bg-amber-300'
                    : connectionStatus === 'disconnected'
                      ? 'bg-fuchsia-300'
                      : 'bg-slate-600'
              }`} />
              {connectionStatus === 'connected'
                ? networkConfig?.mode === 'tor' ? 'ONION RELAY' : 'LOCAL RELAY'
                : connectionStatus === 'connecting'
                  ? networkConfig?.mode === 'tor' ? 'RELAY CONNECTING' : 'LOCAL CONNECTING'
                  : connectionStatus === 'disconnected'
                    ? 'RELAY OFFLINE'
                    : networkConfig?.mode === 'tor' ? 'NO RELAY' : 'LOCAL RELAY'}
            </div>
            {conversation && connectionStatus !== 'connected' && (
              <button
                onClick={handleReconnect}
                disabled={!client || isWorking || (networkConfig?.mode === 'tor' && torStatus.state !== 'connected')}
                className="rounded-sm border border-amber-300/30 px-2.5 py-1.5 text-[9px] tracking-wide text-amber-100 hover:bg-amber-300/[0.06] disabled:cursor-not-allowed disabled:opacity-40"
              >
                RECONNECT
              </button>
            )}
            <button
              onClick={() => resetBundleDialog('join')}
              className="rounded-sm border border-cyan-500/50 px-2.5 py-1.5 text-[9px] tracking-wide text-cyan-200 transition hover:bg-cyan-400/[0.07]"
            >
              JOIN INVITE
            </button>
            <button
              onClick={async () => {
                try {
                  await archiveWriteQueue.current
                  onLock()
                } catch (lockError) {
                  setError(`Could not finish saving encrypted chat history; identity remains unlocked: ${lockError.message}`)
                }
              }}
              disabled={isWorking}
              title="Lock identity"
              aria-label="Lock identity"
              className="rounded-sm border border-white/10 px-2.5 py-1.5 text-[9px] tracking-wide text-slate-400 transition hover:border-white/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              LOCK
            </button>
          </div>
        </header>

        <div className="terminal-notice flex items-center gap-2 border-b border-amber-300/[0.08] bg-amber-300/[0.035] px-4 py-2 text-[9px] leading-relaxed text-amber-100/70">
          <span className="text-amber-300">!</span>
          Offline sends stay encrypted in this device’s archive until relay acceptance. The relay keeps ciphertext for up to seven days, until the recipient acknowledges it.
        </div>

        {error && (
          <p role="alert" className="border-b border-fuchsia-300/15 bg-fuchsia-300/[0.05] px-5 py-2 text-[10px] text-fuchsia-200">
            {error}
          </p>
        )}
        {notice && !error && (
          <p role="status" className="border-b border-green-300/10 bg-green-300/[0.035] px-5 py-2 text-[10px] text-green-200/80">
            {notice}
          </p>
        )}

        {invitationBundle && (
          <div className="border-b border-cyan-300/10 bg-cyan-300/[0.025] p-3">
            <label htmlFor="outgoing-invitation" className="mb-2 block text-[9px] tracking-wide text-cyan-200">
              SIGNED INVITATION — SEND TO @{conversation?.handle}
            </label>
            <div className="flex gap-2">
              <textarea
                id="outgoing-invitation"
                readOnly
                rows="2"
                value={invitationBundle}
                className="min-w-0 flex-1 resize-y border border-white/10 bg-black/20 p-2 text-[9px] text-slate-400"
              />
              <button onClick={() => copyToClipboard(invitationBundle, 'Invitation')} className="border border-cyan-400/30 px-3 text-[9px] text-cyan-200 hover:bg-cyan-400/10">
                COPY
              </button>
            </div>
          </div>
        )}

        <div className="flex-1 space-y-5 overflow-y-auto px-6 py-6 max-[680px]:px-4">
          {!conversation && (
            <div className="mx-auto mt-12 max-w-lg border border-white/[0.08] bg-black/20 p-5">
              <p className="text-xs tracking-wide text-green-300">NO ACTIVE MLS GROUP</p>
              <p className="mt-3 text-[10px] leading-relaxed text-slate-400">
                Exchange signed bundles out of band: your contact card lets a peer invite this device; an invitation lets you join their group. Compare the account fingerprint with your peer through a separate trusted channel before accepting either bundle.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                <button onClick={handleCreateContactCard} disabled={!client} className="border border-cyan-400/40 px-3 py-2 text-[9px] text-cyan-200 hover:bg-cyan-400/10 disabled:opacity-40">
                  CREATE MY CONTACT CARD
                </button>
                <button onClick={() => resetBundleDialog('start')} className="border border-white/15 px-3 py-2 text-[9px] text-slate-300 hover:bg-white/[0.05]">
                  INVITE A CONTACT
                </button>
                <button onClick={() => resetBundleDialog('join')} className="border border-white/15 px-3 py-2 text-[9px] text-slate-300 hover:bg-white/[0.05]">
                  JOIN AN INVITATION
                </button>
              </div>
              {contactCard && (
                <div className="mt-4">
                  <label htmlFor="my-contact-card" className="mb-2 block text-[9px] tracking-wide text-slate-500">ONE-TIME SIGNED CONTACT CARD</label>
                  <div className="flex gap-2">
                    <textarea id="my-contact-card" readOnly rows="3" value={contactCard} className="min-w-0 flex-1 resize-y border border-white/10 bg-black/20 p-2 text-[9px] text-slate-500" />
                    <button onClick={() => copyToClipboard(contactCard, 'Contact card')} className="border border-white/15 px-3 text-[9px] text-slate-300 hover:bg-white/[0.05]">COPY</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {conversation && messages.length === 0 && (
            <p className="mx-auto mt-12 max-w-md text-center text-[10px] leading-relaxed text-slate-500">
              MLS group established with @{conversation.handle}. Messages are encrypted locally; offline recipients receive queued ciphertext when they reconnect.
            </p>
          )}
          {messages.map(message => (
            <div key={message.id} className={`flex ${message.from === 'me' ? 'justify-end' : 'justify-start'}`}>
              <div className={`${message.from === 'me' ? 'items-end' : 'items-start'} flex max-w-[78%] flex-col`}>
                {message.from === 'them' && <span className="mb-1.5 ml-1 text-[9px] text-slate-500">@{conversation.handle}</span>}
                <p className={`rounded-sm border px-4 py-2.5 text-xs leading-relaxed ${
                  message.from === 'me'
                    ? 'terminal-message-mine bg-cyan-400/[0.12] text-cyan-50'
                    : 'terminal-message-peer bg-white/[0.045] text-slate-300'
                }`}>{message.text}</p>
                <span className="mt-1 px-1 text-[9px] text-slate-600">
                  {messageTime(message.sentAt)}
                  {message.from === 'me' && ` · ${message.deliveryStatus === 'delivered'
                    ? 'delivered'
                    : message.deliveryStatus === 'relay-queued'
                      ? 'queued at relay'
                      : 'queued on this device'}`}
                </span>
              </div>
            </div>
          ))}
        </div>

        <form onSubmit={handleSendMessage} className="shrink-0 border-t border-white/[0.07] px-6 pb-5 pt-4 max-[680px]:px-4">
          <label htmlFor="message-draft" className="sr-only">Write an encrypted message</label>
          <div className="flex items-end gap-3 rounded-sm border border-white/10 bg-white/[0.035] p-2 focus-within:border-cyan-300/30">
            <textarea
              id="message-draft"
              value={draft}
              onChange={event => setDraft(event.target.value)}
              onKeyDown={event => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  event.currentTarget.form.requestSubmit()
                }
              }}
              rows="1"
              maxLength={65536}
              disabled={!client || !conversation || isWorking}
              placeholder={conversation ? 'Type an end-to-end encrypted message…' : 'Establish an MLS group to start messaging…'}
              className="max-h-24 min-h-9 flex-1 resize-y bg-transparent px-2 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!draft.trim() || !client || !conversation || isWorking}
              aria-label="Encrypt and send message"
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-cyan-300 text-base font-bold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-30"
            >
              ↑
            </button>
          </div>
          <p className="mt-2 text-center text-[9px] text-slate-600">Enter to send · Shift + Enter for a new line · up to 64 KiB per message</p>
        </form>
      </section>

      {showNewChat && (
        <div className="fixed inset-0 z-20 flex items-center justify-center overflow-y-auto bg-black/75 p-5">
          <section aria-labelledby="new-chat-title" className="my-auto w-full max-w-xl border border-white/10 bg-[#10141d] p-5 shadow-2xl">
            <div className="mb-5 flex items-start justify-between">
              <div>
                <h2 id="new-chat-title" className="text-sm font-semibold text-white">
                  {newChatMode === 'start' ? 'Invite a contact' : 'Join an encrypted chat'}
                </h2>
                <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
                  Bundles travel out of band. Fingerprint signatures prove bundle authorship, not the real-world identity of the account.
                </p>
              </div>
              <button type="button" onClick={() => setShowNewChat(false)} aria-label="Close dialog" className="text-slate-500 hover:text-white">✕</button>
            </div>

            <div className="mb-4 flex gap-2">
              <button type="button" onClick={() => resetBundleDialog('start')} className={`border px-3 py-2 text-[9px] ${newChatMode === 'start' ? 'border-cyan-300/50 text-cyan-200' : 'border-white/10 text-slate-500'}`}>
                INVITE FROM CONTACT CARD
              </button>
              <button type="button" onClick={() => resetBundleDialog('join')} className={`border px-3 py-2 text-[9px] ${newChatMode === 'join' ? 'border-cyan-300/50 text-cyan-200' : 'border-white/10 text-slate-500'}`}>
                JOIN FROM INVITATION
              </button>
            </div>

            <label htmlFor="peer-bundle" className="mb-2 block text-[10px] tracking-wide text-slate-400">
              {newChatMode === 'start' ? 'PEER SIGNED CONTACT CARD JSON' : 'SIGNED MLS INVITATION JSON'}
            </label>
            <textarea
              id="peer-bundle"
              autoFocus
              value={bundleInput}
              onChange={event => {
                setBundleInput(event.target.value)
                setVerifiedPeer(null)
              }}
              rows="7"
              maxLength={200000}
              placeholder={newChatMode === 'start' ? 'Paste the contact card shared by your peer…' : 'Paste the signed invitation shared by your peer…'}
              className="w-full resize-y border border-white/10 bg-black/20 p-3 text-[10px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-300/40"
            />
            {!verifiedPeer ? (
              <button type="button" onClick={handleVerifyBundle} disabled={!bundleInput.trim()} className="mt-3 w-full border border-cyan-500/50 py-2.5 text-[10px] tracking-wide text-cyan-200 hover:bg-cyan-400/[0.07] disabled:opacity-40">
                VERIFY BUNDLE SIGNATURE
              </button>
            ) : (
              <div className="mt-4 border border-amber-300/15 bg-amber-300/[0.035] p-3">
                <p className="text-[10px] text-slate-300">Bundle signed for <span className="text-cyan-200">@{verifiedPeer.handle}</span></p>
                <p className="mt-2 break-all text-[10px] leading-relaxed text-amber-100">
                  ACCOUNT FINGERPRINT: {accountFingerprint(verifiedPeer.accountPublicKey)}
                </p>
                <p className="mt-2 text-[9px] leading-relaxed text-amber-100/70">
                  Compare this full fingerprint with the person through a separate trusted channel. Do not proceed based only on the pasted bundle.
                </p>
                <label htmlFor="fingerprint-confirmation" className="mb-2 mt-3 block text-[9px] tracking-wide text-slate-400">TYPE THE VERIFIED FINGERPRINT</label>
                <input
                  id="fingerprint-confirmation"
                  value={fingerprintConfirmation}
                  onChange={event => setFingerprintConfirmation(event.target.value)}
                  autoComplete="off"
                  className="w-full border border-white/10 bg-black/20 px-3 py-2 text-[10px] text-slate-200 outline-none focus:border-cyan-300/40"
                />
                <button
                  type="button"
                  onClick={newChatMode === 'start' ? handleStartConversation : handleJoinConversation}
                  disabled={!client || isWorking || (networkConfig?.mode === 'tor' && torStatus.state !== 'connected') || normalizeFingerprint(fingerprintConfirmation) !== normalizeFingerprint(accountFingerprint(verifiedPeer.accountPublicKey))}
                  className="mt-3 w-full border border-green-400/40 py-2.5 text-[10px] tracking-wide text-green-200 hover:bg-green-400/[0.07] disabled:opacity-40"
                >
                  {isWorking ? `CONNECTING ${networkConfig?.mode === 'tor' ? 'THROUGH TOR' : 'TO LOOPBACK RELAY'}…` : newChatMode === 'start' ? 'VERIFY FINGERPRINT, CREATE INVITE & CONNECT' : 'VERIFY FINGERPRINT & JOIN'}
                </button>
              </div>
            )}
          </section>
        </div>
      )}

      {showRecoveryKey && (
        <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/80 p-6">
          <section aria-labelledby="recovery-key-title" className="w-full max-w-lg border border-amber-500/50 bg-[#10141d] p-5 shadow-2xl">
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h2 id="recovery-key-title" className="text-sm font-semibold text-amber-200">Account recovery key</h2>
                <p className="mt-2 text-[10px] leading-relaxed text-amber-100/70">
                  This key contains the account’s private signing and encryption keys. Anyone who gets it can control the account. Store it somewhere offline and never send it in chat.
                </p>
              </div>
              <button type="button" onClick={() => setShowRecoveryKey(false)} aria-label="Close recovery key" className="text-slate-500 hover:text-white">✕</button>
            </div>
            <textarea
              readOnly
              rows={3}
              value={recoveryKey}
              aria-label="Account recovery key"
              className="w-full resize-y border border-amber-500/30 bg-black/30 p-3 text-xs text-amber-100 outline-none"
            />
            <div className="mt-3 flex items-center justify-between gap-3">
              <p role="status" className="text-[9px] text-slate-500">
                {recoveryKeyCopied ? 'Copied. Keep this secret offline.' : 'Use this key with your account handle to recover on a new install.'}
              </p>
              <button onClick={copyRecoveryKey} className="border border-amber-400/40 px-4 py-2 text-[9px] tracking-wide text-amber-200 hover:bg-amber-400/10">
                COPY KEY
              </button>
            </div>
          </section>
        </div>
      )}
    </main>
  )
}

export default ChatScreen
