import { useEffect, useState } from 'react'
import { fingerprint, generateRecoveryIdentity, recoverIdentity } from './lib/identity'
import ChatScreen from './components/ChatScreen'
import IdentityScreen from './components/IdentityScreen'

function App() {
  const [handle, setHandle] = useState('gabber')
  const [identity, setIdentity] = useState(null)
  const [status, setStatus] = useState({ type: 'idle', message: 'Ready.' })
  const [showTrace, setShowTrace] = useState(false)
  const [logs, setLogs] = useState([])
  const [isGenerating, setIsGenerating] = useState(false)
  const [isUnlocking, setIsUnlocking] = useState(false)
  const [isChatOpen, setIsChatOpen] = useState(false)
  const [storageInfo, setStorageInfo] = useState(null)
  const [vaultPassphrase, setVaultPassphrase] = useState('')
  const [sessionVaultPassphrase, setSessionVaultPassphrase] = useState('')
  const [vaultPassphraseConfirmation, setVaultPassphraseConfirmation] = useState('')
  const [isNewIdentity, setIsNewIdentity] = useState(false)
  const [isRecoveringIdentity, setIsRecoveringIdentity] = useState(false)
  const [recoveryKey, setRecoveryKey] = useState('')

  const addLog = (type, message) => {
    setLogs(prev => [...prev, { type, message, time: new Date().toLocaleTimeString() }])
  }

  useEffect(() => {
    async function checkIdentity() {
      try {
        const result = await window.electronAPI.getIdentityStorageInfo()
        if (!result.success) throw new Error(result.error)
        setStorageInfo(result.data)
        if (result.data.hasIdentity) {
          setStatus({
            type: 'idle',
            message: result.data.needsMigration
              ? 'Legacy identity found. Unlock to protect it in the local vault.'
              : 'Protected identity found on this device.',
          })
        }
      } catch (err) {
        setStatus({ type: 'error', message: `Failed to check saved identity: ${err.message}` })
      }
    }
    checkIdentity()
  }, [])

  const handleNewKeypair = async () => {
    if (isGenerating) return

    setIsGenerating(true)
    setLogs([])
    setShowTrace(true)
    setStatus({ type: 'loading', message: 'Generating identity...' })
    addLog('init', 'Generating fresh Ed25519 + X25519 keypairs locally...')

    try {
      await new Promise(resolve => setTimeout(resolve, 400))
      const generated = await generateRecoveryIdentity(handle)
      const newIdentity = generated.identity

      addLog('success', 'Account keys generated locally; recovery key is shown below')
      addLog('pub', `sign-fp = ${fingerprint(newIdentity.publicKeySign)}`)
      addLog('pub', `enc-fp  = ${fingerprint(newIdentity.publicKeyEnc)}`)
      addLog('success', 'Keypair ready. You can now save it.')

      setIdentity(newIdentity)
      setRecoveryKey(generated.recoveryKey)
      setIsNewIdentity(true)
      setStatus({ type: 'success', message: 'New identity generated' })
    } catch (err) {
      addLog('error', err.message)
      setStatus({ type: 'error', message: 'Failed to generate identity' })
    } finally {
      setIsGenerating(false)
    }
  }

  const handleSave = async () => {
    if (!identity) return
    if (isNewIdentity && !recoveryKey) {
      setStatus({ type: 'error', message: 'Generate a recovery key before saving this account' })
      return
    }
    if ((isNewIdentity || isRecoveringIdentity) &&
      (vaultPassphrase.length < 12 || vaultPassphrase !== vaultPassphraseConfirmation)) {
      setStatus({ type: 'error', message: 'Set and confirm a local passphrase of at least 12 characters' })
      return
    }

    addLog('init', 'Saving identity to disk...')
    const payload = { handle, ...identity }

    try {
      const result = await window.electronAPI.saveIdentity(payload, vaultPassphrase)
      if (result.cancelled) return
      if (result.success) {
        const lockAfterSave = isNewIdentity || isRecoveringIdentity
        addLog('success', 'Identity saved successfully')
        setStatus({ type: 'success', message: 'Identity saved in encrypted local storage' })
        setVaultPassphrase('')
        setVaultPassphraseConfirmation('')
        setRecoveryKey('')
        setIsNewIdentity(false)
        setIsRecoveringIdentity(false)
        if (lockAfterSave) {
          setIdentity(null)
          setShowTrace(false)
        }
        try {
          const storageResult = await window.electronAPI.getIdentityStorageInfo()
          if (storageResult.success) setStorageInfo(storageResult.data)
        } catch (error) {
          addLog('error', `Identity saved, but storage status could not be refreshed: ${error.message}`)
        }
      } else {
        addLog('error', result.error)
        setStatus({ type: 'error', message: `Failed to save identity: ${result.error}` })
      }
    } catch (err) {
      addLog('error', err.message)
      setStatus({ type: 'error', message: `Failed to save identity: ${err.message}` })
    }
  }

  const handleUnlock = async () => {
    if (isUnlocking) return

    setIsUnlocking(true)
    setLogs([])
    setShowTrace(true)
    setStatus({ type: 'loading', message: 'Unlocking identity...' })
    addLog('init', 'Looking for saved identity on disk...')

    try {
      const result = await window.electronAPI.loadIdentity(vaultPassphrase)

      if (!result.success) {
        addLog('error', result.error || 'No identity found')
        setStatus({ type: 'error', message: result.error || 'No identity found on disk' })
        return
      }

      const loaded = result.data
      addLog('success', `Identity found for @${loaded.handle}`)
      addLog('pub', `sign-fp = ${fingerprint(loaded.publicKeySign)}`)
      addLog('pub', `enc-fp  = ${fingerprint(loaded.publicKeyEnc)}`)
      addLog('success', 'Identity unlocked successfully')
      if (result.migrated) addLog('success', 'Legacy identity migrated to encrypted local storage')

      setHandle(loaded.handle)
      setIdentity(loaded)
      setIsNewIdentity(false)
      setIsRecoveringIdentity(false)
      setVaultPassphrase('')
      setVaultPassphraseConfirmation('')
      setStatus({
        type: 'success',
        message: result.migrated
          ? `Unlocked @${loaded.handle}; local vault encrypted`
          : `Unlocked @${loaded.handle}`,
      })
      setShowTrace(false)
      let unlockedStorageMode = storageInfo?.mode
      try {
        const storageResult = await window.electronAPI.getIdentityStorageInfo()
        if (storageResult.success) {
          setStorageInfo(storageResult.data)
          unlockedStorageMode = storageResult.data.mode
        }
      } catch (error) {
        addLog('error', `Could not refresh local storage status: ${error.message}`)
      }
      setSessionVaultPassphrase(unlockedStorageMode === 'passphrase' ? vaultPassphrase : '')
      setIsChatOpen(true)
    } catch (err) {
      addLog('error', err.message)
      setStatus({ type: 'error', message: `Failed to unlock identity: ${err.message}` })
    } finally {
      setIsUnlocking(false)
    }
  }

  const handleLock = () => {
    setIdentity(null)
    setSessionVaultPassphrase('')
    setIsNewIdentity(false)
    setIsRecoveringIdentity(false)
    setRecoveryKey('')
    setLogs([])
    setShowTrace(false)
    setIsChatOpen(false)
    setVaultPassphrase('')
    setVaultPassphraseConfirmation('')
    setStatus({ type: 'idle', message: 'Identity locked in this session' })
  }

  const handleRecoverIdentity = () => {
    try {
      const restoredIdentity = recoverIdentity(recoveryKey)
      setHandle(restoredIdentity.handle)
      setIdentity(restoredIdentity)
      setIsNewIdentity(false)
      setIsRecoveringIdentity(true)
      setRecoveryKey('')
      setVaultPassphrase('')
      setVaultPassphraseConfirmation('')
      setStatus({ type: 'success', message: `Account key verified for @${restoredIdentity.handle}; set this device's local passphrase and save` })
      setLogs([
        { type: 'success', message: `Recovered account @${restoredIdentity.handle} from its recovery key`, time: new Date().toLocaleTimeString() },
        { type: 'pub', message: `sign-fp = ${fingerprint(restoredIdentity.publicKeySign)}`, time: new Date().toLocaleTimeString() },
        { type: 'pub', message: `enc-fp  = ${fingerprint(restoredIdentity.publicKeyEnc)}`, time: new Date().toLocaleTimeString() },
      ])
      setShowTrace(true)
      return { success: true }
    } catch (error) {
      setStatus({ type: 'error', message: error.message })
      return { success: false, error: error.message }
    }
  }

  if (isChatOpen && identity) {
    return (
      <ChatScreen
        identity={identity}
        vaultPassphrase={sessionVaultPassphrase}
        onLock={handleLock}
      />
    )
  }

  return (
    <IdentityScreen
      handle={handle}
      onHandleChange={setHandle}
      identity={identity}
      isNewIdentity={isNewIdentity}
      isRecoveringIdentity={isRecoveringIdentity}
      recoveryKey={recoveryKey}
      onRecoveryKeyChange={setRecoveryKey}
      onRecoverIdentity={handleRecoverIdentity}
      status={status}
      isGenerating={isGenerating}
      isUnlocking={isUnlocking}
      onGenerate={handleNewKeypair}
      onUnlock={handleUnlock}
      onLock={handleLock}
      showTrace={showTrace}
      logs={logs}
      onCloseTrace={() => setShowTrace(false)}
      onSave={handleSave}
      storageInfo={storageInfo}
      vaultPassphrase={vaultPassphrase}
      onVaultPassphraseChange={setVaultPassphrase}
      vaultPassphraseConfirmation={vaultPassphraseConfirmation}
      onVaultPassphraseConfirmationChange={setVaultPassphraseConfirmation}
    />
  )
}

export default App
