import { useState } from 'react'

function IdentityScreen({
  handle,
  onHandleChange,
  identity,
  isNewIdentity,
  isRecoveringIdentity,
  recoveryKey,
  onRecoveryKeyChange,
  onRecoverIdentity,
  status,
  isGenerating,
  isUnlocking,
  onGenerate,
  onUnlock,
  onLock,
  showTrace,
  logs,
  onCloseTrace,
  onSave,
  storageInfo,
  vaultPassphrase,
  onVaultPassphraseChange,
  vaultPassphraseConfirmation,
  onVaultPassphraseConfirmationChange,
}) {
  const [acknowledgedRecoveryKey, setAcknowledgedRecoveryKey] = useState('')
  const [recoveryKeyCopyError, setRecoveryKeyCopyError] = useState('')
  const [showRecoveryDialog, setShowRecoveryDialog] = useState(false)
  const [recoveryError, setRecoveryError] = useState('')

  const submitRecovery = event => {
    event.preventDefault()
    const result = onRecoverIdentity()
    if (result?.success) {
      setRecoveryError('')
      setShowRecoveryDialog(false)
    } else {
      setRecoveryError(result?.error || 'Could not recover the account from this key.')
    }
  }

  return (
    <main className="terminal-screen relative flex h-screen items-center justify-center overflow-y-auto bg-[#090b10] p-6 font-mono text-slate-300">
      <div className="terminal-login-window w-full max-w-md space-y-6">
        <div className="terminal-windowbar flex items-center justify-between border-b border-white/[0.08] px-4 py-3">
          <div className="flex gap-1.5" aria-hidden="true">
            <span className="h-2 w-2 rounded-full bg-red-400/70" />
            <span className="h-2 w-2 rounded-full bg-amber-300/70" />
            <span className="h-2 w-2 rounded-full bg-green-400/70" />
          </div>
          <span className="text-[10px] tracking-[0.16em] text-slate-500">gabber — identity console</span>
          <span className="text-[10px] text-green-400/80">TTY 01</span>
        </div>
        <div className="px-6 pb-6 pt-2">
          <div className="flex justify-center">
            <img src="/gabber.png" alt="Gabber" className="h-16 w-full max-w-72 object-contain" />
          </div>
          <p className="terminal-command mb-5 mt-1 text-xs"><span className="text-green-400">gabber@local</span><span className="text-slate-500">:~$</span> identity --status</p>

          <div>
            <label htmlFor="operator-handle" className="mb-2 block text-[11px] tracking-[0.2em] text-slate-500">OPERATOR HANDLE</label>
            <input
              id="operator-handle"
              type="text"
              value={handle}
              onChange={event => onHandleChange(event.target.value)}
              className="terminal-input w-full rounded-sm border border-cyan-500/70 bg-transparent px-4 py-3 text-sm text-cyan-300 outline-none focus:border-cyan-400"
            />
          </div>

          <div className="border border-white/[0.08] p-3 text-[11px] leading-relaxed text-slate-400">
            <p className="text-cyan-300">LOCAL KEY STORAGE // {storageInfo?.backendDescription || 'Checking available protection...'}</p>
            {storageInfo?.mode === 'passphrase' && !identity && (
              <>
                <label htmlFor="vault-passphrase" className="mb-2 mt-3 block tracking-[0.15em] text-slate-500">
                  DEVICE VAULT PASSPHRASE (12+ CHARACTERS)
                </label>
                <input
                  id="vault-passphrase"
                  type="password"
                  autoComplete="current-password"
                  value={vaultPassphrase}
                  onChange={event => onVaultPassphraseChange(event.target.value)}
                  className="terminal-input w-full rounded-sm border border-cyan-500/50 bg-transparent px-3 py-2 text-sm text-cyan-200 outline-none focus:border-cyan-400"
                />
              </>
            )}
            {storageInfo?.needsMigration && (
              <p className="mt-2 text-amber-300">A legacy unencrypted identity will be encrypted when you unlock it.</p>
            )}
          </div>

          <div className="border-t border-white/[0.08] pt-3">
            <button
              type="button"
              onClick={() => {
                setRecoveryError('')
                onRecoveryKeyChange('')
                setShowRecoveryDialog(true)
              }}
              className="w-full border border-amber-500/70 py-2 text-[10px] tracking-wider text-amber-200 hover:bg-amber-500/10 disabled:opacity-40"
            >
              RESTORE FROM KEY
            </button>
          </div>

          <div className="flex flex-col gap-3">
            <button
              onClick={onGenerate}
              disabled={isGenerating}
              className="terminal-action w-full border border-fuchsia-500 py-3 text-sm tracking-wider text-fuchsia-400 transition-colors hover:bg-fuchsia-500/10 disabled:opacity-50"
            >
              {isGenerating ? 'GENERATING...' : 'NEW KEYPAIR'}
            </button>
            <button
              onClick={onUnlock}
              disabled={!storageInfo || isUnlocking || (storageInfo.mode === 'passphrase' && vaultPassphrase.length < 12)}
              className="terminal-action w-full border border-cyan-500 py-3 text-sm tracking-wider text-cyan-400 transition-colors hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {isUnlocking ? 'UNLOCKING...' : 'UNLOCK & PROVE'}
            </button>
          </div>

          <div className="border-t border-white/[0.08] pt-4">
            <p className={`text-sm ${
              status.type === 'success' ? 'text-green-400' :
                status.type === 'error' ? 'text-fuchsia-400' :
                  status.type === 'loading' ? 'text-yellow-400' :
                    'text-slate-400'
            }`}>
              {status.message}
            </p>
            {identity && (
              <button
                onClick={onLock}
                className="mt-3 text-[10px] tracking-wider text-slate-500 transition hover:text-slate-200"
              >
                LOCK IDENTITY
              </button>
            )}
          </div>
        </div>
      </div>

      {showTrace && (
        <div className="fixed inset-0 z-10 flex items-center justify-center overflow-y-auto bg-black/75 p-6">
          <div className="my-auto max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-sm border border-gray-700 bg-[#0d0d14] shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
              <span className="text-xs tracking-wider text-gray-400">ZKP.TRACE // Σ-PROTOCOL</span>
              <button
                onClick={onCloseTrace}
                disabled={isNewIdentity || isRecoveringIdentity}
                aria-label="Close trace"
                className="px-2 text-sm text-gray-500 hover:text-white disabled:cursor-not-allowed disabled:opacity-30"
              >
                ✕
              </button>
            </div>
            <div className="h-64 space-y-1.5 overflow-y-auto p-4 text-[13px]">
              {logs.map((log, index) => (
                <p key={`${log.time}-${index}`} className={
                  log.type === 'success' ? 'text-green-400' :
                    log.type === 'pub' ? 'text-cyan-300' :
                      log.type === 'error' ? 'text-fuchsia-400' : 'text-gray-300'
                }>
                  <span className="text-gray-500">[{log.type === 'success' ? 'init' : log.type}]</span> {log.message}
                </p>
              ))}
            </div>
            {identity && (
              <div className="flex flex-col gap-3 border-t border-gray-800 px-4 py-3">
                {(isNewIdentity || isRecoveringIdentity) && (
                  <div className="w-full space-y-3 text-left">
                    {isNewIdentity && (
                      <div className="space-y-2">
                        <label htmlFor="account-recovery-display" className="block text-[10px] tracking-wider text-amber-300">
                          ACCOUNT RECOVERY KEY // KEEP OFFLINE
                        </label>
                        <div className="flex gap-2">
                          <textarea
                            id="account-recovery-display"
                            readOnly
                            rows={2}
                            value={recoveryKey}
                            className="min-w-0 flex-1 resize-y border border-amber-500/40 bg-black/20 p-2 text-[10px] text-amber-100"
                          />
                          <button
                            type="button"
                            onClick={async () => {
                              try {
                                await navigator.clipboard.writeText(recoveryKey)
                                setAcknowledgedRecoveryKey(recoveryKey)
                                setRecoveryKeyCopyError('')
                              } catch (error) {
                                setRecoveryKeyCopyError(`Copy failed: ${error.message}. You can select the key and copy it manually.`)
                              }
                            }}
                            className="border border-amber-500/40 px-3 text-[9px] text-amber-200 hover:bg-amber-500/10"
                          >
                            COPY
                          </button>
                        </div>
                        {recoveryKeyCopyError && <p role="alert" className="text-[9px] text-fuchsia-300">{recoveryKeyCopyError}</p>}
                        <label className="flex items-start gap-2 text-[9px] leading-relaxed text-slate-400">
                          <input
                            type="checkbox"
                            checked={acknowledgedRecoveryKey === recoveryKey}
                            onChange={event => setAcknowledgedRecoveryKey(event.target.checked ? recoveryKey : '')}
                            className="mt-0.5 accent-amber-300"
                          />
                          I saved this recovery key somewhere safe. Anyone with it can control this account.
                        </label>
                      </div>
                    )}

                    <div className="border-t border-white/[0.08] pt-3">
                      <label htmlFor="new-local-passphrase" className="mb-2 block text-[10px] tracking-wider text-slate-500">
                        {isNewIdentity ? 'NEW DEVICE-LOCAL PASSPHRASE (12+ CHARACTERS)' : 'NEW PASSPHRASE FOR THIS DEVICE (12+ CHARACTERS)'}
                      </label>
                      <input
                        id="new-local-passphrase"
                        type="password"
                        autoComplete="new-password"
                        minLength={12}
                        maxLength={1024}
                        value={vaultPassphrase}
                        onChange={event => onVaultPassphraseChange(event.target.value)}
                        className="terminal-input w-full rounded-sm border border-cyan-500/50 bg-transparent px-3 py-2 text-sm text-cyan-200 outline-none focus:border-cyan-400"
                      />
                      <label htmlFor="new-local-passphrase-confirmation" className="mb-2 mt-3 block text-[10px] tracking-wider text-slate-500">
                        CONFIRM DEVICE-LOCAL PASSPHRASE
                      </label>
                      <input
                        id="new-local-passphrase-confirmation"
                        type="password"
                        autoComplete="new-password"
                        minLength={12}
                        maxLength={1024}
                        value={vaultPassphraseConfirmation}
                        onChange={event => onVaultPassphraseConfirmationChange(event.target.value)}
                        className="terminal-input w-full rounded-sm border border-cyan-500/50 bg-transparent px-3 py-2 text-sm text-cyan-200 outline-none focus:border-cyan-400"
                      />
                    </div>
                  </div>
                )}
                <button
                  type="button"
                  onClick={onSave}
                  disabled={
                    !storageInfo ||
                    ((isNewIdentity || isRecoveringIdentity) &&
                      (vaultPassphrase.length < 12 ||
                        vaultPassphrase !== vaultPassphraseConfirmation ||
                        (isNewIdentity && acknowledgedRecoveryKey !== recoveryKey))) ||
                    (!isNewIdentity && !isRecoveringIdentity &&
                      storageInfo.mode === 'passphrase' && vaultPassphrase.length < 12)
                  }
                  className="self-end border border-cyan-500 px-4 py-2 text-xs tracking-wider text-cyan-400 hover:bg-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  SAVE IDENTITY
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {showRecoveryDialog && (
        <div className="fixed inset-0 z-20 flex items-center justify-center overflow-y-auto bg-black/80 p-6">
          <form
            onSubmit={submitRecovery}
            role="dialog"
            aria-modal="true"
            aria-labelledby="account-recovery-title"
            className="my-auto w-full max-w-lg border border-amber-500/50 bg-[#0d0d14] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/[0.08] px-4 py-3">
              <h2 id="account-recovery-title" className="text-xs tracking-wider text-amber-200">RESTORE ACCOUNT FROM KEY</h2>
              <button
                type="button"
                onClick={() => setShowRecoveryDialog(false)}
                aria-label="Close recovery dialog"
                className="px-2 text-sm text-slate-500 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3 p-4">
              <p className="text-[10px] leading-relaxed text-slate-400">
                Paste your account recovery key. No backup file is needed. After the key is verified, set a new passphrase for this device.
              </p>
              <label htmlFor="account-recovery-key" className="block text-[10px] tracking-wider text-slate-500">
                ACCOUNT RECOVERY KEY
              </label>
              <textarea
                id="account-recovery-key"
                autoFocus
                value={recoveryKey}
                onChange={event => {
                  onRecoveryKeyChange(event.target.value.replaceAll(/\s/gu, ''))
                  setRecoveryError('')
                }}
                rows={3}
                autoComplete="off"
                spellCheck={false}
                className="w-full resize-y border border-amber-500/40 bg-black/20 p-3 text-xs text-amber-100 outline-none focus:border-amber-300"
                placeholder="Paste your 136-character recovery key"
              />
              {recoveryError && <p role="alert" className="text-[10px] text-fuchsia-300">{recoveryError}</p>}
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowRecoveryDialog(false)}
                  className="border border-white/15 px-4 py-2 text-[10px] tracking-wider text-slate-400 hover:bg-white/[0.04]"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={!recoveryKey}
                  className="border border-amber-500/70 px-4 py-2 text-[10px] tracking-wider text-amber-200 hover:bg-amber-500/10 disabled:opacity-40"
                >
                  RESTORE ACCOUNT
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

    </main>
  )
}

export default IdentityScreen
