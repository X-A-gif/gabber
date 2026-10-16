import { app, BrowserWindow, dialog, ipcMain, safeStorage, session } from 'electron'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { configureSessionProxy, resolveNetworkConfig } from './torConfig.js'
import { createManagedTor } from './managedTor.js'
import { createChatArchiveStore } from './chatArchiveStore.js'
import {
  decryptIdentityVault,
  encryptIdentityVault,
  identityStorageMode,
  validateIdentity,
} from './identityVault.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Where we store the identity
const identityPath = path.join(app.getPath('userData'), 'identity.json')
let networkConfig
let torManager
let torStatus
let torShutdownStarted = false

async function writeAtomically(filePath, data, mode = 0o600) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 })
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`
  try {
    await fsp.writeFile(temporaryPath, data, { flag: 'wx', mode })
    const fileHandle = await fsp.open(temporaryPath, 'r')
    try {
      await fileHandle.sync()
    } finally {
      await fileHandle.close()
    }
    await fsp.rename(temporaryPath, filePath)
    if (process.platform !== 'win32') {
      const directoryHandle = await fsp.open(path.dirname(filePath), 'r')
      try {
        await directoryHandle.sync()
      } finally {
        await directoryHandle.close()
      }
    }
  } catch (error) {
    await fsp.rm(temporaryPath, { force: true })
    throw error
  }
}

const chatArchiveStore = createChatArchiveStore({
  userDataPath: app.getPath('userData'),
  safeStorage,
  writeAtomically,
  platform: process.platform,
})

async function writeIdentityVault(data, passphrase) {
  const encrypted = await encryptIdentityVault(data, { safeStorage, passphrase })
  await writeAtomically(identityPath, encrypted)
}

function isEncryptedVault(value) {
  return value && value.format === 'gabber-identity-vault'
}

ipcMain.handle('get-identity-storage-info', async () => {
  try {
    let needsMigration = false
    let hasIdentity = false
    let storage = identityStorageMode(safeStorage)
    try {
      const bytes = await fsp.readFile(identityPath)
      hasIdentity = true
      try {
        const envelope = JSON.parse(bytes.toString('utf8'))
        needsMigration = !isEncryptedVault(envelope)
        if (!needsMigration && envelope.backend === 'passphrase-scrypt-aes-256-gcm') {
          storage.mode = 'passphrase'
        } else if (!needsMigration && envelope.backend === 'safeStorage') {
          storage.mode = 'safeStorage'
        } else if (!needsMigration) {
          needsMigration = true
        }
      } catch {
        needsMigration = true
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    return {
      success: true,
      data: {
        ...storage,
        hasIdentity,
        needsMigration,
        backendDescription: storage.mode === 'safeStorage'
          ? hasIdentity
            ? `Protected by ${storage.backend}`
            : 'New accounts use a device-local passphrase'
          : hasIdentity
            ? 'Protected by this device vault passphrase'
            : 'A local passphrase will protect this device vault',
      },
    }
  } catch (error) {
    return { success: false, error: error.message }
  }
})

ipcMain.handle('save-identity', async (event, data, passphrase) => {
  try {
    const identity = validateIdentity(data)
    if (fs.existsSync(identityPath)) {
      const confirmation = await dialog.showMessageBox(BrowserWindow.fromWebContents(event.sender), {
        type: 'warning',
        title: 'Replace saved identity?',
        message: 'Saving this identity will replace the identity currently saved on this device.',
        buttons: ['Cancel', 'Replace identity'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      })
      if (confirmation.response !== 1) return { success: false, cancelled: true }
    }
    await writeIdentityVault(identity, passphrase)
    return { success: true }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('load-identity', async (_event, passphrase) => {
  try {
    const encryptedVault = await fsp.readFile(identityPath)
    let parsed
    try {
      parsed = JSON.parse(encryptedVault.toString('utf8'))
    } catch {
      parsed = null
    }

    if (isEncryptedVault(parsed)) {
      const data = await decryptIdentityVault(encryptedVault, { safeStorage, passphrase })
      return { success: true, data }
    }

    const data = validateIdentity(parsed)
    await writeIdentityVault(data, passphrase)
    return { success: true, data, migrated: true }
  } catch (err) {
    if (err.code === 'ENOENT') return { success: false, error: 'No identity found' }
    return { success: false, error: err.message }
  }
})

ipcMain.handle('save-chat-archive', async (_event, archive, passphrase) => {
  try {
    await chatArchiveStore.save(archive, passphrase)
    return { success: true }
  } catch (error) {
    return { success: false, error: error.message }
  }
})

ipcMain.handle('load-chat-archive', async (_event, ownerPublicKey, passphrase) => {
  try {
    const archive = await chatArchiveStore.load(ownerPublicKey, passphrase)
    return { success: true, data: archive }
  } catch (error) {
    return { success: false, error: error.message }
  }
})

ipcMain.handle('load-mls-wasm', async () => {
  try {
    let wasmPath
    if (process.env.VITE_DEV_SERVER_URL) {
      wasmPath = path.join(__dirname, '../crypto/pkg/gabber_mls_bg.wasm')
    } else {
      const assetDirectory = path.join(__dirname, '../dist/assets')
      const wasmAssets = fs.readdirSync(assetDirectory)
        .filter(file => /^gabber_mls_bg-[A-Za-z0-9_-]+\.wasm$/u.test(file))
      if (wasmAssets.length !== 1) {
        throw new Error(`Expected one bundled MLS WebAssembly asset, found ${wasmAssets.length}`)
      }
      wasmPath = path.join(assetDirectory, wasmAssets[0])
    }

    return { success: true, data: new Uint8Array(fs.readFileSync(wasmPath)) }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('get-network-config', () => ({
  mode: networkConfig.mode,
  relayUrl: networkConfig.relayUrl,
  torStatus,
}))

ipcMain.on('tor-status-subscribe', event => {
  if (event.senderFrame === event.sender.mainFrame) {
    event.sender.send('tor-status', torStatus)
  }
})

const createWindow = () => {
  const win = new BrowserWindow({
    width: 900,
    height: 520,
    resizable: true,
      icon: path.join(__dirname, '../public/gabber.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.mjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })
  win.removeMenu()
  // Force open DevTools every time
  win.webContents.openDevTools({ mode: 'detach' })

  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL)
  } else {
    win.loadFile(path.join(__dirname, '../dist/index.html'))
  }
}

app.whenReady().then(async () => {
  try {
    networkConfig = resolveNetworkConfig()
    torManager = createManagedTor({
      dataDirectory: path.join(app.getPath('userData'), 'tor'),
      onStatus: status => {
        torStatus = status
        for (const win of BrowserWindow.getAllWindows()) {
          win.webContents.send('tor-status', status)
        }
      },
    })
    const torRuntime = await torManager.start()
    torStatus = torRuntime.status
    if (networkConfig.mode === 'tor') {
      networkConfig = { ...networkConfig, socksProxy: torRuntime.socksProxy }
    }
    await configureSessionProxy(
      networkConfig,
      session.defaultSession,
      process.env.VITE_DEV_SERVER_URL,
    )
  } catch (error) {
    dialog.showErrorBox('Gabber network configuration failed closed', error.message)
    app.quit()
    return
  }

  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
}).catch(error => {
  dialog.showErrorBox('Gabber failed to start', error.message)
  app.quit()
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('before-quit', event => {
  if (!torManager || torShutdownStarted) return
  event.preventDefault()
  torShutdownStarted = true
  torManager.stop().then(
    () => app.quit(),
    error => {
      console.error('Failed to stop managed Tor process:', error)
      app.quit()
    },
  )
})