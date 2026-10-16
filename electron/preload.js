const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  getIdentityStorageInfo: () => ipcRenderer.invoke('get-identity-storage-info'),
  saveIdentity: (data, passphrase) => ipcRenderer.invoke('save-identity', data, passphrase),
  loadIdentity: passphrase => ipcRenderer.invoke('load-identity', passphrase),
  saveChatArchive: (archive, passphrase) => ipcRenderer.invoke('save-chat-archive', archive, passphrase),
  loadChatArchive: (ownerPublicKey, passphrase) => ipcRenderer.invoke('load-chat-archive', ownerPublicKey, passphrase),
  loadMlsWasm: () => ipcRenderer.invoke('load-mls-wasm'),
  getNetworkConfig: () => ipcRenderer.invoke('get-network-config'),
  onTorStatus: callback => {
    const listener = (_event, status) => callback(status)
    ipcRenderer.on('tor-status', listener)
    ipcRenderer.send('tor-status-subscribe')
    return () => ipcRenderer.removeListener('tor-status', listener)
  },
})

console.log('✅ Preload loaded successfully')