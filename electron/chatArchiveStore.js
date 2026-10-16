import { createHash } from 'node:crypto'
import { mkdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { decryptChatArchive, encryptChatArchive } from './identityVault.js'

const MAX_ENCRYPTED_ARCHIVE_BYTES = 64 * 1024 * 1024

export function createChatArchiveStore({ userDataPath, safeStorage, writeAtomically, platform }) {
  const legacyPath = join(userDataPath, 'chat-history.json')
  const archiveDirectory = join(userDataPath, 'chat-history')
  const pendingWrites = new Map()

  function getArchivePath(ownerPublicKey) {
    if (typeof ownerPublicKey !== 'string' || !/^[0-9a-f]{64}$/iu.test(ownerPublicKey)) {
      throw new Error('Chat archive owner key is invalid')
    }
    const archiveId = createHash('sha256').update(ownerPublicKey.toLowerCase()).digest('hex')
    return join(archiveDirectory, `${archiveId}.json`)
  }

  async function readEncryptedArchive(filePath) {
    const { size } = await stat(filePath)
    if (size > MAX_ENCRYPTED_ARCHIVE_BYTES) {
      throw new Error('Encrypted chat archive exceeds the 64 MiB limit')
    }
    return readFile(filePath)
  }

  async function save(archive, passphrase) {
    const filePath = getArchivePath(archive?.ownerPublicKey)
    const previousWrite = pendingWrites.get(filePath) || Promise.resolve()
    const write = previousWrite.catch(() => {}).then(async () => {
      const encrypted = await encryptChatArchive(archive, { safeStorage, passphrase, platform })
      await writeAtomically(filePath, encrypted)
    })
    pendingWrites.set(filePath, write)
    try {
      await write
    } finally {
      if (pendingWrites.get(filePath) === write) pendingWrites.delete(filePath)
    }
  }

  async function load(ownerPublicKey, passphrase) {
    const filePath = getArchivePath(ownerPublicKey)
    await pendingWrites.get(filePath)
    try {
      const encrypted = await readEncryptedArchive(filePath)
      return await decryptChatArchive(encrypted, { safeStorage, passphrase, platform })
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }

    let legacyEncrypted
    try {
      legacyEncrypted = await readEncryptedArchive(legacyPath)
    } catch (error) {
      if (error.code === 'ENOENT') return null
      throw error
    }
    const legacyArchive = await decryptChatArchive(legacyEncrypted, { safeStorage, passphrase, platform })
    if (legacyArchive.ownerPublicKey.toLowerCase() !== ownerPublicKey.toLowerCase()) return null

    await mkdir(archiveDirectory, { recursive: true, mode: 0o700 })
    await writeAtomically(filePath, legacyEncrypted)
    return legacyArchive
  }

  return { load, save }
}
