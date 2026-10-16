import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createManagedTor } from './managedTor.js'

class FakeTorProcess extends EventEmitter {
  constructor() {
    super()
    this.stdout = new PassThrough()
    this.stderr = new PassThrough()
    this.exitCode = null
    this.signalCode = null
    queueMicrotask(() => this.emit('spawn'))
  }

  kill(signal) {
    this.signalCode = signal
    this.exitCode = 0
    queueMicrotask(() => this.emit('exit', 0, signal))
    return true
  }
}

test('starts Tor automatically on Linux and reports bootstrap progress', async () => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'gabber-managed-tor-test-'))
  const dataDirectory = path.join(temporaryDirectory, 'tor-state')
  const statuses = []
  let command
  let argumentsList
  let torProcess
  const manager = createManagedTor({
    platform: 'linux',
    dataDirectory,
    reservePort: async () => 49152,
    spawnTor: (executable, args) => {
      command = executable
      argumentsList = args
      torProcess = new FakeTorProcess()
      return torProcess
    },
    onStatus: status => statuses.push(status),
  })

  try {
    const runtime = await manager.start()
    assert.equal(command, 'tor')
    assert.equal(runtime.socksProxy, 'socks5://127.0.0.1:49152')
    assert.ok(argumentsList.includes('--AvoidDiskWrites'))
    assert.ok(argumentsList.includes('--ClientOnly'))
    assert.ok(statuses.some(status => status.state === 'bootstrapping'))

    torProcess.stdout.write('Oct 13 10:00:00.000 [notice] Bootstrapped 45% (requesting_status): Asking for network status\n')
    assert.deepEqual(manager.getStatus(), {
      state: 'bootstrapping',
      progress: 45,
      message: 'Asking for network status',
    })

    torProcess.stdout.write('Oct 13 10:00:01.000 [notice] Bootstrapped 100% (done): Done\n')
    assert.equal(manager.getStatus().state, 'connected')
    assert.equal(manager.getStatus().progress, 100)
  } finally {
    await manager.stop()
    assert.equal((await stat(dataDirectory)).isDirectory(), true)
    await rm(temporaryDirectory, { recursive: true, force: true })
  }
})

test('reports unavailable Tor cleanly on unsupported platforms', async () => {
  const manager = createManagedTor({ platform: 'win32' })
  const runtime = await manager.start()
  assert.equal(runtime.status.state, 'unavailable')
  assert.match(runtime.status.message, /Linux/u)
})

test('reports when the Tor executable cannot be started', async () => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'gabber-managed-tor-test-'))
  const dataDirectory = path.join(temporaryDirectory, 'tor-state')
  const manager = createManagedTor({
    platform: 'linux',
    dataDirectory,
    reservePort: async () => 49153,
    spawnTor: () => { throw new Error('spawn tor ENOENT') },
  })

  try {
    const runtime = await manager.start()
    assert.equal(runtime.status.state, 'error')
    assert.match(runtime.status.message, /ENOENT/u)
    assert.equal((await stat(dataDirectory)).isDirectory(), true)
  } finally {
    await manager.stop()
    await rm(temporaryDirectory, { recursive: true, force: true })
  }
})
