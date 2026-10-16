import { spawn } from 'node:child_process'
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import net from 'node:net'
import path from 'node:path'

function reserveLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(error => error ? reject(error) : resolve(port))
    })
  })
}

export function createManagedTor({
  platform = process.platform,
  spawnTor = spawn,
  reservePort = reserveLoopbackPort,
  dataDirectory,
  onStatus = () => {},
} = {}) {
  let child
  let childSpawned = false
  let stopping = false
  let status = {
    state: platform === 'linux' ? 'starting' : 'unavailable',
    progress: 0,
    message: platform === 'linux' ? 'Starting Tor automatically…' : 'Automatic Tor is currently supported on Linux.',
  }

  const publishStatus = nextStatus => {
    status = { ...status, ...nextStatus }
    onStatus({ ...status })
  }

  const handleOutput = line => {
    const match = line.match(/Bootstrapped\s+(\d+)%\s*\(([^)]+)\):\s*(.*)/u)
    if (!match) return
    const progress = Number(match[1])
    publishStatus({
      state: progress === 100 ? 'connected' : 'bootstrapping',
      progress,
      message: match[3].trim() || match[2],
    })
  }

  async function start() {
    if (platform !== 'linux') {
      publishStatus({
        state: 'unavailable',
        progress: 0,
        message: 'Automatic Tor is currently supported on Linux.',
      })
      return { socksProxy: 'socks5://127.0.0.1:9', status: { ...status } }
    }

    let port
    try {
      port = await reservePort()
      if (!dataDirectory) throw new Error('A private Tor data directory is required')
      await mkdir(dataDirectory, { recursive: true, mode: 0o700 })
      await chmod(dataDirectory, 0o700)
      const torrcPath = path.join(dataDirectory, 'torrc')
      await writeFile(torrcPath, '', { mode: 0o600 })
      publishStatus({ state: 'starting', progress: 0, message: 'Starting Tor automatically…' })
      child = spawnTor('tor', [
        '-f',
        torrcPath,
        '--SocksPort',
        `127.0.0.1:${port}`,
        '--DataDirectory',
        dataDirectory,
        '--ClientOnly',
        '1',
        '--Log',
        'notice stdout',
        '--AvoidDiskWrites',
        '1',
      ], { stdio: ['ignore', 'pipe', 'pipe'] })

      const stdout = createInterface({ input: child.stdout })
      const stderr = createInterface({ input: child.stderr })
      stdout.on('line', handleOutput)
      stderr.on('line', handleOutput)
      stderr.on('line', line => {
        if (/fatal|error|failed/iu.test(line)) {
          publishStatus({
            state: 'error',
            progress: 0,
            message: `Tor reported an error: ${line.slice(0, 200)}`,
          })
        }
      })
      child.on('error', error => {
        if (!stopping) {
          publishStatus({ state: 'error', progress: 0, message: `Could not start Tor: ${error.message}` })
        }
      })
      child.on('exit', (code, signal) => {
        childSpawned = false
        if (!stopping) {
          if (status.state === 'error') return
          publishStatus({
            state: 'error',
            progress: 0,
            message: `Tor stopped unexpectedly (${signal || `exit code ${code}`}).`,
          })
        }
      })

      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Timed out starting the Tor process')), 5000)
        child.once('spawn', () => {
          childSpawned = true
          clearTimeout(timer)
          resolve()
        })
        child.once('error', error => {
          clearTimeout(timer)
          reject(error)
        })
      })
      publishStatus({ state: 'bootstrapping', progress: 0, message: 'Tor started; joining the Tor network…' })
    } catch (error) {
      publishStatus({
        state: 'error',
        progress: 0,
        message: `Tor could not start automatically: ${error.message}`,
      })
    }
    return {
      socksProxy: port ? `socks5://127.0.0.1:${port}` : 'socks5://127.0.0.1:9',
      status: { ...status },
    }
  }

  async function stop() {
    stopping = true
    if (!child || !childSpawned || child.exitCode !== null || child.signalCode !== null) return
    await new Promise(resolve => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        resolve()
      }, 3000)
      child.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
      child.kill('SIGTERM')
    })
    publishStatus({ state: 'stopped', progress: 0, message: 'Tor stopped.' })
  }

  return {
    start,
    stop,
    getStatus: () => ({ ...status }),
  }
}
