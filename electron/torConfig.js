const DEFAULT_LOCAL_RELAY_URL = 'ws://127.0.0.1:8787/v1/rooms'
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost'])
const V3_ONION_HOST = /^[a-z2-7]{56}\.onion$/iu

function parseOnionRelay(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('GABBER_ONION_RELAY_URL must be a version 3 onion WebSocket URL')
  }

  if (
    !['ws:', 'wss:'].includes(url.protocol) ||
    !V3_ONION_HOST.test(url.hostname) ||
    url.pathname !== '/v1/rooms' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('GABBER_ONION_RELAY_URL must use a version 3 onion host and the /v1/rooms path')
  }
  return url.href
}

function parseLocalRelay(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('GABBER_RELAY_URL must be a loopback WebSocket URL')
  }
  if (
    url.protocol !== 'ws:' ||
    !LOOPBACK_HOSTS.has(url.hostname) ||
    url.pathname !== '/v1/rooms' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('GABBER_RELAY_URL must use a loopback host and the /v1/rooms path')
  }
  return url.href
}

export function resolveNetworkConfig(environment = process.env) {
  if (environment.GABBER_ONION_RELAY_URL) {
    return {
      mode: 'tor',
      relayUrl: parseOnionRelay(environment.GABBER_ONION_RELAY_URL),
    }
  }

  if (environment.GABBER_REQUIRE_ONION_RELAY === '1') {
    throw new Error('GABBER_REQUIRE_ONION_RELAY=1 requires GABBER_ONION_RELAY_URL; refusing non-onion relay mode')
  }

  return {
    mode: 'local',
    relayUrl: parseLocalRelay(
      environment.GABBER_RELAY_URL ||
      environment.VITE_GABBER_RELAY_URL ||
      DEFAULT_LOCAL_RELAY_URL,
    ),
    socksProxy: null,
  }
}

export function loopbackDevServerBypass(devServerUrl) {
  if (!devServerUrl) return null
  let url
  try {
    url = new URL(devServerUrl)
  } catch {
    throw new Error('VITE_DEV_SERVER_URL must be a loopback development server when Tor mode is enabled')
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    !LOOPBACK_HOSTS.has(url.hostname) ||
    url.username ||
    url.password
  ) {
    throw new Error('Tor mode only allows a loopback Vite development server')
  }
  const port = url.port || (url.protocol === 'https:' ? '443' : '80')
  return `${url.hostname}:${port}`
}

export async function configureSessionProxy(networkConfig, electronSession, devServerUrl) {
  if (networkConfig.mode === 'tor') {
    if (!networkConfig.socksProxy || !networkConfig.socksProxy.startsWith('socks5://127.0.0.1:')) {
      throw new Error('Tor mode requires the managed local Tor SOCKS proxy')
    }
    const devServerBypass = loopbackDevServerBypass(devServerUrl)
    await electronSession.setProxy({
      mode: 'fixed_servers',
      proxyRules: networkConfig.socksProxy,
      proxyBypassRules: devServerBypass
        ? `<-loopback>;${devServerBypass}`
        : '<-loopback>',
    })
    return
  }

  await electronSession.setProxy({ mode: 'direct' })
}
