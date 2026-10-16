import assert from 'node:assert/strict'
import test from 'node:test'
import { configureSessionProxy, loopbackDevServerBypass, resolveNetworkConfig } from './torConfig.js'

const onionHost = `${'a'.repeat(56)}.onion`

test('defaults to the loopback relay without enabling Tor', () => {
  assert.deepEqual(resolveNetworkConfig({}), {
    mode: 'local',
    relayUrl: 'ws://127.0.0.1:8787/v1/rooms',
    socksProxy: null,
  })
})

test('requires v3 onion relay and loopback SOCKS5 proxy in Tor mode', () => {
  assert.deepEqual(resolveNetworkConfig({
    GABBER_ONION_RELAY_URL: `ws://${onionHost}/v1/rooms`,
  }), {
    mode: 'tor',
    relayUrl: `ws://${onionHost}/v1/rooms`,
  })
  assert.equal(resolveNetworkConfig({
    GABBER_ONION_RELAY_URL: `wss://${onionHost}:8443/v1/rooms`,
    GABBER_TOR_SOCKS: '192.0.2.5:9050',
  }).mode, 'tor')
})

test('rejects direct network relays and ignores external SOCKS configuration', () => {
  assert.throws(() => resolveNetworkConfig({
    GABBER_ONION_RELAY_URL: 'ws://example.com/v1/rooms',
  }), /version 3 onion/u)
  assert.deepEqual(resolveNetworkConfig({
    GABBER_ONION_RELAY_URL: `ws://${onionHost}/v1/rooms`,
    GABBER_TOR_SOCKS: 'socks5://192.0.2.10:9050',
  }), { mode: 'tor', relayUrl: `ws://${onionHost}/v1/rooms` })
})

test('requires a configured onion relay when onion-only mode is enabled', () => {
  assert.throws(
    () => resolveNetworkConfig({ GABBER_REQUIRE_ONION_RELAY: '1' }),
    /requires GABBER_ONION_RELAY_URL/u,
  )
  assert.deepEqual(resolveNetworkConfig({
    GABBER_REQUIRE_ONION_RELAY: '1',
    GABBER_ONION_RELAY_URL: `ws://${onionHost}/v1/rooms`,
    GABBER_RELAY_URL: 'ws://127.0.0.1:8787/v1/rooms',
  }), {
    mode: 'tor',
    relayUrl: `ws://${onionHost}/v1/rooms`,
  })
})

test('disables implicit loopback proxy bypass when Tor mode is enabled', async () => {
  const calls = []
  await configureSessionProxy(
    { mode: 'tor', socksProxy: 'socks5://127.0.0.1:49152' },
    { setProxy: async config => calls.push(config) },
    'http://localhost:5174',
  )
  await configureSessionProxy(
    { mode: 'local' },
    { setProxy: async config => calls.push(config) },
  )
  assert.deepEqual(calls, [
    {
      mode: 'fixed_servers',
      proxyRules: 'socks5://127.0.0.1:49152',
      proxyBypassRules: '<-loopback>;localhost:5174',
    },
    { mode: 'direct' },
  ])
})

test('refuses Tor proxy mode without the app-managed SOCKS proxy', async () => {
  await assert.rejects(
    () => configureSessionProxy({ mode: 'tor' }, { setProxy: async () => {} }),
    /managed local Tor SOCKS proxy/u,
  )
})

test('only permits a loopback Vite server exception in Tor mode', () => {
  assert.equal(loopbackDevServerBypass('http://127.0.0.1:5174'), '127.0.0.1:5174')
  assert.equal(loopbackDevServerBypass('http://localhost:5174'), 'localhost:5174')
  assert.equal(loopbackDevServerBypass(undefined), null)
  assert.throws(
    () => loopbackDevServerBypass('http://dev.example.com:5174'),
    /loopback Vite development server/u,
  )
})
