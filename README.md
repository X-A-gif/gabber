# Gabber

Gabber is an experimental Electron chat client exploring end-to-end encrypted
messaging and zero-knowledge proofs.

## Current status

- The React chat screen uses the OpenMLS WebAssembly client to encrypt and
  decrypt messages in an MLS group. Signed contact cards and invitations are
  exchanged out of band; the app asks users to compare the full account
  fingerprint through a separate trusted channel.
- The existing Ed25519 account identity signs a binding to each in-memory MLS
  device key. Newly created and recovered identities use a
  passphrase-protected scrypt/AES-256-GCM local vault; existing identities can
  use Electron `safeStorage` when backed by a supported OS keyring. Older
  plaintext identity files are migrated only after a successful unlock and
  encrypted write. The app persists its one active MLS session and message
  history in a separate, authenticated encrypted local archive.
- By default, the app connects only to the loopback relay at `127.0.0.1:8787`.
  The relay keeps opaque MLS ciphertext in a bounded, disk-backed queue for up
  to seven days and removes it after the recipient acknowledges processing.
  Room membership and mailbox IDs are unauthenticated; a client with the room
  invitation can claim a mailbox or forge acknowledgements. The relay does not
  validate MLS messages. The default local setup cannot chat between different
  computers. Do not expose the relay to a LAN or the public internet.
- On Linux, the app starts its own client-only Tor process automatically at
  launch when the `tor` executable is installed. A green Tor indicator means
  bootstrap reached 100%; a separate relay indicator means the chat room was
  joined. The current development relay remains loopback-only and is not routed
  through Tor or reachable from another device.
- This is an integration prototype, not production-ready secure messaging.
  Identity verification still depends on users comparing fingerprints, and
  the client, local key protection, relay protocol, update process, and complete
  application need independent security review before release.

### Account identity recovery

Every account has a portable 136-character recovery key containing its account
handle, signing and encryption secrets, with a checksum to catch typing
mistakes. A user can restore an account on a new install with that key alone;
no pairing scan or backup file is required. The key is equivalent to
the account's master secret: anyone who gets it can impersonate the account.
Gabber displays it at account creation and lets an unlocked user view it later.
Keep it offline and separate from the device.

To recover, use **Recover account with key** on the identity screen, paste the
recovery key, then set a new local passphrase. The account is restored directly
from that key; the app does not offer file-based identity recovery.

Each installation stores its own local identity vault protected by a
device-local passphrase (at least 12 characters). When recovering an account,
choose a new local passphrase for that installation; it is independent from the
recovery key and from other devices' passphrases. Recovery restores account
keys only, not chat history or MLS sessions.

### Local chat persistence

Gabber encrypts the active conversation’s transcript and serialized OpenMLS
provider state on disk, using the local vault passphrase or the supported OS
keyring. On the next unlock it loads the saved MLS group, restores its ratchets,
and reconnects to the saved relay room. The archive is local to this device and
bound to the account identity; separate accounts on the same installation use
separate archives. Existing single-archive installations are migrated when the
matching account next unlocks. Archives are not included in the portable
account recovery key. This prototype still supports only one active
conversation per account.

Messages sent while the sender is offline are encrypted and saved in the
device's local chat archive, then retried when the relay reconnects. Once the
relay accepts an envelope, it durably queues the opaque ciphertext for the
recipient for up to seven days. The recipient acknowledges only after the
decrypted message and updated MLS state have been saved locally; the sender
sees device-queued, relay-queued, and delivered statuses. Relay queue data is
stored at `~/.gabber/relay-queue.json` by default and can be moved with
`GABBER_RELAY_QUEUE_FILE`. The queue is size-bounded and expires; it is not a
history backup or a multi-device synchronization mechanism.

MLS state is security sensitive: replacing or restoring an older copy of the
local archive can roll back ratchets. Gabber does not yet have hardware-backed
anti-rollback protection, so do not manually copy/restore older chat archives.
A damaged, missing, or incompatible archive can prevent resuming the saved MLS
session.

At this prototype stage, devices restored from the same recovery key share
account-level authority. There is not yet a synchronized device registry or
global device revocation/rekey flow; deleting one device's local vault does not
revoke copies of the account key or remove that device from existing MLS
groups. Those require durable MLS state and a way to propagate signed
revocations to peers.

## Development

Install Node.js and Rust (1.94 or newer), the Rust
`wasm32-unknown-unknown` target, and `wasm-bindgen-cli` 0.2.129.

```sh
npm install
npm run dev
```

The `dev` and `build` lifecycle scripts build the WebAssembly crypto package
first. The `build:crypto` script requires `cargo` and `wasm-bindgen` on `PATH`.

Run the relay tests:

```sh
npm run test:relay
```

Run the browser-side signed-bundle and two-client MLS/relay integration tests:

```sh
npm run test:messaging
```

Test network-mode validation and proxy fail-closed settings:

```sh
npm run test:network
```

Run the native OpenMLS client tests:

```sh
npm run test:crypto
```

Build the OpenMLS WebAssembly package manually:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
npm run build:crypto
```

Run the WebAssembly encryption smoke test:

```sh
npm run test:crypto:wasm
```

For manual app testing, start the relay in a separate terminal before
`npm run dev`:

```sh
npm run relay
```

The relay listens on `127.0.0.1:8787` by default. `GABBER_RELAY_HOST` only
accepts loopback addresses; the prototype must not bind to a network interface.
Queued messages are stored as ciphertext in `~/.gabber/relay-queue.json`;
override the path with `GABBER_RELAY_QUEUE_FILE`. Room membership exists only
in relay process memory. Queue files contain unencrypted routing metadata
alongside MLS ciphertext; the relay does not add another at-rest encryption
layer. Protect the file like other private application data.

### Automatic Tor startup (Linux)

Install the Tor package for your Linux distribution so the `tor` executable is
available on `PATH`. Gabber then launches a separate, client-only Tor process
automatically when the app starts. No SOCKS port or Tor daemon setup is
required. The process uses an app-owned data directory under Electron's user
data folder and a dynamically selected loopback SOCKS port; Tor bootstrap
progress appears in the UI. If Tor is missing or fails to start, local
development mode remains available and reports Tor as offline.

For an onion-relay connection, provide the relay's v3 onion URL:

```sh
GABBER_REQUIRE_ONION_RELAY=1 \
GABBER_ONION_RELAY_URL=ws://<56-character-v3-onion-host>.onion/v1/rooms \
npm run dev
```

`GABBER_ONION_RELAY_URL` must be a v3 `.onion` WebSocket URL using the
`/v1/rooms` path. `GABBER_REQUIRE_ONION_RELAY=1` makes startup fail rather
than silently selecting the local development relay if the onion URL is
missing. Onion traffic is held until the managed Tor daemon has fully
bootstrapped. During `npm run dev`, only the exact loopback Vite dev-server host
and port are exempted so the UI/HMR can load; the onion relay remains routed
via SOCKS. The green Tor indicator means Tor reported 100% bootstrap; the
separate relay indicator turns green only after the onion relay acknowledges
the joined room. Neither indicator independently audits the route or means a
peer is online. For stronger fail-closed guarantees, also use an OS firewall
rule that blocks direct outbound connections from Gabber.

### Onion relay host deployment (Linux/systemd)

The relay process must remain loopback-only. Tor publishes it as a v3 onion
service; do not expose port 8787 on a public or LAN interface. The repository
includes a Tor configuration snippet at `deploy/tor/gabber-relay.torrc` and a
systemd unit at `deploy/systemd/gabber-relay.service`. These examples assume
the application is installed at `/opt/gabber`, the relay runs as a dedicated
`gabber` user, and the host has a system Tor daemon. Adapt paths and the Tor
service account to the host distribution.

1. Install Node.js and Tor on a Linux server. Install the Gabber runtime at
   `/opt/gabber` with production dependencies (`npm ci --omit=dev`).
2. Create a dedicated unprivileged `gabber` system user with no login shell.
   Install `deploy/systemd/gabber-relay.service` as
   `/etc/systemd/system/gabber-relay.service`.
3. Add the directives from `deploy/tor/gabber-relay.torrc` to the host Tor
   daemon configuration. Ensure `/var/lib/tor/gabber-relay` is owned by the
   Tor daemon account and accessible only to that account, then restart Tor.
   The onion service hostname is written to
   `/var/lib/tor/gabber-relay/hostname`; keep the service directory private
   because it contains the onion service identity keys.
4. Start the relay with `systemctl daemon-reload && systemctl enable --now
   gabber-relay`. Verify it listens only on `127.0.0.1:8787`, and that the Tor
   daemon reports the onion service as ready. Configure no public port-forward
   or firewall allowance for 8787.
5. Configure each client with the resulting hostname:

   ```sh
   GABBER_REQUIRE_ONION_RELAY=1 \
   GABBER_ONION_RELAY_URL=ws://<hostname-from-tor>/v1/rooms \
   npm run dev
   ```

The included service file provides a persistent, permission-restricted queue
file at `/var/lib/gabber/relay-queue.json`. Back up the Tor service keys and
queue file securely; losing the keys changes the onion address, while losing
the queue loses messages awaiting delivery. This setup exposes the current
prototype relay as an onion service, not a production-ready public messaging
service: room IDs and claimed member IDs are not authenticated, acknowledgments
can be forged by anyone with the room invitation, and queue metadata is not
encrypted at rest. Do not invite real users or rely on it for important
messages until the relay authentication and abuse-resistance model has been
implemented and independently reviewed.

## Cryptography direction

The prototype uses OpenMLS, an MIT-licensed implementation of IETF MLS
(RFC 9420). The current Rust wrapper creates an MLS KeyPackage, establishes a
group from a Welcome, and encrypts/decrypts application messages. The relay
receives only serialized MLS ciphertext. Signed bundles bind the MLS device
signing key, KeyPackage or Welcome, and room ID to the existing account
identity; bundle signatures do not independently establish who controls that
account, so compare the full account fingerprint out of band.

Remaining work includes hardware-backed protection against local MLS-state
rollback; authenticated and privacy-preserving delivery suitable for remote
clients; multi-device enrollment and history transfer; and independent
security review. The current offline queue is prototype plumbing, not a
production relay. Automatic Tor startup currently targets Linux
and relies on a separately installed Tor executable; the app does not yet
bundle Tor for distribution on other platforms. The onion-relay path has not
been tested against a live onion service. Tor does not hide communication
timing or room-level metadata from the relay, and does not replace MLS
end-to-end encryption. The current relay remains an unauthenticated
development prototype, including when exposed as an onion service.
