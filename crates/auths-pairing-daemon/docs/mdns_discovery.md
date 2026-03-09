# mDNS Discovery Protocol

## Service Type

`_auths-pair._tcp.local.`

## TXT Record Keys

| Key   | Description                          | Example        |
|-------|--------------------------------------|----------------|
| `sc`  | 6-character pairing short code       | `ABC123`       |
| `v`   | Protocol version                     | `1`            |
| `did` | Controller DID of the initiator      | `did:keri:...` |

## Advertisement

The initiating device registers an mDNS service with:
- Instance name: `auths-pair-{short_code_lowercase}`
- Hostname: `$HOSTNAME.local.` (falls back to `$HOST`, then `auths-device.local.`)
- Port: the TCP port the pairing HTTP server is bound to
- TXT records: `sc`, `v`, `did` as above

## Discovery Flow

1. Discovering device calls `ServiceDaemon::browse("_auths-pair._tcp.local.")`
2. Receives `ServiceEvent::ServiceResolved` events
3. For each resolved service, checks the `sc` TXT property (case-insensitive match)
4. Prefers IPv4 addresses from `get_addresses_v4()`
5. Returns `SocketAddr` of the first match, or errors on timeout

## Timeout Behavior

Discovery uses `recv_timeout` in a blocking loop with a configurable deadline.
The loop checks 1-second intervals against the deadline. Callers should use
`tokio::task::spawn_blocking` when calling from an async context.
