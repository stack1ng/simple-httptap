# simple-httptap

An HTTPS-intercepting proxy you start for one job and throw away. It listens on a port the OS picks
and writes every request and response to stdout as JSON lines: headers in the order and case they were
sent, full bodies, HTTP/1.1 and HTTP/2. It forwards bytes unchanged, so the server sees exactly what the
client sent.

## Install

```sh
brew install stack1ng/tap/simple-httptap
```

or

```sh
curl -LsSf https://github.com/stack1ng/simple-httptap/releases/latest/download/simple-httptap-proxy-tokio-installer.sh | sh
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/stack1ng/simple-httptap/releases/latest/download/simple-httptap-proxy-tokio-installer.ps1 | iex"
```

Then trust its root certificate once:

```sh
httptap trust
```

It asks once and then checks that TLS clients really trust the root. On macOS that is the system's own
prompt (password or Touch ID) for your login keychain's trust settings, which Chrome and Safari use; on
Linux it runs `sudo` itself for the system store; on Windows, from an elevated or administrator SSH
session, it goes into the machine's root store with no dialog, and otherwise into your user's, where
Windows asks you to confirm it.
Run it again any time: if the root is already trusted, it says so and asks nothing. The certificate lives in the OS's data folder for
the app (`~/Library/Application Support/simple-httptap` on macOS, `~/.local/share/simple-httptap` on
Linux, `%APPDATA%\simple-httptap\data` on Windows), and every run reuses it.

The command is `httptap`; the project, its Homebrew formula and its data folder are `simple-httptap`.

## Use

```sh
httptap > /tmp/tap.jsonl &
ADDR=$(head -1 /tmp/tap.jsonl | jq -r .address)   # {"event":"listening","address":"127.0.0.1:54321",...}
HTTPS_PROXY=http://$ADDR HTTP_PROXY=http://$ADDR curl https://example.com
```

There are no options. Output goes to stdout, so redirect or pipe it wherever you want; the line
`proxy started at http://127.0.0.1:PORT` and any warnings go to stderr. Start as many as you like: each
gets its own port and its own stream.

Programs that keep their own CA list need it pointed at the root certificate, for example
`NODE_EXTRA_CA_CERTS` for Node (which also needs `NODE_USE_ENV_PROXY=1` for `fetch`) and
`SSL_CERT_FILE` for Python.

To go out through another HTTP proxy, set `HTTPTAP_UPSTREAM_PROXY=http://[user:password@]host:port`.
Every connection, HTTPS and plain HTTP, goes through it with `CONNECT`.

## Output

One JSON object per line, `event` first and `unix_ms` last:

| `event` | Fields |
|---|---|
| `listening` | `address` |
| `opened` | `connection`, `client`, `target`, `tls`, `protocol` (`h2`, `http/1.1` or null) |
| `request`, `response` | `connection`, `stream` (HTTP/2) or `start_line` (HTTP/1), `headers` and `trailers` as `[name, value]` pairs in wire order, `body`, `complete` |
| `unparsed` | `connection`, `from` (`client` or `server`), `bytes`: anything that is not HTTP, such as WebSocket frames after an upgrade |
| `fault` | `connection`, `from`, `detail`: why the bytes after it are `unparsed` |
| `refused` | `connection`, `detail`: the proxy could not reach or handshake with the target |
| `closed` | `connection` |

Bytes are a JSON string when they are UTF-8 and `{"base64": "..."}` otherwise. Bodies are recorded as sent:
chunked framing is removed, but gzip and other content codings are left as they are. A message cut off
by a closed connection still comes out, with `complete: false`. The `CONNECT` request a client sends to
the proxy is logged too.

## Limits

- The TLS fingerprint the server sees is this proxy's, not your client's. Every intercepting proxy has
  this limitation.
- Targets must have certificates your OS trusts.
- On Windows, each run also serves an empty certificate revocation list on another loopback port, which
  its host certificates point to, because Windows tools such as `curl.exe` refuse a certificate whose
  revocation they cannot check.
- A plain-HTTP keep-alive connection goes to the host of its first request.
- The proxy notices that stdout has closed only when it next writes an event; stop it with a signal.
