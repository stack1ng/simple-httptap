# simple-httptap

Runs a program and writes every HTTP request and response it makes to stdout as JSON lines: headers in the
order and case they were sent, full bodies, HTTP/1.1, HTTP/2 and HTTP/3.

```sh
httptap curl https://example.com > tap.jsonl
```

All of the program's TCP and UDP traffic, and that of every process it starts, goes through httptap without the
program being told, so nothing has to be pointed at a proxy and browsers keep using HTTP/3. httptap decrypts TLS
and QUIC with a key log, the `SSLKEYLOGFILE` format Wireshark reads, which it gets one of two ways:

- **The program logs its own keys.** Set `SSLKEYLOGFILE` and httptap reads the secrets the program writes there.
  Every byte passes through untouched, so the server sees exactly the TLS your program speaks, and you need
  no root certificate. Chrome, Edge, Firefox, curl, Python and Node (with `--tls-keylog`) can do this.
- **httptap intercepts.** Without `SSLKEYLOGFILE`, httptap ends the program's TLS with a certificate from its own
  root, which the program must trust, makes its own TLS to the server, and logs those keys itself. This works for
  any program that trusts the root, but the server sees httptap's TLS instead of your program's.

Either way the connection is decrypted the same way, from the key log.

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

The command is `httptap`; the project, its Homebrew formula and its data folder are `simple-httptap`.

### Capturing a program, per system

- **macOS:** a network extension sends the program's flows to httptap. The first run installs `httptap.app` in
  `/Applications` and macOS asks you, once, to allow its extension (System Settings → General → Login Items &
  Extensions → Network Extensions) and its proxy configuration. The extension only takes flows of programs
  httptap started, and stops itself when no httptap is running.
- **Linux:** the program runs in its own network namespace whose only way out is httptap. That needs
  unprivileged user namespaces, or `sudo`; on Ubuntu 24.04 and later, which restricts them, run httptap with
  `sudo` (the program still runs as you) or allow them with `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`.
- **Windows:** WinDivert diverts the program's packets to httptap, which needs an administrator terminal.

## Use

```sh
# The program logs its own keys: nothing is changed on the wire.
SSLKEYLOGFILE=/tmp/keys.log httptap curl https://example.com > tap.jsonl

# Chrome, HTTP/3 included. Use a profile of its own: a Chrome that is already running would take the URL
# and httptap would see nothing.
SSLKEYLOGFILE=/tmp/keys.log httptap "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/httptap-chrome https://example.com > tap.jsonl

# Node and Python.
SSLKEYLOGFILE=/tmp/keys.log NODE_OPTIONS=--tls-keylog=/tmp/keys.log httptap node app.js > tap.jsonl
SSLKEYLOGFILE=/tmp/keys.log httptap python3 app.py > tap.jsonl

# httptap intercepts; trust its root once first.
httptap trust
httptap curl https://example.com > tap.jsonl
```

stdout carries only httptap's JSON lines: the program's own stdout goes to stderr, with httptap's messages.
httptap exits when the program does, with its exit code.

When httptap intercepts, programs that keep their own CA list need it pointed at the root certificate, for
example `NODE_EXTRA_CA_CERTS` for Node and `SSL_CERT_FILE` for Python. `httptap trust` adds the root to the system's
trust store: on macOS through the system's own prompt, on Linux with `sudo` for the system store, on Windows into
the machine's store from an elevated session and otherwise the user's. It checks that TLS clients really trust it
and asks nothing if they already do. The root lives in the OS's data folder for the app
(`~/Library/Application Support/simple-httptap` on macOS, `~/.local/share/simple-httptap` on Linux,
`%APPDATA%\simple-httptap\data` on Windows), and every run reuses it. The keys httptap logs itself go to a file
only you can read in the system's temporary folder, named on stderr.

To go out through another proxy, set `HTTPTAP_UPSTREAM_PROXY=socks5://[user:password@]host:port`. TCP goes
through it with `CONNECT` and UDP with `UDP ASSOCIATE`.

## Output

One JSON object per line, `event` first and `unix_ms` last:

| `event` | Fields |
|---|---|
| `listening` | `address`: the SOCKS5 address httptap serves the program's traffic on |
| `opened` | `connection`, `client`, `target`, `transport` (`tcp` or `udp`), `tls` (TLS or QUIC), `protocol` (`h3`, `h2`, `http/1.1` or null) |
| `request`, `response` | `connection`, `stream` (HTTP/2 and HTTP/3) or `start_line` (HTTP/1), `headers` and `trailers` as `[name, value]` pairs in wire order, `body`, `complete` |
| `unparsed` | `connection`, `from` (`client` or `server`), `bytes`: anything that is not HTTP, such as DNS, WebSocket frames after an upgrade, or encrypted bytes whose keys never came |
| `fault` | `connection`, `from`, `detail`: why the bytes after it are `unparsed`, such as a client random the key log has no secret for |
| `refused` | `connection`, `detail`: the target could not be reached, or TLS or QUIC to it failed |
| `closed` | `connection` |

A UDP connection is one destination's datagrams both ways, so an HTTP/3 connection is `"transport": "udp",
"protocol": "h3"`. Bytes are a JSON string when they are UTF-8 and `{"base64": "..."}` otherwise. Bodies are
recorded as sent: chunked framing is removed, but gzip and other content codings are left as they are. A
message cut off by a closed connection still comes out, with `complete: false`.

## Limits

- A connection whose keys the program never logs, because it does not support `SSLKEYLOGFILE` or ignored it,
  comes out as encrypted `unparsed` bytes after a `fault` naming its client random.
- When httptap intercepts, the server sees httptap's TLS, not your program's, and the program sees httptap's
  certificate. Chrome refuses certificates from roots you added for QUIC, so intercepted Chrome falls back to
  HTTP/2; log Chrome's keys instead to see its HTTP/3. Programs that pin certificates fail when intercepted.
- Targets of intercepted connections must have certificates your OS trusts.
- On Windows, each run also serves an empty certificate revocation list on another loopback port, which
  its host certificates point to, because Windows tools such as `curl.exe` refuse a certificate whose
  revocation they cannot check.
- A UDP connection closes in the output after two minutes without a datagram, or when the program exits.
