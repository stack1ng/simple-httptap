# simple-httptap

Runs a program and writes every HTTP request and response it makes to stdout as JSON lines: HTTP/1.1, HTTP/2 and
HTTP/3, headers in wire order and case, full bodies.

```sh
SSLKEYLOGFILE=/tmp/keys.log httptap curl https://example.com > tap.jsonl
```

All of the program's TCP and UDP, and its children's, goes through httptap without the program knowing. TLS and
QUIC are read with a key log, the format Wireshark uses:

- **`SSLKEYLOGFILE` set:** the program logs its own keys and httptap never touches its bytes, so servers see exactly
  your program. Chrome, Edge, Firefox, curl and Python do this; Node does with `NODE_OPTIONS=--tls-keylog=<file>`.
- **Unset:** httptap intercepts with its own root certificate (`httptap trust`, once) and logs the keys itself.
  Servers then see httptap's TLS.

Capture never fails silently. If it breaks, httptap stops the program, writes a `failed` event and exits non-zero;
if httptap dies, the program dies with it.

## Install

```sh
brew install stack1ng/tap/simple-httptap
```

or `curl -LsSf https://github.com/stack1ng/simple-httptap/releases/latest/download/simple-httptap-proxy-tokio-installer.sh | sh`,
or on Windows `irm https://github.com/stack1ng/simple-httptap/releases/latest/download/simple-httptap-proxy-tokio-installer.ps1 | iex`.

- **macOS:** the first run installs `httptap.app` and macOS asks once to allow its network extension.
- **Linux:** needs unprivileged user namespaces, or `sudo` (the program still runs as you).
- **Windows:** needs an administrator terminal.

## Output

One JSON object per line, `event` first and `unix_ms` last.

| `event` | Fields |
|---|---|
| `listening` | `address` |
| `opened` | `connection`, `client`, `target`, `transport` (`tcp`/`udp`), `tls`, `protocol` (`h3`, `h2`, `http/1.1` or null) |
| `request`, `response` | `connection`, `stream` or `start_line`, `headers`, `body`, `trailers`, `complete` |
| `unparsed` | `connection`, `from`, `bytes`: anything not HTTP, or encrypted bytes whose keys never came |
| `fault` | `connection`, `from`, `detail`: why the bytes after it are `unparsed` |
| `refused` | `connection`, `detail` |
| `closed` | `connection` |
| `failed` | `detail`: capture broke; always the last line |

Bytes are a string when UTF-8, else `{"base64": "..."}`. Bodies keep their content coding. The program's own stdout
goes to stderr. `HTTPTAP_UPSTREAM_PROXY=socks5://[user:password@]host:port` sends everything through another proxy.

## Limits

- Traffic to `localhost` is not captured.
- Intercepted Chrome uses HTTP/2: Chrome refuses added roots for QUIC. Give it `SSLKEYLOGFILE` instead.
- A connection whose keys never arrive comes out as `unparsed`, after a `fault` naming its client random.
