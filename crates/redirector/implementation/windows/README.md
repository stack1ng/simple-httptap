# simple-httptap-redirector-windows

Sends every TCP and UDP packet a program and its descendants send through httptap's SOCKS5 proxy, with
[WinDivert](https://reqrypt.org/windivert.html) 2.2.2.

## How it works

1. The program starts suspended, joins a new job object, then runs. Every process it starts joins the job too.
2. A WinDivert handle on the SOCKET layer (sniffing) reports, for each `connect()` on the machine, the process
   and the flow (protocol, local port, remote address and port). A flow is diverted when that process is in the job.
3. A WinDivert handle on the NETWORK layer takes every outbound, non-loopback, unicast TCP and UDP packet.
   Packets of diverted flows go to a userspace stack; all others are injected again unchanged. A packet whose
   flow has no socket event yet waits up to a second for one, then passes (flows older than the capture).
4. The stack (smoltcp for TCP) ends each TCP connection and opens a SOCKS5 CONNECT to its destination, and gives
   each of the program's UDP sockets a SOCKS5 UDP ASSOCIATE. Replies are written as packets from the original
   destination and injected on the outbound path, which Windows loops back to the program's socket, as mitmproxy does.
5. `Capture::wait` waits for the started process, then shuts the handles, which ends the diversion.

httptap's own connections are never diverted: its process is not in the job, and loopback (where the proxy
listens) is never captured. Name resolution done by Windows' DNS Client service is not diverted either.

## How WinDivert reaches the user

httptap must run elevated (Administrator) on Windows; WinDivert's driver needs it.

`windivert/` holds the unchanged x64 `WinDivert.dll` and `WinDivert64.sys` from the signed release
[WinDivert-2.2.2-A.zip](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)
(zip SHA-256 `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`):

| File | SHA-256 |
| --- | --- |
| `WinDivert.dll` | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
| `WinDivert64.sys` | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |

They are compiled into httptap.exe with `include_bytes!`. On first use httptap writes each one that is missing to
`httptap-windivert-2.2.2\` beside httptap.exe, then loads the DLL from there by its full path (never from `PATH` or
the current folder) at run time; the DLL installs the driver from its own folder. So:

- httptap.exe is one file and needs no installer step; it starts on any Windows, and only `launch` needs WinDivert.
- A file already in the folder is never overwritten, so a user may replace the DLL with their own build, as the LGPL
  asks. Delete the folder to get the shipped files back.
- WinDivert ships only for x64; on ARM64 Windows `launch` returns `Unsupported`.

WinDivert is dual-licensed LGPLv3 or GPLv2; its license is in `windivert/LICENSE`, and a release must carry it.

## Licenses

`stack.rs` and `packet.rs` adapt mitmproxy_rs's `src/network` (MIT, see `LICENSE-mitmproxy`). mitmproxy's Windows
redirector itself is LGPL-3.0-or-later and was read for its approach but not copied.
