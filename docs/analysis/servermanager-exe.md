# `ServerManager.exe` — static analysis (MITM reverse proxy)

Static analysis of the Windows executable referenced from
`https://github.com/EduardoC3677/opencode/raw/refs/heads/o/O+/Data/ServerManager.exe`,
performed entirely from headers, sections, the import table and ASCII /
UTF-16 strings. The binary was **not executed**.

This binary is treated separately from
[`oplus-toolshub-bins.md`](./oplus-toolshub-bins.md) because it is the
only file in the bundle that

* has **no Authenticode signature**,
* has **no PDB path**,
* talks DNS-redirection plus HTTP forwarding to a third-party host,
* and is x86_64 (every other binary in the bundle is x86),

— i.e. it does not come from the OPPO build pipeline that signed
`OpSecLib.dll`, `LoginPlugin.dll`, `libUpdate.dll`, `libTHS.dll` and
`ToolsUpgrade.exe`.

---

## 1. File identity

| Field   | Value |
|---------|-------|
| Filename | `ServerManager.exe` |
| Size     | 346,624 bytes (≈ 339 KiB) |
| Type     | PE32+ executable, GUI subsystem, machine `IMAGE_FILE_MACHINE_AMD64` (x86_64) |
| MD5      | computable from `sha256sum`'s sibling — the SHA-256 alone is given here |
| SHA-256  | `64d328158a25afd2581002c7c119950e09ca008a4adf801f1677d5528b3c144a` |
| Authenticode | **none** — `IMAGE_DIRECTORY_ENTRY_SECURITY` size = 0 |
| `VS_VERSION_INFO` | absent (no `CompanyName`, no `FileVersion`, no `LegalCopyright`) |
| PDB path / debug dir | none |
| Resources (`.rsrc`) | absent |

So unlike every other binary in the bundle this file carries **zero
provenance** — no vendor, no version, no signature, no debug symbols,
no manifest. The string `ServerManager` and the class name
`ServerManagerClass` is the only branding inside the file.

---

## 2. PE header summary

| Field | Value |
|-------|-------|
| Machine | `0x8664` (AMD64) |
| Number of sections | 6 |
| `Characteristics` | `0x22` (`EXECUTABLE_IMAGE`, `LARGE_ADDRESS_AWARE`) |
| Subsystem | `IMAGE_SUBSYSTEM_WINDOWS_GUI` (3) |
| `DllCharacteristics` | typical (DYNAMIC_BASE / NX_COMPAT / TERMINAL_SERVER_AWARE) |
| Linker | MSVC 14.x (Visual Studio 2019/2022) |

Sections are the standard, unpacked MSVC layout (`.text` `.rdata`
`.data` `.pdata` `.fptable` `.reloc`) — no protector / packer
fingerprints. Strings are recoverable directly.

---

## 3. Imports — what kind of program this is

Only **5** distinct DLLs are imported, and they are diagnostic:

| DLL | Selected symbols | Conclusion |
|---|---|---|
| `WS2_32.dll` (13) | `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `closesocket`, `htons`, `inet_addr`, `WSAStartup`, `WSACleanup`, `WSAGetLastError` | Raw BSD-style TCP server **and** outgoing connection |
| `WINHTTP.dll` (9) | `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpQueryHeaders`, `WinHttpQueryDataAvailable`, `WinHttpReadData`, `WinHttpCloseHandle` | Outbound HTTP**S** client |
| `USER32.dll` (16) | `RegisterClassA`, `CreateWindowExA`, `GetMessageA`, `DispatchMessageA`, `MessageBoxA`, `PostQuitMessage`, `SendMessageA`, `PostMessageA`, `EnableWindow`, `ShowWindow`, `DestroyWindow`, `LoadCursorA`, … | Win32 message-loop GUI |
| `KERNEL32.dll` (104) | + `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `OpenProcess`, `TerminateProcess` | Process-tree walking and **process termination** |
| `SHELL32.dll` (1) | (one symbol) | Possibly `ShellExecute` for hosts-file edit elevation prompt |

So `ServerManager.exe` is a **GUI Windows application** that:

1. Listens as a TCP server (`bind`/`listen`/`accept`).
2. Forwards each connection out via `WinHTTP` to an HTTPS target.
3. Walks the process list and can terminate processes.
4. Touches the local file system (it edits the system `hosts` file —
   see § 4).

There is no use of `WININET`, no `URLDownloadToFile`, no
`CertVerifyCertificateChainPolicy`, no `CryptUI` — i.e. it does
**not** present any signed-update / signed-package UI.

---

## 4. Behaviour — strings tell the whole story

The binary is unpacked, so its operational strings drop out cleanly.
Verbatim, in the order they appear in the binary:

```
=== ServerManager Started ===
\servermanager_startup.log
\reverseproxy_debug.log
\drivers\etc\hosts
HostsManager: Removed %d lines containing '%s'
StopServer: Removing hosts entry for %s...
StopServer: Hosts entry removed
Cannot read hosts file:
Cannot write to hosts file. Make sure you have admin rights.

Bind failed on port
Bind failed. Make sure port 80 is available and you have admin rights
Bind success on port
Listen success - proxy is now accepting connections
Listen failed
Socket creation failed
ServerLoop: Started, waiting for connections...
ServerLoop: Accept failed with error
ServerLoop: Connection #
ServerLoop: Exiting (running=false)

HandleClient: Connection received
HandleClient: Received
HandleClient: Got response, size=
HandleClient: Response sent successfully
HandleClient: No data received or connection error
HandleClient: ERROR -
HandleClient: ERROR - Unknown exception

ForwardRequest: Starting
ForwardRequest: Full URL=
ForwardRequest: Host=
ForwardRequest: Method=
ForwardRequest: Sending request with
ForwardRequest: WinHttpSendRequest failed, error=
ForwardRequest: Request sent, waiting for response
ForwardRequest: WinHttpReceiveResponse failed, error=
ForwardRequest: Response received successfully
ForwardRequest: Status code=
ForwardRequest: Complete, returning

About to launch: %s
Process Name: %s
Process launched successfully
Failed to start process:
Failed to get process handle for:
WARNING: Could not get O+ Support process handle

HTTP/1.1 502 Bad Gateway
Connection: close
Content-Type: text/plain
Content-Length:
Host: 127.0.0.1
ServerManager-Proxy/1.0
Proxy Error: Unable to reach target server.
Proxy is already running
Proxy failed to start listening on port 80

Server Status: Running
Server Status: Stopped
Server thread started
Server started successfully
Cleanup complete, exiting ServerManager
StopServer: Stopping reverse proxy...
ServerManagerClass

dfs-server-test.wanyol.com
https://gsmnepalserver.com/realme
```

That is the complete operational vocabulary. There are no other URLs,
no other hostnames, and **no other strings of substance** in the
binary.

The behaviour is unambiguous:

1. On startup the program looks for the **"O+ Support" process handle**
   ("WARNING: Could not get O+ Support process handle"), which is the
   user-facing GUI of OPPO's *O+ Support* (`ToolsUpgrade.exe` /
   `ToolsHub`) — i.e. it expects to run alongside the legitimate OPPO
   tool. It can also `About to launch:` a child process by name.
2. It **edits the Windows hosts file** (`C:\Windows\System32\drivers\etc\hosts`),
   adding an entry that pins `dfs-server-test.wanyol.com` to
   `127.0.0.1`. On `StopServer` it removes the line again
   (`HostsManager: Removed %d lines containing '%s'`).
3. It **binds TCP/80 on `127.0.0.1`** (the same port the hosts entry
   re-routes traffic to) and runs an `ServerLoop` accepting
   connections.
4. For every accepted connection it parses the inbound HTTP request,
   then calls `WinHttp{Open,Connect,OpenRequest,SendRequest,…}` to
   **forward** that request to the hard-coded outbound target

   ```
   https://gsmnepalserver.com/realme
   ```

   adding outbound headers `Connection: close`, `Content-Type: text/plain`,
   `Host: 127.0.0.1`, `User-Agent: ServerManager-Proxy/1.0`.
5. It writes two log files — `servermanager_startup.log` and
   `reverseproxy_debug.log` — at a path determined by the parent
   directory it is launched from.

That is the textbook signature of a **DNS-hijacking man-in-the-middle
proxy**, configured to intercept every call the OPPO toolchain
(`ToolsUpgrade.exe` / `libUpdate.dll` / `libTHS.dll`) would normally
send to OPPO's internal Distributed File Service test endpoint
`dfs-server-test.wanyol.com`, and silently redirect it to
`gsmnepalserver.com/realme` over HTTPS.

---

## 5. URLs / hosts / endpoints / headers — final table

| Type | Value | Origin in file | Purpose |
|---|---|---|---|
| Hostname (intercepted) | `dfs-server-test.wanyol.com` | constant string | written into `\drivers\etc\hosts` pointing to `127.0.0.1` |
| URL (proxied to) | `https://gsmnepalserver.com/realme` | constant string | base URL passed to `WinHttpConnect` + `WinHttpOpenRequest` |
| Loopback bind | `127.0.0.1:80` | `Host: 127.0.0.1` literal + log strings | TCP listener |
| User-Agent | `ServerManager-Proxy/1.0` | constant string | sent on outbound `WinHttpSendRequest` |
| Outbound headers | `Connection: close`, `Content-Type: text/plain`, `Content-Length: …`, `Host: 127.0.0.1` | constant strings | template header set |
| Error response | `HTTP/1.1 502 Bad Gateway` | constant string | served back to the client when the upstream call fails |
| Local logs | `servermanager_startup.log`, `reverseproxy_debug.log` | constant strings | log files |

There are **no API keys, no JWTs, no bearer tokens, no
hard-coded credentials, no certificates**, no PEM blocks and no public
keys in the binary. Everything cryptographic happens transparently
through `WINHTTP` (so it inherits the OS Schannel TLS + system
trust-store).

The IPv4 literal `127.0.0.1` is the only IP in the binary.

---

## 6. Capabilities check

| Surface | Verdict |
|---|---|
| Network — listen | **yes** (TCP/80) |
| Network — connect out | **yes** (HTTPS via WINHTTP, hard-coded host `gsmnepalserver.com`) |
| File system — system | **yes** (`%WINDIR%\System32\drivers\etc\hosts`) |
| File system — logs | **yes** (`*.log` next to the binary) |
| Registry | not used (no `ADVAPI32` import) |
| Persistence (Run keys / services) | not directly used by this binary (could be set up by an installer not in the dump) |
| Process control | enumerates (`Process32First/Next`), can `OpenProcess` / `TerminateProcess` |
| Privilege escalation | binary does not call `AdjustTokenPrivileges`; admin rights are needed (the program tells the user so verbatim — *"Make sure port 80 is available and you have admin rights"*, *"Cannot write to hosts file. Make sure you have admin rights"*) |

---

## 7. Provenance / risk

| Indicator | Value | Read |
|---|---|---|
| Authenticode signature | **none** | Did not pass through OPPO's signing pipeline (every other shipped DLL/EXE in the bundle is OPPO-signed) |
| `VS_VERSION_INFO` | **none** | No publisher / product / version metadata |
| PDB path | **none** | Stripped (or never embedded) — unusual for any in-house Windows tool |
| Domain `gsmnepalserver.com` | **third-party** | A commercial unlocking / IMEI / firmware site (`gsmnepal*` is a well-known unlocking-service brand) — **not** OPPO infrastructure |
| Domain `wanyol.com` | OPPO legacy infra | The OPPO target the proxy intercepts |
| Endpoint `/realme` | path on a **third-party** server | The server-side handler that receives intercepted OPPO/realme traffic |

**Net read**: this is **not** an OEM tool. It is a sideloader bolted on
to the OPPO O+ Support toolchain by a third party so that a workshop
PC running the official OPPO tools is silently redirected from the OPPO
backend to `gsmnepalserver.com/realme`. Whoever runs this PC then has
*all* of the after-sales-server traffic — `THS_LoginEx`, `THS_GetToken`,
`THS_GetKey`, `THS_QueryDeviceByAccount`, `THS_QueryWorkOrder`,
`THS_DownloadPackage`, `THS_UploadServiceLog`, `THS_ReportDiagResult`
etc. — answered by `gsmnepalserver.com/realme` instead of OPPO's
servers.

This makes the bundle as a whole a **legitimate-OEM-binaries +
unsigned-MITM-proxy** package — a typical pattern for grey-market
unlocking / repair toolkits that ride on stolen, trial-activated, or
legitimately distributed but contractually restricted OEM service
software.

> **Operator note** — Running this `.exe` once on a Windows machine
> persistently (a) modifies the Windows `hosts` file (you must
> manually verify it was reverted on `StopServer`), (b) opens TCP/80,
> and (c) requires Administrator. Do not execute it inside this repo
> without an isolated VM.

---

## 8. Reproducing the analysis

```bash
pip install pefile
curl -L -o ServerManager.exe \
  "https://raw.githubusercontent.com/EduardoC3677/opencode/o/O%2B/Data/ServerManager.exe"

python3 - <<'PY'
import pefile, hashlib
pe = pefile.PE("ServerManager.exe", fast_load=False)
print("sha256", hashlib.sha256(open("ServerManager.exe","rb").read()).hexdigest())
print("machine", hex(pe.FILE_HEADER.Machine))
print("subsystem", pe.OPTIONAL_HEADER.Subsystem)
print("signed", pe.OPTIONAL_HEADER.DATA_DIRECTORY[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
].Size > 0)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode(), len(entry.imports))
    for imp in entry.imports:
        print("   ", imp.name.decode() if imp.name else f"#{imp.ordinal}")
PY

strings -a -n 8 ServerManager.exe | grep -Ei \
  'wanyol|gsmnepal|hosts|proxy|Forward|Handle|ServerLoop|launch|process|http'
```

No binary was executed at any point in the production of this
document.
