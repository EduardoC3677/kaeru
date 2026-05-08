# `OpSecLib.dll` — Static Analysis

Static analysis of the Windows DLL referenced from
`https://github.com/EduardoC3677/opencode/raw/refs/heads/o/O+/Data/OpSecLib.dll`,
performed entirely from headers, sections, strings, the export table, the
embedded Authenticode signature and disassembly of the entry point. The binary
was **not executed**.

---

## 1. File identity

| Field   | Value |
|---------|-------|
| Filename | `OpSecLib.dll` |
| Size     | 11,498,664 bytes (≈ 10.97 MiB) |
| Type     | PE32 executable, DLL, GUI subsystem, machine `IMAGE_FILE_MACHINE_I386` (x86, 32-bit) |
| MD5      | `f01f126ecc3391085177d0ecd0a96088` |
| SHA-1    | `6927258a7858128c770759426b666e5f24a8515b` |
| SHA-256  | `f6c86de6e56e35442641dce113a7301bdbaf3129a5098544b266214a7a5f1b18` |

`VS_VERSION_INFO` resource (only legible string block in the file):

| Field            | Value |
|------------------|-------|
| `CompanyName`    | Guangdong OPPO Mobile Telecommunications Corp., Ltd. |
| `FileDescription`| OpSecLib |
| `FileVersion`    | 1.0.3.0 |
| `InternalName`   | OpSecLib.dll |
| `OriginalFilename` | OpSecLib.dll |
| `ProductName`    | OpSecLib |
| `ProductVersion` | 1.0.3.0 |
| `LegalCopyright` | Copyright (C) 2004 OPPO. All rights reserved. |
| Translation      | `0804 04b0` (Chinese – PRC, codepage UTF-16) |

So this is an **OPPO-signed user-mode DLL**, branded "OpSecLib" (likely
short for *OPPO Security Library* / *Op-Sec*). It is a desktop / Windows
component, not a phone-side binary.

---

## 2. PE header summary

| Field | Value |
|-------|-------|
| Machine | `0x014c` (i386) |
| Number of sections | 8 |
| `TimeDateStamp` | `0x68afabd3` → **2025-08-28 01:07:31 UTC** |
| `Characteristics` | `0x2102` (`EXECUTABLE_IMAGE`, `DLL`, 32-bit machine) |
| Subsystem | `IMAGE_SUBSYSTEM_WINDOWS_GUI` |
| `DllCharacteristics` | `0x0140` (DYNAMIC_BASE, NX_COMPAT) |
| `ImageBase` | `0x10000000` |
| `AddressOfEntryPoint` | `0x0082563d` (VA `0x1082563d`) |
| `SizeOfImage` | `0x110a000` (≈ 17.04 MiB virtual) |
| `SizeOfCode` | `0x2e00` (advertised) |
| `MajorLinkerVersion` | 14.29 (MSVC 2019, build 16.10–16.11 era) |
| `MinSubsystem` | 6.0 (Windows Vista+) |

The advertised `SizeOfCode` of `0x2e00` is misleading — see § 4.

---

## 3. Sections

| Name    | VirtualAddr | VirtualSize | RawAddr   | RawSize    | Entropy | Flags |
|---------|-------------|-------------|-----------|------------|---------|-------|
| `.text` | `0x1000`    | `0x2d7b`    | `0x0`     | **`0x0`**  | n/a     | RX (`0x60000020`) |
| `.rdata`| `0x4000`    | `0x4ee4`    | `0x0`     | **`0x0`**  | n/a     | R   (`0x40000040`) |
| `.data` | `0x9000`    | `0x610`     | `0x0`     | **`0x0`**  | n/a     | RW  (`0xc0000040`) |
| `.-hD`  | `0xa000`    | `0x6088f9`  | `0x0`     | **`0x0`**  | n/a     | RX  (`0x60000020`) |
| `.IWs`  | `0x613000`  | `0x58`      | `0x400`   | `0x200`    | 0.480   | RW  (`0xc0000040`) |
| `.Zu=`  | `0x614000`  | `0xaf34b0`  | `0x600`   | **`0xaf3600`** | **7.935** | RX (`0x60000020`) |
| `.rsrc` | `0x1108000` | `0x46d`     | `0xaf3c00`| `0x600`    | 2.958   | R   (`0x40000040`) |
| `.reloc`| `0x1109000` | `0x758`     | `0xaf4200`| `0x800`    | 4.080   | R   (`0x42000040`) |

Three observations are decisive:

1. The four sections that hold the "real" code/data of a normal binary
   (`.text`, `.rdata`, `.data`, `.-hD`) all have **`SizeOfRawData = 0`** — they
   exist only as virtual-memory reservations. They will be filled in at load
   time.
2. The two sections with non-standard names (`.-hD` and `.IWs`) are the kind of
   marker sections that **commercial PE protectors** add to reserve the layout
   they will rebuild at runtime.
3. The single huge raw payload is `.Zu=` — `0xaf3600` bytes (≈ 11 MiB, almost
   the entire file), with **entropy ≈ 7.935 / 8.0**. That is the entropy of
   compressed and/or encrypted data; normal x86 code sits between 5.8 and 6.5.

The DLL's entry point (`AddressOfEntryPoint = 0x82563d`) lives **inside `.Zu=`**,
not inside `.text`. The 10 advertised exports point into `.text`, but `.text`
has zero bytes on disk — the export thunks therefore have to be **materialised
at runtime** by the entry-point stub.

That is exactly the runtime model of a packer/protector: the loader receives a
stub that decrypts/decompresses `.Zu=` into the empty `.text` / `.rdata` /
`.data` / `.-hD` regions, restores the original IAT, then transfers control to
the real `DllMain` / export thunks.

### Disassembly of the entry point (first 60 bytes)

```
0x1082563d  call   0x10832aa3
0x10825642  dec    esp
0x10825643  mov    [esp + ecx - 0x5391], esi
0x1082564a  adc    [esp + ecx - 0x5391], cx
0x10825652  inc    ecx
0x10825653  movzx  esi, [edx + ecx*2 - 0xa722]
0x1082565b  inc    ebp
0x1082565c  mov    esp, ebp
...
```

The pattern (long arithmetic chains with no obvious purpose, mixed register
widths, displacements that do not correspond to any real symbol, loose
control-flow into the middle of `.Zu=`) is the **virtualised / mutated code**
signature characteristic of a commercial protector — most notably **VMProtect**
or **Themida/WinLicense**. There is no plain ASCII protector tag inside the
file (so neither name was matched textually), but the section layout, the empty
raw `.text`, the high-entropy payload and the entry-point pattern collectively
identify the family beyond reasonable doubt.

#### Why this is *not* a regular MSVC 2019 DLL

- A normal MSVC 2019 DLL of this size would have `.text` raw size in the hundreds
  of KB to MBs and an entropy around 6.0.
- A normal DLL's entry point is `_DllMainCRTStartup` in `.text`, not deep
  inside a high-entropy "blob" section.
- A normal DLL has dozens to hundreds of imports; this one has **8 imports
  total, one symbol per DLL** (see § 5) — the textbook minimum stub left by a
  protector that hides the real IAT.

---

## 4. Imports — the giveaway IAT stub

```
libcrypto-1_1.dll                          : RSA_size
MSVCP140.dll                               : operator<<(unsigned int)  (basic_ostream<char>)
VCRUNTIME140.dll                           : __std_exception_destroy
api-ms-win-crt-runtime-l1-1-0.dll          : _initialize_narrow_environment
api-ms-win-crt-heap-l1-1-0.dll             : _callnewh
api-ms-win-crt-stdio-l1-1-0.dll            : _fseeki64
api-ms-win-crt-string-l1-1-0.dll           : strcpy_s
KERNEL32.dll                               : GetSystemTimeAsFileTime
```

**Eight DLLs, exactly one symbol each.** Real OpenSSL/MSVC code never produces
an IAT this thin — this is the minimal stub that protectors emit so the OS
loader resolves at least one symbol per DLL (forcing the DLL to be mapped),
after which the protector rebuilds the *real* IAT in memory.

Even so, the stub leaks the **runtime stack** the protected code depends on:

- **OpenSSL 1.1** (`libcrypto-1_1.dll`) — the underlying cryptographic
  primitives. `RSA_size` confirms RSA operations are inside the protected
  payload, consistent with the export names.
- **MSVC 2019 C / C++ runtime** (`MSVCP140`, `VCRUNTIME140`,
  `api-ms-win-crt-*` UCRT shims) — agreeing with `LinkerVersion 14.29`.
- **`KERNEL32!GetSystemTimeAsFileTime`** — used by the protector for
  anti-debug timing checks and/or by OpenSSL's RNG seeding.

There is **no overlap** with low-level Win32 APIs (`VirtualAlloc`,
`LoadLibrary`, `GetProcAddress`, `CreateFileMapping`, …) — those are resolved
by the protector itself at runtime via API-hashing, not via the IAT.

---

## 5. Exports — the public API

```
ord  RVA           Name
  1  0x00001540    OpDecrypt
  2  0x000013f0    OpEncrypt
  3  0x000027b0    OpHashFinal
  4  0x00002830    OpHashFinalToString
  5  0x00002a20    OpHashFree
  6  0x000025b0    OpHashInit
  7  0x00002610    OpHashUpdateBuffer
  8  0x00002640    OpHashUpdateFile
  9  0x00001600    OpSign
 10  0x000016c0    OpVerify
```

All ten RVAs land inside the `.text` section, **whose raw size is `0x0`** — i.e.
the export bodies are not present on disk. They will be materialised when the
unpacker runs.

The names give a clear picture of what the DLL is for: it is a **thin C-style
façade over OpenSSL** that exposes three families of operations:

### 5.1 Symmetric (or hybrid) encryption — `OpEncrypt` / `OpDecrypt`
Generic encrypt/decrypt entry points. Combined with the use of
`RSA_size` from libcrypto, this is most likely either RSA-only, or a
**hybrid scheme** (RSA-wrapped session key + AES payload) — a very common
shape for licensing / config / signed-resource decryption in OEM tools.

### 5.2 Hashing — incremental hash API
A textbook libcrypto-style streaming-hash API:

| Export                  | Equivalent OpenSSL primitive |
|-------------------------|------------------------------|
| `OpHashInit`            | `EVP_MD_CTX_new` + `EVP_DigestInit_ex` |
| `OpHashUpdateBuffer`    | `EVP_DigestUpdate` (in-memory) |
| `OpHashUpdateFile`      | wrapper that mmap/streams a file into `EVP_DigestUpdate` |
| `OpHashFinal`           | `EVP_DigestFinal_ex` (returns raw bytes) |
| `OpHashFinalToString`   | hex-encoded variant of the above |
| `OpHashFree`            | `EVP_MD_CTX_free` |

The presence of `OpHashUpdateFile` strongly suggests file-integrity / artifact
hashing (e.g. firmware-image SHA verification on the host side).

### 5.3 Digital signatures — `OpSign` / `OpVerify`
Public-key sign / verify built on the same OpenSSL stack — the natural pair for
a tool that produces and verifies signed firmware bundles, signed update
packages or signed configuration blobs.

### 5.4 Bottom line on the API
`OpSecLib.dll` is the **host-side cryptographic library** of an OPPO desktop
toolchain — exactly the role that, for example, MTK/SP Flash Tool plug-ins
play, or that vendor flashing tools play when they need to sign / verify
something before it is delivered to the device. Its API surface (encrypt,
decrypt, hash, sign, verify) is **generic**: nothing in the export table tells
you *what* it signs — that policy lives inside the protected `.Zu=` blob.

---

## 6. Authenticode signature

The PE has a populated `IMAGE_DIRECTORY_ENTRY_SECURITY` (offset `0xaf4a00`,
10,920 bytes), containing a `WIN_CERTIFICATE` of `wRevision = 0x0200`,
`wCertificateType = 0x0002` (PKCS#7 Authenticode).

### 6.1 Signing certificate (leaf)

| Field | Value |
|-------|-------|
| Subject CN | Guangdong OPPO Mobile Telecommunications Corp., Ltd. |
| Subject O  | Guangdong OPPO Mobile Telecommunications Corp., Ltd. |
| Subject OU | IT Dept |
| Subject L / ST / C | Dongguan / Guangdong / CN |
| Issuer | GlobalSign GCC R45 CodeSigning CA 2020 |
| Serial | `1D 83 D5 F5 34 C8 67 3B A5 6F 40 A2` |
| Valid from | 2023-11-29 08:15:12 UTC |
| Valid until | 2026-11-29 08:15:12 UTC |

### 6.2 Intermediate

| Field | Value |
|-------|-------|
| Subject | GlobalSign GCC R45 CodeSigning CA 2020 |
| Issuer  | GlobalSign Code Signing Root R45 |
| Serial  | `81 4E 42 17 A1 29 7F ED 5A CC D4 17 F8 91 AD 75` |
| Valid 2024-06-19 → 2038-07-28 |

A **Sectigo Public Time Stamping Signer R36** counter-signature is also
present, anchored under USERTrust RSA Certification Authority.

### 6.3 Signing time

`signingTime` attribute on the SignerInfo: **2025-08-28 01:08:05 UTC**.
This matches the PE `TimeDateStamp` (2025-08-28 01:07:31 UTC) to within
about 30 seconds, which is the build → sign latency expected from a normal
release pipeline.

The signing chain therefore confirms: this DLL was *built and code-signed by
OPPO's official IT department* on 2025-08-28, using a GlobalSign-issued
code-signing certificate, and was time-stamped by Sectigo. There is no
indication of forgery or chain irregularity.

---

## 7. Other PE structures

| Directory | Status |
|-----------|--------|
| TLS callbacks | none |
| Debug directory | none (no PDB path leaks) |
| Load Config | present (default MSVC) |
| Resources | only `VS_VERSION_INFO` + a default Win32 application manifest (`<assembly … manifestVersion='1.0'>`) |
| Overlay | the 10,920 bytes after the last section *is* the Authenticode signature itself; nothing else is appended |
| `.reloc` | regular base-relocation table, ≈ 1.8 KB (consistent with a normal DLL after the protector finishes unpacking) |

There is **no Mono/Il2Cpp metadata, no .NET CLR header, no embedded
PDB path, and no debug GUID** — the protector has wiped them.

---

## 8. What the DLL actually does — synthesis

Putting all of the above together:

1. **Identity**: OPPO's first-party "OpSecLib" — a 32-bit Windows DLL,
   officially code-signed by Guangdong OPPO Mobile Telecommunications, version
   `1.0.3.0`, built on **2025-08-28**.
2. **Role**: a generic cryptographic-primitives façade exposed to host-side
   tools, with three families of exports — **encrypt/decrypt**,
   **incremental hashing** (including hash-of-file), and **sign/verify**.
   Underlying engine: **OpenSSL 1.1** (`libcrypto-1_1.dll`).
3. **Protection**: the entire implementation of those exports is shipped as a
   single **encrypted/compressed blob in `.Zu=`** (≈ 11 MiB, entropy 7.94),
   with the standard sections (`.text`, `.rdata`, `.data`, `.-hD`) reserved
   only virtually and reconstructed at runtime by an entry-point stub. The
   layout — empty raw `.text`, oddly-named "scratch" sections (`.-hD`,
   `.IWs`), one-symbol-per-DLL IAT stub, and the obfuscated entry point —
   matches the runtime model of a **commercial PE protector** of the
   VMProtect / Themida class.
4. **Loader-visible facts (everything observable without unpacking)**:
   - 10 exported C symbols listed in § 5.
   - Hard dependency on OpenSSL 1.1 (`libcrypto-1_1.dll`) and on the MSVC
     2019 / UCRT runtime.
   - Authenticode-signed and timestamp-valid against publicly-trusted
     roots (GlobalSign / USERTrust / Sectigo TS).

### What you cannot tell without unpacking it

The protector deliberately hides:

- the concrete cipher used by `OpEncrypt` / `OpDecrypt` (RSA-only? RSA + AES
  hybrid? AES-CBC vs. AES-GCM? PKCS#1 v1.5 vs. OAEP?),
- the digest algorithm(s) accepted by `OpHashInit` (SHA-256? SHA-1? MD5?),
- the signature scheme used by `OpSign` / `OpVerify` (RSA-PKCS#1 v1.5? RSA-PSS?
  ECDSA?),
- any **embedded public keys**, key-IDs or constants — the in-protected
  region likely contains an OPPO root/code-signing public key used to verify
  signed payloads, but it is encrypted on disk (none of MD5/SHA-1/SHA-256
  init constants and none of the AES S-box bytes are visible in the file
  as-is).

Recovering those requires running the DLL inside an instrumented sandbox
(e.g. dynamic dump after the unpacker finishes) or static unpacking via a
tool that targets the specific protector — which is **out of scope for a
read-only static review** and would in any case be necessary on a Windows
host.

### Risk assessment

- The file is signed by a legitimate OPPO certificate; the Authenticode
  chain is intact and the signing time (2025-08-28) matches the build.
- The packing/protection is consistent with normal vendor practice for
  commercial OEM tooling and is **not, on its own, a malware indicator**.
- The DLL's only documented capability surface is "crypto primitives" — it
  does not import any networking, registry, persistence or process-injection
  APIs in the visible IAT. If the protected code uses such APIs, it does so
  through dynamically-resolved imports that are not visible until runtime.
- Treat as **closed-source vendor crypto library**: usable as a black-box
  via its 10 exports, but not auditable from the on-disk image alone.

---

## 9. Reproducibility

All findings above were produced from the file at the URL shown at the top of
this document, with checksum
`sha256:f6c86de6e56e35442641dce113a7301bdbaf3129a5098544b266214a7a5f1b18`,
using only:

- `pefile` (Python) for the PE structures, sections, imports, exports,
  resources, TLS, debug, overlay and security-directory parsing,
- `capstone` (x86 32-bit) for the entry-point disassembly,
- `openssl pkcs7` / `openssl x509` for the Authenticode certificate chain,
- byte-level inspection (entropy, fingerprint scan, ASCII / UTF-16 string
  carving) of each section.

No part of the DLL was executed.
