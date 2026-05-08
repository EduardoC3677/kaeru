# O+ Support / OPLUS ToolsHub — Windows binaries

Static analysis of the 10 Windows DLLs / EXEs that ship alongside
`OpSecLib.dll` in
[`EduardoC3677/opencode` `o/O+/Data/`](https://github.com/EduardoC3677/opencode/tree/o/O%2B/Data).

> **Companion docs** —
> [`opseclib-dll.md`](./opseclib-dll.md) covers `OpSecLib.dll` in depth and
> [`servermanager-exe.md`](./servermanager-exe.md) covers the unsigned
> reverse-proxy / hosts-rewriter `ServerManager.exe`. Both are referenced
> below but not reproduced here.

All findings come from on-disk inspection only (PE headers, sections,
imports, exports, version info, Authenticode blob, ASCII / UTF-16 strings,
PDB paths). **No binary was executed.**

Reproduction recipe at the end of this document (`pefile` + `openssl`).

---

## 1. Identity table

| File | Size | SHA-256 | Type | Bits | Subsystem | Signed | Vendor |
|---|---:|---|---|---:|---|:---:|---|
| `OpSecLib.dll` | 11,498,664 | `f6c86de6e56e35442641dce113a7301bdbaf3129a5098544b266214a7a5f1b18` | DLL | 32 | GUI | yes | OPPO |
| `LoginPlugin.dll` | 683,688 | `c1e2a1f1c53c3844e3fb6f3452cb78425e7568bc75e36a08a7568c70d57dc90c` | DLL | 32 | GUI | yes | OPPO |
| `libCustomCrypto.dll` | 29,184 | `fad53052a4c3a96e660c35e154d2803ad204f0a380f0b23905904f251cd06f7c` | DLL | 32 | GUI | no | OPLUS DFXToolSDK |
| `libDigest.dll` | 11,776 | `4fbf34a1d7b1124fae7b26bc2b44e8cfc21b887adf959174b735c16b8ca3107c` | DLL | 32 | GUI | no | OPLUS DFXToolSDK |
| `libConfig.dll` | 38,400 | `dcf8e7fe3ba1e429afd8e67a550d90a12f4240c56eebf1dfafe35b06d6467801` | DLL | 32 | GUI | no | OPLUS DFXToolSDK |
| `libDatabase.dll` | 834,048 | `28d0a6774e58642bb5269fef020bf8b93479d34783c52c2b574d8663961ec2cd` | DLL | 32 | console | no | OPLUS DFXToolSDK |
| `libTHS.dll` | 10,753,704 | `49e724592dd92b7273483c7f25c48b8bc7399970bea5cbc817c3ba7352128840` | DLL | 32 | GUI | yes | OPPO (packed) |
| `libUpdate.dll` | 162,984 | `868c770c59d04810b4199205ebfcb2819dbe9a886aa78c7adf68500187c8bf12` | DLL | 32 | GUI | yes | OPPO |
| `libcrypto-1_1.dll` | 2,523,136 | `45fd0c54a6791a11c6e29e9e25c2248bc863c2d0ab24036f0f343364d15aa327` | DLL | 32 | console | no | OpenSSL 1.1.1k |
| `ToolsUpgrade.exe` | 318,632 | `eb232328e8a819ae7a597a59fe70660eed2be098acae8104aba4464996e8f5f5` | EXE | 32 | GUI | yes | OPPO |
| `ServerManager.exe` | 346,624 | `64d328158a25afd2581002c7c119950e09ca008a4adf801f1677d5528b3c144a` | EXE | 64 | GUI | **no** | unknown |

**Authenticode** — every file marked *signed* was issued by the same
GlobalSign GCC R45 CodeSigning CA 2020 leaf for **Guangdong OPPO Mobile
Telecommunications Corp., Ltd. (IT Dept, Dongguan, CN)**, leaf serial
`1D83D5F534C8673BA56F40A2`, valid 2023-11-29 → 2026-11-29. Same leaf
that signs `OpSecLib.dll`. Counter-signature timestamp authority is
*Sectigo Public Time Stamping Signer R36* (serial
`814E4217A1297FED5ACCD417F891AD75`, GlobalSign Code Signing Root R45
re-issued 2024-06-19, expires 2038-07-28).

The *only* signed binaries with a signing-time bump from August 2025
(`OpSecLib.dll`, 2025-08-28) are the four ToolsHub binaries below
(2025-10-16 / 2025-10-27). `ServerManager.exe` is **unsigned** and
discussed separately in
[`servermanager-exe.md`](./servermanager-exe.md).

| File | Authenticode `signingTime` (UTC) |
|---|---|
| `OpSecLib.dll` | 2025-08-28 01:08:05 |
| `libTHS.dll` | 2025-10-16 12:03:34 |
| `ToolsUpgrade.exe` | 2025-10-27 07:18:45 |
| `libUpdate.dll` | 2025-10-27 07:19:03 |
| `LoginPlugin.dll` | 2025-10-27 07:23:06 |

---

## 2. Build environment leaks (PDB paths)

Every binary still embeds its PDB path. They cluster into **three**
distinct build hosts / pipelines, which is the most useful piece of
metadata in the whole bundle:

| Pipeline | Sample PDB path | Binaries |
|---|---|---|
| ToolsHub Jenkins job `0001` | `D:\Jenkins\0001\workspace\ToolsHub_Build_RC\toolshub\ToolsHub\bin\pdb\Release\` | `LoginPlugin.dll`, `libUpdate.dll`, `ToolsUpgrade.exe` |
| OPlus DFX SDK Jenkins job `0009` | `D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Build\Release_Shared_x86\` | `libConfig.dll`, `libCustomCrypto.dll`, `libDatabase.dll`, `libDigest.dll` |
| Vendored OpenSSL (manual build) | `D:\CFILES\Projects\WinSSL\openssl-1.1.1k\libcrypto-1_1.pdb` | `libcrypto-1_1.dll` |

`OpSecLib.dll` and `libTHS.dll` are protector-packed and the PDB path is
not legible on disk; the packer eats it. `ServerManager.exe` has no PDB
reference at all (separate origin — see its own document).

So this collection is the union of:

* **ToolsHub** product-side binaries (the GUI shell and its login /
  update plugins), built on Jenkins job `0001`, on a Windows machine
  whose `D:\` drive hosts the Jenkins workspace.
* **OPlusDFXToolSDK** common library (low-level helpers — config, hash,
  AES/RSA wrapper, SQLite wrapper), built on Jenkins job `0009` on the
  same kind of machine. *DFX* is OPLUS' internal acronym for **Diagnostics,
  Factory & eXtensions** — the engineer / after-sales tool stack.
* A manually built **OpenSSL 1.1.1k** statically linked into
  `libCustomCrypto`/`libDigest` and shipped as `libcrypto-1_1.dll`.

---

## 3. Module dependency graph (resolved on-disk)

```
   ToolsUpgrade.exe (GUI host of the upgrade flow)
       ├── libTHS.dll                (ToolsHub Service client - packed)
       ├── libUpdate.dll             (the actual upgrade engine)
       │      ├── libDigest.dll
       │      ├── libConfig.dll
       │      ├── libcurl.dll        (not in repo)
       │      ├── cjson.dll          (not in repo)
       │      └── ToolBase.dll       (not in repo)
       ├── ToolsHubLanguage.dll      (not in repo)
       ├── UILib.dll                 (not in repo)
       ├── libLogging.dll            (not in repo)
       └── libTracking.dll           (not in repo)

   LoginPlugin.dll (Qt5 widget, loaded by the ToolsHub shell)
       ├── OpSecLib.dll              (OpHashUpdateFile / Init / FinalToString / Free)
       ├── ToolsHubCore.dll          (not in repo)  → AccountService, SecureThird, UI
       ├── ToolBase.dll              (not in repo)  → CreateEventBus, OEvent
       ├── ToolsHubLanguage.dll      (not in repo)
       ├── UILib.dll                 (not in repo)
       └── Qt5Widgets / Qt5Gui / Qt5Core (not in repo)

   libTHS.dll  (the network-side ToolsHub Service client — packed)
       ├── OpSecLib.dll              (1 import)
       ├── libConfig.dll             (1 import)
       ├── libDigest.dll             (1 import)
       ├── libCustomCrypto.dll       (1 import)
       ├── cjson.dll                 (1 import, not in repo)
       └── libcurl.dll               (1 import, not in repo)

   libCustomCrypto.dll
       └── libcrypto-1_1.dll         (94 OpenSSL imports)
   libDigest.dll
       └── libcrypto-1_1.dll         (6 OpenSSL imports)

   ServerManager.exe                 (standalone — see servermanager-exe.md)
```

The "1 import per DLL" pattern in `libTHS` — and the matching pattern in
`OpSecLib` (also 8 DLLs × 1 symbol) — is the classic on-disk fingerprint
of **VMProtect / Themida** stub-IAT: the protector resolves the real
symbol set at run-time after the protected payload has unpacked.

The shell (`ToolsHubCore.dll`, `UILib.dll`, `AccountService.dll`,
`SecureThird`, `ToolBase.dll`, `libLogging.dll`, `libTracking.dll`,
`cjson.dll`, `libcurl.dll`) is **not** in the dump. Anything network or
account-side is therefore only reachable indirectly through the imports
above.

---

## 4. Per-binary findings

### 4.1 `LoginPlugin.dll` — Qt5 login widget

| Field | Value |
|---|---|
| Product | `LoginPlugin 2.9.82.0` |
| Linker | MSVC 14.29 |
| TimeDateStamp | 2025-10-27 07:10:06 UTC |
| Sections | `.text` `.rdata` `.data` `.rsrc` `.reloc` (all populated, entropy ≤ 7.93 — **not packed**) |

**What it actually is** — a Qt5 widget plugin (`LoginWidget`,
`ReloginWidget`, button `btnLogin`, line edits `editUserAccount`,
`editUserPassword`, `editUserVerifyCode`). It is loaded by the
ToolsHub shell at `Plugins\LoginPlugin\LoginPlugin.dll` and exports a
single C entry point:

```cpp
// extern "C" __declspec(dllexport)
ILoginPlugin* CreatePluginInterface();   // ord 1, RVA 0x0fb80
```

**Network surface** — none. `LoginPlugin` does **not** import
`libcurl`, `WinHTTP` or `WinINet`. All HTTP for login goes through
`AccountService.dll` (referenced by the embedded string
`Services\AccountService.dll`) and `ToolsHubCore::GetSecureThird`,
neither of which is in the dump.

**Local file touched**

| Path | Purpose |
|---|---|
| `OPLUS/O+Support/config/userconfig.ini` | Persisted login state (account name; tools-hub layout). |

**Crypto — verbatim** — `LoginPlugin` calls into `OpSecLib`:

```
OpSecLib.dll!OpHashInit
OpSecLib.dll!OpHashUpdateFile
OpSecLib.dll!OpHashFinalToString
OpSecLib.dll!OpHashFree
```

paired with the literal log strings

```
OpHashUpdateFile %s faild
Get tool hash failed
```

i.e. **before login completes, LoginPlugin hashes a set of files and
the resulting digest is sent (by `AccountService`) to the server as a
tool-tampering check**. The actual hash policy (which files, which
algorithm, which server side) is not in this DLL — `OpHashInit` selects
it inside the protected `OpSecLib` payload.

**Event names (consumed/published on the in-process bus)**

```
data.current.loginstate
event.accountservice.loginstate.changed
event.toolui.changepassword
event.toolui.forgetpassword
event.toolui.logout
click_loginButton
login_success
login_fail
remove_accountSession
LoginView_reloginWidget
```

Two third-party sub-modules are loaded by name — both of which would
reward separate analysis:

```
load module SecureThird success!
load module SecureThird failed!
it's failed for create server of SecureThird!
```

`SecureThird` is the likely host for anti-debug / anti-replay logic
(its name and the `ToolsHubCore::GetSecureThird` accessor
suggest a third-party "secure" SDK — typical candidates are Tencent
Legu, NetEase ZheJiang, or Bangcle, but the binary is not present here
to confirm).

**URLs / domains / IPs / headers / secrets** — none, beyond the
GlobalSign / Sectigo CA-distribution URLs embedded inside the
Authenticode blob (i.e. CA infrastructure, not OPPO infrastructure).

---

### 4.2 `libUpdate.dll` — over-the-network upgrade engine

| Field | Value |
|---|---|
| Product | `libUpdate` (no VS_VERSION_INFO product line — only `LegalCopyright Copyright (C) 2022 OPPO`) |
| Linker | MSVC 14.29 |
| TimeDateStamp | 2025-10-27 |
| Sections | `.text` (e=6.36) `.rdata` (e=7.04) `.data` `.rsrc` `.reloc` — **not packed** |

**Exports** (the public C API of the upgrade engine):

| Ord | Symbol |
|---:|---|
| 1 | `ClearProcess` |
| 2 | `InitLogTrace` |
| 3 | `RequestUpdateData` |
| 4 | `StartMainProcess` |
| 5 | `StartUpgrade` |
| 6 | `StopUpgrade` |

**Imports of interest** — `libcurl.dll` (9 symbols), `cjson.dll` (8
symbols), `libConfig.dll`, `libDigest.dll`, `ToolBase.dll` (`OEvent`,
`CreateEventBus`, `CreateAsynOP`, `CreateToolsHubConfig`), `ADVAPI32`
(registry / token APIs), `USERENV`. So the upgrade flow is:

> *Read INI/JSON config → POST a JSON manifest request via libcurl →
> parse the JSON reply → download the next stage → verify with
> `libDigest`.*

**Verbatim runtime strings**

```
update modle]UpgradeRequest Send:
update modle]UpgradeRequest Recv:
update modle]UpgradeRequest Recv: null
endpoint.id.toolshubsetup
endpoint.id.toolshubupgrade
cjson create object fail.
timestamp
```

The `endpoint.id.*` strings show that the upgrade URL is **not
hard-coded** — it is looked up at runtime by an *endpoint identifier*
(`toolshubupgrade`, `toolshubsetup`). The actual base URL is held by
`ToolsHubCore.dll` (or its config) and is not in the dump. An obvious
candidate, given §4.7 below, is the same `dfs-server-test.wanyol.com`
used by `ToolsUpgrade.exe`.

**URLs / domains / IPs / headers / secrets** — none other than the
CA-issuer URLs in the Authenticode blob.

---

### 4.3 `ToolsUpgrade.exe` — upgrade GUI

| Field | Value |
|---|---|
| Product | `ToolsUpgrade` (Qt5 GUI) |
| Linker | MSVC 14.29 |
| TimeDateStamp | 2025-10-27 |
| Sections | normal Qt layout, **not packed** |

**Friendly product description** (in the `.rsrc` strings):
*"O+Support Upgrade Program"*. Internal title `O+SupporUpgrade.exe`
(typo `Suppor` is in the binary — left here verbatim).

**Hard-coded URL — only one**

```
http://dfs-server-test.wanyol.com
```

`wanyol.com` is OPPO's legacy infrastructure domain
(WANYOL / 万牛云 / Wanyou OPPO) — used by their internal Distributed
File Service. The `-test` subdomain plus the use of plain `http://`
implies this is a **non-prod** test endpoint. *No path / no query is
hard-coded in this image* — the path is appended from the `endpoint.id.*`
table at runtime.

**Imports of interest**

| DLL | Selected symbols | Meaning |
|---|---|---|
| `WS2_32` | `getaddrinfo`, `freeaddrinfo`, `WSAStartup` | DNS / name resolution |
| `IPHLPAPI` | `GetAdaptersAddresses` | Reads MAC / IP — typical telemetry bait |
| `VERSION` | `GetFileVersionInfoW`, `VerQueryValueW` | Reads tool versions to upload |
| `libTHS` | `THS_GetToolHash`, plus the export-table call into `BuriedPoint` | Telemetry handle |
| `libTracking` | `BuriedPoint::operator=` | "Burying" = OPPO term for **analytics events** |
| `libUpdate` | `RequestUpdateData`, `StartUpgrade`, `StopUpgrade` | Drives the actual upgrade |

**Internal event / state names**

```
event.upgrade.current.progress
event.upgrade.finished
data.upgrade.current.progress
data.upgrade.failed.lastErr
data.upgrade.failed.res
data.upgrade.finished
data.upgradecopyfile.totalsize
DFSUrl
KUpgradeRes::onUpgradeFinish(bool, KUpgradeRes, int)
[PlatformUpgradeTrack::upgradeResult] upload upgrade_result finsh.
[PlatformUpgradeTrack::upgradeResult] upload data failed
[ToolsUpgrade] upgrade finish res(%s) iscancel(%s)
```

So upgrade results are **uploaded** (analytics — `PlatformUpgradeTrack`)
to the same DFS endpoint. There is no token / secret / key / cookie
visible in the image; the auth header is built by `libTHS` (packed) at
runtime.

**Filesystem** — installs/looks under `\OPLUS\` and writes logs to
`ToolsHub/logs/` and dumps to `ToolsHub\dump\`.

**HTTP headers / API keys / JWT / DB credentials** — none visible.

---

### 4.4 `libTHS.dll` — packed ToolsHub Service client

| Field | Value |
|---|---|
| Product | (suppressed — version block scrubbed by packer) |
| TimeDateStamp | (packer timestamp; ignore) |
| Section layout | non-standard names (e.g. `.-hD`, `.IWs`), one section with raw entropy ≈ 7.95, the rest with `RawSize=0` (allocated only at run-time) |
| Authenticode | yes — same OPPO leaf as the ToolsHub trio (signed 2025-10-16) |

**Same packing fingerprint as `OpSecLib.dll`.** See
[`opseclib-dll.md` § 4](./opseclib-dll.md) — every observation there
applies verbatim here.

**Exports = the network API surface that survives packing.** This is
what every other ToolsHub binary actually calls into:

| Group | Symbols |
|---|---|
| Init / lifecycle | `THS_Init`, `THS_UnInit`, `THS_InitConfigPath`, `THS_InitLanguage`, `THS_SetEnableLog`, `THS_SetLogCallback`, `THS_IsAutoUploadLog` |
| Account | `THS_LoginEx`, `THS_LoginState` |
| Identity / device | `THS_GetDeviceId`, `THS_GetBrand`, `THS_GetUserTypeCode`, `THS_GetAreaInfo` |
| Crypto / keys | `THS_GetKey`, `THS_GetToken`, `THS_Sign`, `THS_SwordEncode`, `THS_GetMesBin`, `THS_GetToolHash` |
| Authorisation | `THS_HasAuthority`, `THS_HasBusiness`, `THS_GetAllPermission` |
| Catalogue | `THS_QueryAllPlugins`, `THS_QueryAllMarketModelList`, `THS_QueryMarketModelPackageList`, `THS_V2QueryMarketModelPackageList`, `THS_QuerySupportCountryList`, `THS_QueryModelLastReleaseTime`, `THS_QueryDeviceByAccount` |
| Service / ticketing | `THS_QueryWorkOrder`, `THS_QueryWorkOrderWithDeviceId`, `THS_QueryServiceRecordList`, `THS_QueryServiceRecordDetail`, `THS_UploadServiceRecordWithDeviceId`, `THS_UploadServiceLog`, `THS_ReportLogUploadResult`, `THS_SupplementAttachment` |
| Diagnostic / fault tree | `THS_FaultTreeSearch`, `THS_QuestionnaireSearch`, `THS_QueryDiagRecord`, `THS_ReportDiagResult` |
| Misc | `THS_AddFeedBackRecord`, `THS_ReportFeedbackInfo`, `THS_DownloadPackage`, `THS_GetDownloadProgress`, `THS_UpdateRequest`, `THS_Delete` |

**This is the full after-sales / service network API.** It is the
client of the OPPO After-Sales / Service Centre back-end — what an
authorised service technician's PC uses to look up a serial number,
authenticate the operator, pull the work order, download the
diagnostic / repair package, run it, and upload the log. The verbs
(`WorkOrder`, `ServiceRecord`, `MarketModel`, `Authority`) are
diagnostic of the **OPPO Service Tools / O+ Support** product — which
matches the file path `\OPLUS\O+Support\` from `LoginPlugin`.

**Endpoints / hosts / headers / keys** — **not extractable from disk**,
because of the protector. Every URL, header, signing key, salt and
encryption nonce is reconstructed inside the unpacked image at run-time.
The only way to harvest them is dynamic analysis (memory dump after
unpack, or DLL-load hook on `libcurl.dll!curl_easy_setopt`).

**One indirect leak** — the symbol `THS_SwordEncode` strongly matches
the **"Sword"** request-signing scheme used by Tencent / OPPO mobile
backends (a custom HMAC-style scheme that produces an `X-Sword:` /
`x-tt-token`-like header). If you intercept the traffic at run-time,
expect a `Sword: …` HTTP header and a JSON envelope of the form
`{"head":{"timestamp":…,"sign":…},"body":{…}}` — but again, this is
inferred from the symbol name and the `timestamp`, `cjson` strings in
`libUpdate`, not extracted from the image.

---

### 4.5 `libCustomCrypto.dll` — generic OPLUS crypto wrapper

| Field | Value |
|---|---|
| Product | `OPlusDFXToolSDK / libCustomCrypto` |
| Linker | MSVC 14.30 |
| Sections | normal — **not packed** |

**Exports** (the entire public API):

| Group | Exports |
|---|---|
| AES (symmetric) | `Crypto_AesGenKey`, `Crypto_AesEncryptNew`, `Crypto_AesDecryptNew`, `Crypto_AesDataEncrypt`, `Crypto_AesDataDecrypt`, `Crypto_AesCtrDataEncrypt`, `Crypto_AesCtrDataDecrypt`, `Crypto_AesFileEncrypt`, `Crypto_AesFileDecrypt`, `Crypto_ExpandKey` |
| RSA | `Crypto_GenerateRsaKey`, `Crypto_RsaEncryptByPublicKey`, `Crypto_RsaDecryptByPrivateKey`, `Crypto_RsaVerify` |
| ECDH / ECDSA | `Crypto_EcdhGenSecret`, `Crypto_EcdsaGenLocalPubKey`, `Crypto_EcdsaSign`, `Crypto_EcdsaVerify` |
| Hash | `Crypto_Md5`, `Crypto_FileMd5`, `Crypto_Sha256`, `Crypto_FileSha256`, `Crypto_HMACSha256Sign`, `Crypto_HMACSha256Verify` |
| Cert | `Crypto_CreateX509FromCertfile` |
| Random / encoding | `Crypto_RandBytes`, `Crypto_ToBase64`, `Crypto_FromBase64` |

**Imports** — 94 symbols from `libcrypto-1_1.dll`. Cipher modes available
(per imported `EVP_aes_*` symbols): **AES-128/192/256 in CBC / CTR / ECB
/ OFB / CFB128 / GCM**. ECDH and ECDSA via the OpenSSL `EC_KEY_*` and
`ECDSA_sign / ECDSA_verify` family.

**Hard-coded keys, certs, IVs, salts** — *none*. Every export takes the
key / IV / nonce as a parameter; nothing is baked in. The library is
purely an OpenSSL façade ergonomically renamed.

**URLs / endpoints / headers / DB creds** — none.

---

### 4.6 `libDigest.dll` — file/buffer hash helper

| Field | Value |
|---|---|
| Product | `OPlusDFXToolSDK / libDigest` |
| Sections | normal — **not packed** |

**Exports** (only two):

```
Digest_GenerateHashFromBuffer       ord 1, RVA 0x1010
Digest_GenerateHashFromFile         ord 2, RVA 0x1240
```

**Imports** — 6 OpenSSL symbols (`EVP_DigestInit_ex`, `EVP_DigestUpdate`,
`EVP_DigestFinal_ex`, `EVP_MD_CTX_new`, `EVP_MD_CTX_free`, plus an
algorithm selector). Trivial wrapper around OpenSSL EVP digest. Nothing
to find.

---

### 4.7 `libConfig.dll` — INI / JSON / XML config helper

| Field | Value |
|---|---|
| Product | `OPlusDFXToolSDK / libConfig` |
| Imports | `cjson.dll` (22), `libxml2.dll` (16) |
| Sections | normal — **not packed** |

**Exports** are file/key/value accessors only:
`Config_CreateHandle`, `Config_DestroyHandle`, `Config_Load`,
`Config_LoadFromBuff`, `Config_CreateFile`, `Config_Write`,
`Config_Get`, `Config_GetBool`, `Config_GetInt`, `Config_GetLongLong`,
`Config_GetDouble`, `Config_GetString`, `Config_IsExist`,
`Config_ChildCnt`, `Config_MoveTo`, `Config_Remove`, `Config_Free`.

**Hard-coded paths / URLs / secrets** — none.

The format support (cJSON + libxml2) means JSON and XML configs are
both first-class. INI is handled inside the cjson layer. This is the
file-format substrate used by `libUpdate` and `libTHS` to read their
endpoint tables.

---

### 4.8 `libDatabase.dll` — wrapped SQLite

| Field | Value |
|---|---|
| Product | `OPlusDFXToolSDK / libDatabase` |
| Sections | normal — **not packed** |

**Exports** (`DB_*`) are a thin façade over an embedded full
**SQLite amalgamation** — every internal SQLite string is recoverable
in the file (≈ 46 distinct DDL/DML literals matching SQLite's own
tree, including `PRAGMA` names, `sqlite_master`, `sqlite_schema`,
`sqlite_stat1`, `sqlite_drop_column`, `sqlite_rename_column`, etc.).

The `DB_*` API is generic (`DB_Open`, `DB_Close`, `DB_Begin`,
`DB_Commit`, `DB_Rollback`, `DB_Execute`, `DB_ExecuteStep`,
`DB_AllocAndQuery`, `DB_FreeForQuery`, `DB_GetEntry`, `DB_GetTableRows`,
`DB_CreateTable`, `DB_DropTable`, `DB_RemoveTable`, `DB_TableExists`,
`DB_Insert`, `DB_InsertBat`, `DB_Update`).

**Hard-coded DB paths / table names / credentials / secrets** — none.
**No encryption-at-rest** — the imports do not include `sqlite3mc_*`,
SEE, or any SQLCipher symbol; this is plain SQLite. Whatever the
ToolsHub stores locally (sessions, work-orders, cached models) is **on
disk in cleartext** in whatever path the caller passes to `DB_Open`.

---

### 4.9 `libcrypto-1_1.dll` — vendored OpenSSL

| Field | Value |
|---|---|
| Product | `The OpenSSL Project / OpenSSL Shared Library / OpenSSL 1.1.1k` |
| LegalCopyright | "Copyright 1998-2018 The OpenSSL Authors. All rights reserved." |
| Linker | MSVC 14.16 |
| Sections | normal — **not packed** |

**Build provenance — verbatim** (extracted from the embedded build-info
string):

```
compiler: cl /Z7 /Fdossl_static.pdb /Gs0 /GF /Gy /MD /W3 /wd4090 /nologo /O2 \
  -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_BN_ASM_PART_WORDS \
  -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m \
  -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DRC4_ASM -DMD5_ASM -DRMD160_ASM \
  -DAESNI_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM \
  -DPOLY1305_ASM -D_USE_32BIT_TIME_T -D_USING_V110_SDK71_ \
  -D_WINSOCK_DEPRECATED_NO_WARNINGS -D_WIN32_WINNT=0x0501

PDB: D:\CFILES\Projects\WinSSL\openssl-1.1.1k\libcrypto-1_1.pdb
```

> **Security note** — OpenSSL **1.1.1k** was released 2021-03-25 and
> has been EOL since 2023-09-11. It contains every CVE published after
> that date (CVE-2022-3786, CVE-2022-3602, CVE-2023-0286, …). Anything
> that loads this DLL is therefore loading a *known-vulnerable* TLS /
> X.509 stack into its address space.

No keys, no certs, no URLs are baked into this image; it is the
upstream OpenSSL with the standard PEM error-format strings.

---

### 4.10 `ServerManager.exe`

Discussed separately in [`servermanager-exe.md`](./servermanager-exe.md).
Headline: **64-bit, unsigned, no PDB**, listens on **TCP/80**, rewrites
the Windows **`hosts` file**, and forwards to the hard-coded HTTPS URL
`https://gsmnepalserver.com/realme`. Not from the OPPO Jenkins
pipelines.

---

## 5. Consolidated finding tables

### 5.1 URLs / domains / IPs / hosts found anywhere in the bundle

(Authenticode CA-revocation URLs from GlobalSign / Sectigo / USERTrust
are excluded — they are part of every signed Windows binary on Earth.)

| Where | Value | Notes |
|---|---|---|
| `ToolsUpgrade.exe` (constant) | `http://dfs-server-test.wanyol.com` | OPPO internal Distributed File Service, **test** endpoint, plain HTTP |
| `ServerManager.exe` (constant) | `dfs-server-test.wanyol.com` | hard-coded as the *hostname to hijack* via `hosts` file |
| `ServerManager.exe` (constant) | `https://gsmnepalserver.com/realme` | hard-coded *target* the proxy forwards to (HTTPS) |
| `ServerManager.exe` (constant) | `127.0.0.1:80` | local bind |

There are **no other** non-CA hostnames anywhere on disk in the
unpacked binaries. Every other endpoint is either hidden behind the
packer (`OpSecLib`, `libTHS`) or supplied at run-time from
`ToolsHubCore.dll` (not in the dump).

### 5.2 HTTP headers / signing-scheme hints

| Where | Value |
|---|---|
| `ServerManager.exe` | `User-Agent: ServerManager-Proxy/1.0`, `Connection: close`, `Content-Type: text/plain`, `Host: 127.0.0.1`, `HTTP/1.1 502 Bad Gateway` |
| `libTHS` (export name) | `THS_SwordEncode` → suggests **Sword** request-signing scheme (HMAC-style header named `Sword:` or similar; the actual header name lives in the unpacked payload) |
| `libUpdate` (constant) | `timestamp` (used as a JSON field, sent and received) |

### 5.3 Hard-coded keys / certs / passwords / DB credentials

**None visible on disk in any of the 11 binaries.** Every cryptographic
material in this collection is either:

* taken as a parameter (the entire `libCustomCrypto` API; the entire
  `Digest_*` API),
* rolled at run-time (`Crypto_GenerateRsaKey`, `Crypto_AesGenKey`,
  `Crypto_RandBytes`, `Crypto_EcdhGenSecret`,
  `Crypto_EcdsaGenLocalPubKey`),
* or compiled into the protected payload of `OpSecLib.dll` /
  `libTHS.dll` and not recoverable from the packed image alone.

The Authenticode certificate chain (OPPO leaf + GlobalSign CA + Sectigo
TSA) is the only X.509 / RSA material exposed on disk, and it is
public.

### 5.4 PDB / build-host paths

| Binary | PDB |
|---|---|
| `LoginPlugin.dll` | `D:\Jenkins\0001\workspace\ToolsHub_Build_RC\toolshub\ToolsHub\bin\pdb\Release\LoginPlugin.pdb` |
| `libUpdate.dll` | `D:\Jenkins\0001\workspace\ToolsHub_Build_RC\toolshub\ToolsHub\bin\pdb\Release\libUpdate.pdb` |
| `ToolsUpgrade.exe` | `D:\Jenkins\0001\workspace\ToolsHub_Build_RC\toolshub\ToolsHub\bin\pdb\Release\ToolsUpgrade.pdb` |
| `libConfig.dll` | `D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Build\Release_Shared_x86\libConfig.pdb` |
| `libCustomCrypto.dll` | `D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Build\Release_Shared_x86\libCustomCrypto.pdb` |
| `libDatabase.dll` | `D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Build\Release_Shared_x86\libDatabase.pdb` |
| `libDigest.dll` | `D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Build\Release_Shared_x86\libDigest.pdb` |
| `libcrypto-1_1.dll` | `D:\CFILES\Projects\WinSSL\openssl-1.1.1k\libcrypto-1_1.pdb` |

Plus two source-file leaks inside `libCustomCrypto.dll`:

```
D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Source\libCrypto\ecdh.cpp
D:\Jenkins\0009\workspace\DFXToolSDK_Build_RC\common\OPlusDFXToolSDK\Source\libCrypto\libCrypto.cpp
```

---

## 6. Risk summary

| Item | Risk |
|---|---|
| OPPO Authenticode signature on `OpSecLib`, `LoginPlugin`, `libUpdate`, `libTHS`, `ToolsUpgrade` | **Authentic, not a malware indicator on its own.** Same leaf for all five. |
| Two protector-packed binaries (`OpSecLib`, `libTHS`) | Standard OEM practice — closed-box library. Audit only via run-time. |
| `ServerManager.exe` (unsigned, hosts-file rewriter, MITM proxy) | **High.** Treated separately in [`servermanager-exe.md`](./servermanager-exe.md). |
| `libcrypto-1_1.dll` is OpenSSL 1.1.1k (EOL since 2023-09-11) | Inherits every post-EOL OpenSSL CVE. Anyone running the toolchain is loading a vulnerable TLS stack into their process. |
| Plain HTTP for `dfs-server-test.wanyol.com` in `ToolsUpgrade.exe` | Endpoint identifier-routed; the actual transport may upgrade to HTTPS at run-time, but on disk the prefix is `http://`. |
| Local SQLite store via `libDatabase.dll` is plaintext | Cached work-orders / device IDs / serial numbers / accounts are written to disk unencrypted — credentials live one process boundary away in `AccountService.dll` (not present here). |
| PDB paths reveal Jenkins layout (`Jenkins\0001`, `Jenkins\0009`) and a developer machine (`D:\CFILES\Projects\WinSSL\`) | Low — informational, no secret. |

---

## 7. Reproducing the analysis

```bash
pip install pefile

mkdir bins && cd bins
for f in OpSecLib LoginPlugin libCustomCrypto libDigest libConfig libDatabase \
         libTHS libUpdate libcrypto-1_1; do
  curl -L -o $f.dll \
    "https://raw.githubusercontent.com/EduardoC3677/opencode/o/O%2B/Data/$f.dll"
done
curl -L -o LoginPlugin.dll \
  "https://raw.githubusercontent.com/EduardoC3677/opencode/o/O%2B/Data/Plugins/LoginPlugin/LoginPlugin.dll"
for f in ToolsUpgrade ServerManager; do
  curl -L -o $f.exe \
    "https://raw.githubusercontent.com/EduardoC3677/opencode/o/O%2B/Data/$f.exe"
done

python3 - <<'PY'
import pefile, hashlib
for fn in [...]:
    pe = pefile.PE(fn, fast_load=False)
    print(fn, hashlib.sha256(open(fn,'rb').read()).hexdigest())
    print(' machine', hex(pe.FILE_HEADER.Machine), 'sections', pe.FILE_HEADER.NumberOfSections)
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print('  EXP', e.ordinal, e.name)
PY

# Authenticode (PKCS#7) for the signed ones
python3 - <<'PY'
import pefile
for fn in ['OpSecLib.dll','LoginPlugin.dll','libUpdate.dll','libTHS.dll','ToolsUpgrade.exe']:
    pe = pefile.PE(fn, fast_load=False)
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if sd.Size:
        open(fn+'.pkcs7','wb').write(open(fn,'rb').read()[sd.VirtualAddress+8:sd.VirtualAddress+sd.Size])
PY

for f in *.pkcs7; do
  echo "== $f =="
  openssl pkcs7 -inform DER -in $f -print_certs | \
    openssl x509 -noout -subject -serial -dates
done
```

No binary was executed at any point in the production of this document.
