# MTK Download Agent / BROM — SLA & Anti-Clone keys

**Source repository analysed:** [`EduardoC3677/opencode`](https://github.com/EduardoC3677/opencode.git),
sub-tree `O+/Plugins/`.
This is the **OPLUSFLASHTOOLNEXT** Windows flash-tool stack (a.k.a. the
"OPLUS ToolsHub" / "O+ Support" after-sales tool), which on top of the
material analysed in [`oplus-toolshub-bins.md`](./oplus-toolshub-bins.md)
ships a complete copy of MediaTek's reference flash-tool SDK,
**customised by OPlus / OPPO**, with the live OEM cryptographic material
needed to talk to MediaTek's **BootROM** (BROM) and **Download Agent**
(DA) over USB-DL.

The analysis is purely static. No device was flashed, no DA was executed,
nothing was decrypted. Reproduce with
[`scripts/analysis/extract_mtk_sla_keys.py`](../../scripts/analysis/extract_mtk_sla_keys.py).

> **Why this matters for kaeru.** kaeru patches LK; it does not currently
> touch the MTK BROM/DA flow. But this tree shows _exactly_ which OEM
> keys are baked into eFuse on each SoC the OPlus tool supports, and
> consequently what kaeru would need (or not need) to interpose if it
> ever wanted to ride on top of an OEM-flash session. The single biggest
> finding — that the very first RSA-2048 modulus hard-coded in
> `SLA_Challenge.dll` matches the per-SoC AC modulus shared by **seven**
> MediaTek SoCs (MT6763, MT6833, MT6853, MT6873, MT6877, MT6885,
> MT6889) — means those seven SoCs are unlocked from the host with
> exactly the same OEM key.

---

## 1. Inventory of MTK-relevant artefacts

### 1.1 Locations inside the cloned `O+/` tree

| Path (relative to `O+/`) | Purpose |
| --- | --- |
| `Plugins/resource/FlashResource/mtkSocPlatformList.json` | Master list of supported MTK SoCs and which DA generation they require (V5 vs V6). |
| `Plugins/resource/MTKResource/MTK/<SoC>/auth_sv5.auth` | Per-SoC **Anti-Clone authentication blob** consumed by the BROM during USB-DL handshake (15 files, one per SoC). |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/SLA_Challenge.dll` | **Signed OPlus build** of the SLA challenge DLL (2021-11-23). Contains four hard-coded RSA-2048 public keys + the public exponent `0x010001`. Imports `LIBEAY32.dll` (classic OpenSSL). |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/Resources/SLA_Challenge.dll` | **Neutral MediaTek stub** of the same DLL (TimeDateStamp 2006-08-13, no LIBEAY32 import, no embedded keys). The stub MTK ships in its reference SDK. Co-exists with the OPlus build as a fallback / reference. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/Resources/oplusD2/<hex>` | Five high-entropy opaque blobs (787 938 / 1 034 722 / 653 202 bytes). Likely **encrypted DA payloads** ("OPlus D2" — second-stage download agents). Three of the five are byte-identical (multiple filenames pointing at the same content). All-zero strings, no PE / GFH header — the encryption key lives in `LibOplusMtkV5Callback.dll`. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/FTLibMtkCore.dll` | The MediaTek FlashTool core (1.85 MiB). Contains the entire BROM/DA/SLA orchestration glue — function names, eFuse-field names, BROM-stage callbacks. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/ModMtkV5FlashWorker.dll` | V5-generation MTK flash worker. Auth-file consumer. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV6FlashWorker/ModMtkV6FlashWorker.dll` | V6-generation MTK flash worker. Talks about `efuse.img`, `CMD:READ-EFUSE`, `CMD:WRITE-EFUSE`, `preloader_sig_ver`, `auth_sv5.auth`, `DA_BR.bin`. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkOfpPackageParser/ModMtkOfpPackageParser.dll` | OPLUS Firmware Package (`.ofp`) parser. References `EFUSE_CONFIG`, `EFUSE_INI`, `OPLUS_DEFINE_20240326_DA_KEY_VER_`, `AES_cfb128_encrypt`, `AES_set_encrypt_key`. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV6SfpPackageParser/ModMtkV6SfpPackageParser.dll` | "Secure Firmware Package" V6 parser. Lists slot pairs `preloader_a`, `preloader_b`, `preloader_raw_a`, `preloader_raw_b`. |
| `Plugins/FLASH_SRV/FlashTool_SDK_Full/LibOplusMtkV5Callback.dll` | OPlus V5 callback library. Owns the resource-resolution namespace `http://www.oppo.com/rom\…` (see §6). |

### 1.2 The MTK SoC list

`mtkSocPlatformList.json` enumerates **24 SoCs** in two generations:

| Generation | Count | SoCs |
| --- | --- | --- |
| **V6** (newer DA, anti-rollback, AArch64 LK) | 10 | MT6897, MT6991, MT6878, MT6989, MT6985, MT6983, MT6789, MT6895, MT6896, MT6835 |
| **V5** (legacy DA, ARMv7 LK) | 14 | MT6833, MT6877, MT6765, MT6893, MT6853, MT6873, MT6885, MT6889, MT6779, MT6768, MT6769, MT6781, MT6785, MT6771 |

`auth_sv5.auth` files exist on disk for **15 V5 SoCs**: the 14 above plus
two extra OPlus-internal preloader revisions of MT6765 (`MT6765_18540`,
`MT6765_20271`) and one of MT6771 (`MT6771_18531`). MT6768, MT6781, and
MT6785 are listed in the SoC catalogue but no auth blob is provided in
this tree.

> **No `auth_sv6.auth` files are shipped in this tree.** The V6 DA pipeline
> uses a different, anti-rollback-aware authentication scheme keyed on
> `OPLUS_DEFINE_20240326_DA_KEY_VER_` and `preloader_sig_ver`; the keys
> live elsewhere (likely inside the encrypted `oplusD2/*` blobs and/or
> `ModMtkV6FlashWorker.dll`). They are out of scope for the SV5 SLA
> extraction below.

---

## 2. `SLA_Challenge.dll` — the OPlus host-side SLA keys

`SLA_Challenge.dll` is the standard MediaTek extension point in the
flash-tool: when the BROM (or DA, post-jump) issues a **Serial Link
Authentication** challenge, the flash-tool calls into this DLL to
produce the response. MTK ships a neutral stub; OEMs replace it with
their own build that holds the OEM public keys.

This tree contains **both** copies. They diverge dramatically.

### 2.1 The OPlus build (signed, 2021)

* **Path:** `O+/Plugins/FLASH_SRV/FlashTool_SDK_Full/SLA_Challenge.dll`
* **Size:** 24 576 bytes
* **SHA-256:** `3afa217793fbc4f8fb8671fec07ae77d09c65ade7bb0f8ac3c34b95271a16349`
* **Machine:** `0x14c` (i386)
* **TimeDateStamp:** `0x619c8913` → 2021-11-23 06:24:19 UTC
* **LinkerVersion:** 6.0
* **VS_VERSION_INFO:** CompanyName `Customer`, FileDescription `SLA Challenge DLL`, OriginalFilename `SLA_Challenge.dll`, FileVersion `1, 0, 0, 1`, LegalCopyright `Copyright c 2006`. The "Customer" placeholder is intentional — MTK's reference template just gets recompiled with the OEM payload.
* **Sections:** `.text` (RAW=0x1000, ENT=3.18), `.rdata` (0x1000, 0.97), `.data` (0x1000, 3.46), `.rsrc` (0x1000, 1.01), `.reloc` (0x1000, 0.45). No packing.
* **Imports:**
  - `LIBEAY32.dll` ordinals 117, 484, 486, 491, 497, 3315, 4757 — i.e. the BIGNUM + RSA primitives (`BN_new`, `BN_bin2bn`, `BN_bn2bin`, `BN_num_bits`, `BN_set_word`, `RSA_new`, `RSA_public_encrypt` / `RSA_size`).
  - `MSVCRT.dll`: `fopen`, `fclose`, `fflush`, `fprintf`, `printf`, `malloc`, `free`, `_initterm`, `_adjust_fdiv`.
  - `KERNEL32.dll`: `DisableThreadLibraryCalls`.
* **Exports (5):**

  | Ord | Symbol | Notes |
  | --- | --- | --- |
  | 1 | `SLA_Challenge` | Standard BROM-side challenge entry-point. Opens `C:\sla.log`, writes `challenge_in is: …` then `challenge_in_len is: %d`, calls into a wrapper that loads one of the 4 RSA keys via `BN_bin2bn`, then `RSA_public_encrypt` over the input, writes `pp_challenge_out` back. |
  | 2 | `SLA_Challenge_END` | Free-context stub. |
  | 3 | `SLA_Feature_Config` | Feature-flag query. Logs `"SLA_Feature_Config is called"`. |
  | 4 | `DA_SLA_Challenge` | **DA-side variant** of the challenge. Same workflow but called after the DA has been jumped to. Larger frame (`sub esp, 0x904`). |
  | 5 | `DA_SLA_Challenge_END` | Free-context stub. |

  The pair `SLA_Challenge` / `DA_SLA_Challenge` mirrors MediaTek's
  documented split between BROM-stage SLA and DA-stage SLA — two
  independent challenge contexts that the host has to satisfy on every
  flash session for a secured device.

* **Visible log strings (literal, in-binary):**
  ```text
  C:\sla.log
  ----challenge_in is:
  ----challenge_in_len is: %d
  ----Rsa Encrypted Data(pp_challenge_out):----
  ----challenge_out_len : %d
  size is: %d
  0x%02x,
  md == NULL
  SLA_Feature_Config is called
  ```
  These are the verbatim format strings written to `C:\sla.log` while
  flashing — direct evidence that the response is `RSA_public_encrypt`
  (not sign / not verify) of `challenge_in` under one of the four keys
  below.

### 2.2 The four hard-coded RSA-2048 SLA / Anti-Clone keys

Four 512-character ASCII-hex strings live consecutively in the `.rdata`
section, separated by the public exponent `010001` and a few padding
bytes. All four use the same exponent **e = 0x010001** (= 65537).

| # | `.rdata` offset | First 16 B | Last 16 B | SHA-256 of modulus |
| --- | --- | --- | --- | --- |
| 1 | `0x3018` | `c43469a95b143cdc63ce318fe32bad35` | `38df846366926993097222f90628528f` | `1a89bd533b633a5b6e5c8ad908790f2dce3284f70525a7570a1101870096176b` |
| 2 | `0x321c` | `8e02cdb389bbc52d5383ebb5949c895b` | `f905a7456af675a04af1118ce71e36c9` | `d3a44ea86d235793c1e638ff419502071e948bf1e7e8921ef3e5f2706ec7f686` |
| 3 | `0x3420` | `707c8892d0de8ce0ca116914c8bd277b` | `13561b9f6ea65bd2516de950f08b2e81` | `0456e7540f2c459ab2ce910f72a15c4000a8aadde1f9acd5c416575aa3ac34b6` |
| 4 | `0x3624` | `a243f6694336d527c5b3ed569ddd0386` | `09c0a09e3d51d64a4c4ce026fad24cd7` | `664471dd6a667ccc62fbcd3fc1885243d2442db81e7fe8f0a003f3130760000a` |

All four are valid RSA-2048 moduli (last byte odd; high bit set on
keys #1, #2, #4; key #3 has high bit clear, i.e. effective length 2047
bits — still a legal modulus).

The full hex of every modulus is reproduced in
[`scripts/analysis/extract_mtk_sla_keys.py`](../../scripts/analysis/extract_mtk_sla_keys.py)
(re-extracts them on demand from `SLA_Challenge.dll`).

### 2.3 The MTK stub (neutral, 2006)

* **Path:** `O+/Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/Resources/SLA_Challenge.dll`
* **Size:** 24 576 bytes
* **SHA-256:** `f75a94e4c32a6a9862239c7ab6449291467660cafc2e4c221863a8db5d65c5ad`
* **TimeDateStamp:** `0x44df573b` → 2006-08-13 16:45:47 UTC. This is the canonical date that ships in MediaTek's SDK template.
* **Imports:** `MSVCRT.dll` (`malloc`, `free`, `_initterm`, `_adjust_fdiv`), `KERNEL32.dll` (`DisableThreadLibraryCalls`). **No LIBEAY32.** **No `LIBCRYPTO`.** **No crypto at all.**
* **Exports (2):** `SLA_Challenge` (RVA `0x1000`), `SLA_Challenge_END` (RVA `0x1010`). The whole `.text` section is 0x18E bytes; `.data` is 0x24 bytes at entropy 0.0 (literal zeros). No keys, no challenge handling — stub returns immediately.

So the V5 worker has the unmodified MediaTek reference DLL alongside it
as a fallback / drop-in template, while the production load path goes
through the OPlus build at the SDK root. Two reasons this co-existence
is interesting:

1. The OPlus build is `Subsystem=2` (Win GUI), Linker 6.0, MSVC-built.
   The 2006 stub is the same `Subsystem=2`, Linker 6.0, MSVC. They were
   intentionally produced from the **same** project template — i.e. the
   OPlus build is a recompile of the public reference template against
   `LIBEAY32` with the OPlus keys baked in.
2. The build chain pre-dates the rest of the OPLUSFLASHTOOLNEXT stack
   by years (the rest of the bundle is MSVC 2019 / 2025-built and
   Authenticode-signed by the OPPO Guangdong leaf — see
   [`oplus-toolshub-bins.md`](./oplus-toolshub-bins.md) §4). The
   `SLA_Challenge.dll` is **not** signed — it is the only DLL inside
   `FlashTool_SDK_Full/` shipped without a code-signature, which is
   coherent with MediaTek's "OEM compiles its own SLA DLL" policy.

---

## 3. `auth_sv5.auth` — the per-SoC Anti-Clone blob

Each `auth_sv5.auth` is a MediaTek **GFH** (Generic File Header) container.
The structure is identical across SoCs (with one exception, MT6769),
yielding a 2 256-byte file:

```
                           offset   size   contents
GFH FILE_INFO           ┌─ 0x000 ┐ 0x038   magic 4D 4D 4D 01, type=0x0000, "FILE_INFO"
                        └─       ┘
GFH ANTI_CLONE header   ┌─ 0x038 ┐ 0x010   magic 4D 4D 4D 01, ver=1, size=0x798, type=0x0005, name="MTK"
                        └─       ┘
zero pad + counter      ┌─ 0x048 ┐ 0x164   zeros + sentinel 0x60c2 at 0x68
                        └─       ┘
AC version/flags        ┌─ 0x1ac ┐ 0x014   "03 00 00 00 00 01 00 00 00 00 00 00 01 00 01 00"
                        └─       ┘
zero pad                ┌─ 0x1c0 ┐ 0x0f8   zeros
                        └─       ┘
per-SoC pubkey-info #1  ┌─ 0x2b8 ┐ 0x083   131-byte opaque blob (SoC-specific; same blob appears again at 0x6d0)
                        └─       ┘
'\0' terminator           0x33b
per-SoC info area #1    ┌─ 0x33c ┐ 0x07c   124-byte SoC-specific blob
                        └─       ┘
zero pad                ┌─ 0x3b8 ┐ 0x10c   zeros
                        └─       ┘
*** AC MODULUS ***      ┌─ 0x4c4 ┐ 0x100   ★ RSA-2048 modulus, raw big-endian, **per-SoC** ★
                        └─       ┘
zero pad                ┌─ 0x5c4 ┐ 0x10c   zeros
                        └─       ┘
per-SoC pubkey-info #2  ┌─ 0x6d0 ┐ 0x083   131-byte blob (identical to the one at 0x2b8)
                        └─       ┘
'\0' terminator           0x753
per-SoC info area #2    ┌─ 0x754 ┐ 0x133   307-byte SoC-specific blob
                        └─       ┘
…remainder of GFH#2 body up to 0x8ff…
RSA-2048 signature      ┌─ 0x900 ┐ 0x100   signature over GFH#2 body, per-SoC
                        └─       ┘ EOF
```

* The **AC modulus at offset 0x4C4** is the actual RSA-2048 public
  key the BROM will trust as "OEM-Anti-Clone key" once it has matched
  it against the eFuse-blown `sbc_pub_key_hash[0..3]` slot.
* The **131-byte blob at offset 0x2B8** appears verbatim again at
  `0x6D0`. It is opaque — first bytes do not match any DER tag; this
  is **not** a `RSAPublicKey` ASN.1 encoding. It is plausibly the
  per-SoC nonce, the OEM device-info hash, or an additional AES key
  reserved for the AC handshake.
* The 256-byte tail at `0x900` is an RSA-2048 signature whose
  `pow(sig, 65537, N)` does **not** decode as PKCS#1 v1.5 under any
  of the four `SLA_Challenge.dll` keys (verified). Therefore the
  signing key is a **separate root key** held by OPlus / MTK that
  does not appear anywhere in this tree.
* MT6769 carries one extra `MMM\x01 type=0x0060` GFH record (16 bytes)
  between the body and the signature, padding the file to 2 272 bytes
  and pushing the modulus offset by `+0x10`. The extractor
  ([`extract_mtk_sla_keys.py`](../../scripts/analysis/extract_mtk_sla_keys.py))
  branches on filesize.

### 3.1 Per-SoC AC modulus map

There are **15 auth files** but only **7 distinct AC moduli** — i.e.
several SoCs share the same OEM AC key (because they share the same
`sbc_pub_key_hash` slot in eFuse). Crucially, **one of the 7 distinct
keys is byte-identical to `SLA_Challenge.dll` modulus #1**:

| AC modulus SHA-256 | SoCs | Same key in `SLA_Challenge.dll`? |
| --- | --- | --- |
| `1a89bd533b633a5b6e5c8ad908790f2dce3284f70525a7570a1101870096176b` | **MT6763, MT6833, MT6853, MT6873, MT6877, MT6885, MT6889** (7 SoCs) | ✅ **Yes — modulus #1** (the `c43469a9…` key) |
| `36e3717ad4b3e8bac442e06440460e194b2edb8155306c10692a362b56ec9ccb` | MT6765 | No |
| `a13ed7b7f399882f00e71ed34e140af7956ea863c56d26b9bc99265737a1e19f` | MT6765_18540 | No |
| `7f9f5f563b4e685e85088d589297b7cd7eefe4489fc46bad7a5e5d02d5b2b1df` | MT6765_20271, MT6893 | No |
| `5acd248fa2a32da97229eae1bafb71b455bec74d2495882a1d1c8adae4797bee` | MT6769 | No |
| `32e1113f484f7c1523949bc4e946e7032be249be8b8c80369071104fd3112ef0` | MT6771 | No |
| `79d3e01abdf71bd4a96459598965d0802757ba9f60b6d116b606d860a3349052` | MT6771_18531, MT6779 | No |

Implications:

1. The seven SoCs sharing modulus #1 form the **Helio P / Dimensity
   700-1100 family** (P23, P22, G80/G85, G90/G95, etc.). They were
   provisioned by OPlus with the same OEM AC public-key hash in eFuse,
   so a single OEM-private-key compromise unlocks the AC handshake on
   every one of them.
2. The other six AC moduli are unique-per-SoC (or per-SoC-revision):
   MT6765 has three distinct keys (base, `_18540`, `_20271`), MT6771
   has two (base and `_18531`), and MT6779 happens to share its key
   with `MT6771_18531`. The double-naming with a numeric suffix
   (`_18540`, `_18531`, `_20271`) is OPlus's internal convention for
   silicon revisions that landed with different fused public keys.
3. `SLA_Challenge.dll` only embeds **4** RSA keys but the tree carries
   **7** distinct AC moduli. The discrepancy means three of the seven
   AC keys (those shared by MT6771, MT6779, MT6769, the three MT6765
   revisions, MT6893) are **not** answerable by `SLA_Challenge.dll`
   alone — those SoCs presumably either (a) ship with SLA disabled in
   eFuse (`sla_en = 0`, `sbc_en = 0`) so the host never has to respond,
   or (b) require a different challenge DLL that this tree does not
   include in the SDK root, or (c) are handled by the V6 worker / a
   different code path. The V5 worker references `auth_sv5.auth` but
   does not reach into `SLA_Challenge.dll` for those SoCs in the static
   call graph.
4. The remaining 3 keys in `SLA_Challenge.dll` (modulus #2 `8e02cd…`,
   #3 `707c88…`, #4 `a243f6…`) **do not match any** AC modulus shipped
   for the V5 SoCs. They are most likely the keys for the V6 SoCs
   (MT6897, MT6991, MT6989, MT6985, MT6983, MT6878, MT6789, MT6895,
   MT6896, MT6835) whose `auth_sv6.auth` companion files are not
   in this tree, or for SoCs in the V5 list whose auth files are
   missing here (MT6768, MT6781, MT6785).

### 3.2 Use within the BROM USB-DL handshake (reference, MTK SV5)

Order of operations as referenced by `FTLibMtkCore.dll`'s string
table:

1. `APCore::Connection::ConnectBROM` — open the USB-DL endpoint.
2. `m_boot_arg.m_speedup_brom_baudrate(%d)` — switch UART/USB to fast mode.
3. `m_boot_arg.m_cb_in_brom_stage(0x%x)` — flag "we are in BROM".
4. `m_boot_arg.m_auth_handle(0x%x)` — auth-context pointer.
5. The flash-tool sends the `auth_sv5.auth` blob over the wire. The BROM verifies:
   - `sha256(GFH_anti_clone[0x4c4:0x5c4]) == eFuse.sbc_pub_key_hash[i]` for some slot `i`.
   - The 256-byte tail signature decrypts under that newly-trusted key.
6. The BROM now considers the host **authenticated as OEM**.
7. `BromBootArg::cb_download_da_init` / `m_cb_download_da_init` — the host begins shipping the DA (`DA_BR.bin` / `DA_PL.bin` / `DA_NEW_BR.bin` / `DA_NEW_PL.bin`).
8. `m_boot_arg.m_cb_sla_challenge(0x%x)` — BROM fires an **SLA challenge**: a random `challenge_in` is sent over USB.
9. The flash-tool dispatches into `SLA_Challenge.dll!SLA_Challenge`, which performs `RSA_public_encrypt(challenge_in, key_i)` under the matching modulus and returns `pp_challenge_out`.
10. `m_boot_arg.m_cb_sla_challenge_end(0x%x)` — BROM accepts (or rejects) the response.
11. `Start BROM jump...` — control transfers to the just-uploaded DA.
12. From the DA: `BromDownloadArg::cb_da_report` (`cb_da_report(): DA report: m_da_report addr: %x, chip name: %s, chip type: %d. ext ram size: %x`) and `cb_da_chksum_init` / `cb_da_chksum_progress`.
13. **A second SLA round** runs against the DA itself via the
    `DA_SLA_Challenge` export (see §2.1).

> The string `"anti_rollback project, set m_da_pl_handle for preloader com"`
> vs. `"not anti_rollback project, set m_da_handle for bootrom com"`
> tells the FlashTool to route the DA over the preloader transport
> (anti-rollback) or directly over the BROM transport (legacy V5).
> V6 SoCs go down the anti-rollback path.

---

## 4. eFuse field map (extracted from `FTLibMtkCore.dll`)

These are the literal `printf` field-names the flash-tool uses when it
dumps a SoC's eFuse state. They map 1:1 to the BROM/DA security
configuration:

| Field (verbatim) | Meaning |
| --- | --- |
| `efuse_sf_boot_dis` | Disable serial-flash boot (USB-DL forced) |
| `usbdl_type` | USB-DL transport selector |
| `sbc_en` | **Secure-Boot enabled** master switch |
| `sla_en` | **Serial-Link Authentication enabled** master switch |
| `md1_sbc_en`, `c2k_sbc_en` | Secure-Boot enable for modem (`md1`) and CDMA (`c2k`) firmware |
| `ac_key_blow`, `ac_key` | **Anti-Clone key burned-in flag, AC key value** (eFuse-blown) |
| `sbc_pubk_blow` | Public-key #0 burned flag |
| `sbc_public_key_e`, `sbc_public_key_n` | Public-key #0 modulus / exponent (raw eFuse) |
| `sbc_pub_key_hash` | SHA-256 of public-key #0 — slot 0 |
| `sbc_pubk1_blow`, `sbc_public_key1_e`, `sbc_public_key1_n`, `sbc_pub_key_hash1` | Same for slot 1 |
| `sbc_pubk2_blow`, `sbc_public_key2_e`, (no `_n` printed), `sbc_pub_key_hash2` | Same for slot 2 |
| `sbc_pubk3_blow`, `sbc_public_key3_e`, `sbc_public_key3_n`, `sbc_pub_key_hash3` | Same for slot 3 |
| `sbc_pub_hash{,1,2,3}_dis` | Disable bit per public-key slot |
| `sbc_pubk_hash{,1,2,3}_lock` | Lock bit per public-key slot |
| `sbc_pubk_hash{,1,2,3}_fa_dis` | Field-Application disable per slot |
| `sbc_pubk_hash_mtk_fa_dis` | Disable MTK Field-Application bypass |
| `cust_crypt_data_lock` | Custom-Crypto-Data lock |
| `stb_key_g{0..7}_lock` | Set-Top-Box keys group N lock |
| `stb_key_chipid_blow`, `stb_key_chipID` | Chip-ID-specific STB key |
| `stb_key_operatorid_blow`, `stb_key_operatorid` | Operator-ID-specific STB key |
| `stb_key_chipid_lock`, `stb_key_operatorid_lock`, `stb_key_sn_lock` | Lock bits for the above |

So a MediaTek SoC has up to **four** independent Secure-Boot public-key
hash slots (`sbc_pub_key_hash[0..3]`) plus a separate Anti-Clone key
(`ac_key`). The OPlus AC moduli we extracted from `auth_sv5.auth`
correspond to whichever of those slots OPlus chose to populate at
production time.

---

## 5. URL / endpoint inventory (host-side only)

The MTK-relevant binaries do **not** make any outbound HTTP/HTTPS calls
of their own. The only "URLs" they emit are:

* CRL / OCSP / CA repository URLs from the embedded Authenticode chain (Sectigo, GlobalSign, USERTrust). These are inert metadata, not runtime calls. They are identical to the chain documented in [`oplus-toolshub-bins.md`](./oplus-toolshub-bins.md) §4.
* OPlus's **internal resource namespace** — *not* an actual HTTP host. `LibOplusMtkV5Callback.dll` uses URL-shaped strings like `http://www.oppo.com/rom\DAA_AUTH_FILE` as opaque keys for the in-process resource resolver (note the **backslash** between host and path — illegal for a real URL but typical for a Windows-style "namespace" lookup). The full set:

  | Resource key | Resolved file |
  | --- | --- |
  | `http://www.oppo.com/rom\DAA_AUTH_FILE` | `auth_sv5.auth` for the active SoC |
  | `http://www.oppo.com/rom\DA_BR.bin` | DA-BROM binary (legacy) |
  | `http://www.oppo.com/rom\DA_PL.bin` | DA-Preloader binary (legacy) |
  | `http://www.oppo.com/rom\DA_NEW_BR.bin` | DA-BROM (post-key-rotation) |
  | `http://www.oppo.com/rom\DA_NEW_PL.bin` | DA-Preloader (post-key-rotation) |
  | `http://www.oppo.com/rom\DA_BR_MTK_AllInOne_DA.bin` | "All-in-One" DA (covers multiple SoCs) |
  | `http://www.oppo.com/rom\scatter` | Scatter-loading manifest |

* No bearer tokens. No JWTs. No PEMs. No plaintext credentials. No outbound HTTP from the MTK callbacks — everything goes through the in-tree resource resolver and the USB-DL transport.

---

## 6. PDB / build-pipeline leaks

`LibOplusMtkV5Callback.dll`, `ModMtkV6FlashWorker.dll`,
`ModMtkV6SfpPackageParser.dll`, `ModMtkOfpPackageParser.dll`,
`ModMtkV5FlashWorker.dll`, `ModPSW20PackageMtkV5.dll`, and
`MTKV6FilePlugin.dll` all carry leaked PDB paths of the form:

```
D:\Jenkins\0001\workspace\ToolsHub_Build_RC\aftersale\flashtool\
  OPLUSFLASHTOOLNEXT\Build\Release.vc142.x86\<…>.pdb
```

This is the same Jenkins build-host already documented in
[`oplus-toolshub-bins.md`](./oplus-toolshub-bins.md) §6 (job `0001`,
`ToolsHub_Build_RC`), but a **distinct sub-project** —
`aftersale/flashtool/OPLUSFLASHTOOLNEXT` rather than the parent
`ToolsHub` build. So the OPlus engineering org has at least two CI
configurations on the same Jenkins server building distinct deliverables
into the same OPlus ToolsHub bundle.

`SLA_Challenge.dll` itself ships **without** a PDB path and **without**
an Authenticode signature — confirming it follows the MTK reference SDK
template (which is hand-built outside the Jenkins pipeline) and is
delivered into the bundle as a precompiled artefact.

---

## 7. Encrypted DA payloads (`oplusD2/`)

Five blobs live under
`Plugins/FLASH_SRV/FlashTool_SDK_Full/Modules/ModMtkV5FlashWorker/Resources/oplusD2/`,
named with hash-shaped prefixes that all share the same first 19 hex
characters `03f2bd055ae009925bb`. Three are byte-identical (787 938
bytes, SHA-256 `23578be19b2c392e6b72b2f701d5af36fd37a7b04c496e8e57012c3fd3c4abac`),
the other two are unique:

| File | Size | SHA-256 |
| --- | --- | --- |
| `03f2bd055ae009925bb68bf917b6a507` | 787 938 | `23578be19b2c392e6b72b2f701d5af36fd37a7b04c496e8e57012c3fd3c4abac` |
| `03f2bd055ae009925bb68bf966a1aa1a308aa2dcbc` | 787 938 | `23578be19b2c392e6b72b2f701d5af36fd37a7b04c496e8e57012c3fd3c4abac` (dup) |
| `03f2bd055ae009925bb68bf966baa336ffeb7cbad75a276cc35dcce1a6` | 787 938 | `23578be19b2c392e6b72b2f701d5af36fd37a7b04c496e8e57012c3fd3c4abac` (dup) |
| `03f2bd055ae009925bb68ffd17b6a507` | 1 034 722 | `d4916e8b45ae7ddffe40df528d9be029554888106f9ff11c85d3eacb7dec795f` |
| `03f2bd055ae009925bb98ef266bbaf0df476aa8094` | 653 202 | `eae85c60c72ee591edb0e1517a080ec26450e348979b6c7bd38599d43fe2b6b3` |

All five start with the same 33 bytes:
```
50 48 fe 12 1c 00 8a 5e fd 1d a9 94 bb 7f 8e f6
ec 0c eb 39 eb e7 fa 1c 9a 7c 86 48 d1 b5 a5 76 3b
```

* No PE / GFH / ELF magic. The first dword `0x12fe4850` is not a known DA / FT format magic.
* Byte-frequency distribution is approximately uniform (top-8 byte counts are within 2 % of 1/256), entropy ≥ 7.99 bits/byte across all five files — consistent with **a stream/AES cipher, not a packer with a header**.
* No printable strings of length ≥ 6 anywhere in any of the five files.
* Long-run XOR with constants (0x00, 0x12, 0x50, 0xa5, 0xff, 0x5a) does not produce any recognisable header.
* Filename prefix `03f2bd05…` is the same in every blob, suggesting a **content-addressable scheme** keyed on a hash of `(SoC, preloader version, DA generation)`. The trailing portion of each filename (`b68bf917b6a507`, `b68bf966a1aa1a308aa2dcbc`, etc.) is the variable part.

These are almost certainly the OPlus-encrypted second-stage Download
Agents — the `DA_PL.bin` / `DA_BR.bin` payloads referenced by
`LibOplusMtkV5Callback.dll`, encrypted at rest with a key resolved at
runtime by `LibOplusMtkV5Callback`. Static decryption from this tree
alone is not possible without dynamic recovery of the wrapping key from
that callback DLL.

---

## 8. What this means in practice

* **Anyone with access to OPlus's matching RSA-2048 *private* keys can
  authenticate as OEM to the BROM / DA on every supported SoC.** The
  public moduli are now public; the private halves are not in this
  tree, are not in the OPLUS ToolsHub bundle, and are presumably held
  by OPlus's HSM. There is no static path from the artefacts shipped
  here to those private keys.
* **Seven different MTK SoCs (MT6763, MT6833, MT6853, MT6873, MT6877,
  MT6885, MT6889) share a single OEM AC public key** (`c43469a9…`),
  meaning the same OEM private key unlocks all of them. This is the
  exact scenario MediaTek's four-slot `sbc_pub_key_hash[0..3]` design
  is meant to allow — OEMs partition their fleet across slots. OPlus
  has chosen to use slot 0 (or whichever it picked) for the entire
  Helio P / Dimensity 700-1100 generation. The other six AC keys are
  per-SoC unique.
* **The four SLA keys in `SLA_Challenge.dll` cover only the V5 path,
  and only some of the V5 SoCs** — three of the seven distinct AC
  moduli are not represented in the DLL. The V6 path uses a different,
  anti-rollback authentication scheme keyed on
  `OPLUS_DEFINE_20240326_DA_KEY_VER_` and `preloader_sig_ver`; that
  scheme's keys are not in this static tree.
* **The 256-byte signatures inside each `auth_sv5.auth` are signed by
  a key not present in the tree.** That root signing key is what an
  attacker would actually need to forge a *new* `auth_sv5.auth` for an
  unsupported SoC; the public AC moduli we extracted only let you
  identify which OEM keys a given SoC accepts.
* **`SLA_Challenge.dll` performs `RSA_public_encrypt(challenge_in,
  key_i)`, not signing.** The handshake is therefore "host proves
  possession of the BROM's private key" (BROM holds the private,
  decrypts the response, compares) — i.e. it is a **classical
  challenge-response over RSA-OAEP / PKCS#1 v1.5 encryption**, not an
  RSA signature scheme. This is consistent with MediaTek's documented
  SLA flow.
* **kaeru** is unaffected by any of this in its current form — kaeru
  patches LK, never the BROM/DA stage. But if a future kaeru variant
  ever wanted to ride on top of an OEM flash session (e.g. to inject
  itself between DA and LK), it would have to either:
  1. wait for a session that has already been authenticated by the
     official tool, then interpose at the DA → LK boundary, or
  2. obtain an OPlus AC private key (out of scope for static
     analysis), or
  3. exploit a BROM bug that allows DA upload without SLA — many
     pre-V6 MediaTek SoCs have well-known such flaws.

---

## 9. Reproducing this analysis

```bash
# 1. Clone the source repo (the analysis target).
git clone --depth 1 https://github.com/EduardoC3677/opencode.git /tmp/opencode

# 2. Install the Python prerequisites.
pip install pefile capstone

# 3. Run the extractor against the cloned tree.
python3 scripts/analysis/extract_mtk_sla_keys.py /tmp/opencode/O+
```

The script's output will reproduce, in machine-readable form:

* The four RSA-2048 moduli + their SHA-256 fingerprints from
  `SLA_Challenge.dll`.
* The seven distinct per-SoC AC moduli + their SHA-256 fingerprints
  from the 15 `auth_sv5.auth` files, grouped by SoC.
* The cross-match table linking the 7 AC keys to the 4 DLL-embedded
  keys (one match: AC key shared by MT6763/MT6833/MT6853/MT6873/MT6877/MT6885/MT6889 → `SLA_Challenge.dll` modulus #1).

---

## Appendix A — full RSA-2048 moduli (SLA_Challenge.dll, OPlus 2021)

For convenience, the four hex-encoded moduli, exactly as found in
`.rdata` of the OPlus build of `SLA_Challenge.dll`. Public exponent for
all four is `0x010001` (= 65537).

**Modulus #1** (`.rdata` offset `0x3018`, SHA-256
`1a89bd533b633a5b6e5c8ad908790f2dce3284f70525a7570a1101870096176b`,
**also the AC public key for** MT6763, MT6833, MT6853, MT6873, MT6877,
MT6885, MT6889):

```
C43469A95B143CDC63CE318FE32BAD35B9554A136244FA74D13947425A32949E
E6DC808CDEBF4121687A570B83C51E657303C925EC280B420C757E5A63AD3EC6
980AAD5B6CA6D1BBDC50DB793D2FDDC0D0361C06163CFF9757C07F96559A2186
322F7ABF1FFC7765F396673A48A4E8E3296427BC5510D0F97F54E5CA1BD7A93A
DE3F6A625056426BDFE77B3B502C68A18F08B470DA23B0A2FAE13B8D4DB37462
55371F43306582C74794D1491E97FDE504F0B1ECAC9DDEF282D674B817B7FFA8
522672CF6281790910378FEBFA7DC6C2B0AF9DA03A58509D60AA1AD6F9BFDC84
537CD0959B8735FE0BB9B471104B458A38DF846366926993097222F90628528F
```

**Modulus #2** (`.rdata` offset `0x321c`, SHA-256
`d3a44ea86d235793c1e638ff419502071e948bf1e7e8921ef3e5f2706ec7f686`,
no V5 SoC in this tree advertises this AC key):

```
8E02CDB389BBC52D5383EBB5949C895B0850E633CF7DD3B5F7B5B8911B0DDF2A
80387B46FAF67D22BC2748978A0183B5B420BA579B6D847082EA0BD14AB21B6C
CCA175C66586FCE93756C2F426C85D7DF07629A47236265D1963B8354CB229AF
A2E560B7B3641DDB8A0A839ED8F39BA8C7CDB94104650E8C7790305E2FF6D182
06F49B7290B1ADB7B4C523E10EBF53630D438EF49C877402EA3C1BD6DD903892
FD662FBDF1DFF5D7B095712E58E728BD7F6A8B5621175F4C08EBD6143CDACD65
D9284DFFECAB64F70FD63182E4981551522727A2EE9873D0DB78180C26553AD0
EE1CAAA21BCEBC5A8C0B331FE7FD8710F905A7456AF675A04AF1118CE71E36C9
```

**Modulus #3** (`.rdata` offset `0x3420`, SHA-256
`0456e7540f2c459ab2ce910f72a15c4000a8aadde1f9acd5c416575aa3ac34b6`,
**high bit clear** → effective length 2047 bits, no V5 SoC in this
tree advertises this AC key):

```
707C8892D0DE8CE0CA116914C8BD277B821E784D298D00D3473EDE236399435F
8541009525C2786CB3ED3D7530D47C9163692B0D588209E7E0E8D06F4A697254
98B979599DC576303B5D8D96F874687A310D32E8C86E965B844BC2ACE51DC5E0
6859EA087BD536C39DCB8E1262FDEAF6DA20035F14D3592AB2C1B58734C5C62A
C86FE44F98C602BABAB60A6C8D09A199D2170E373D9B9A5D9B6DE852E859DEB1
BDF33034DCD91EC4EEBFDDBECA88E29724391BB928F40EFD945299DFFC4595BB
8D45F426AC15EC8B1C68A19EB51BEB2CC6611072AE5637DF0ABA89ED1E9CB8C9
AC1EB05B1F01734DB303C23BE1869C9013561B9F6EA65BD2516DE950F08B2E81
```

**Modulus #4** (`.rdata` offset `0x3624`, SHA-256
`664471dd6a667ccc62fbcd3fc1885243d2442db81e7fe8f0a003f3130760000a`,
no V5 SoC in this tree advertises this AC key):

```
A243F6694336D527C5B3ED569DDD0386D309C6592841E4C033DCB461EEA7B6F8
535FC4939E403060646A970DD81DE367CF003848146F19D259F50A385015AF63
09EAA71BFED6B098C7A24D4871B4B82AAD7DC6E2856C301BE7CDB46DC10795C0
D30A68DD8432B5EE5DA42BA22124796512FCA21D811D50B34C2F672E25BCC259
4D9C012B34D473EE222D1E56B90E7D697CEA97E8DD4CCC6BED5FDAECE1A43F96
495335F322CCE32612DAB462B024281841F553FF7FF33E0103A7904037F8FE5D
9BE293ACD7485CDB50957DB11CA6DB28AF6393C3E78D9FBCD4567DEBCA260162
2F0F2EB19DA9192372F9EA3B28B1079409C0A09E3D51D64A4C4CE026FAD24CD7
```

## Appendix B — per-SoC AC RSA-2048 moduli (`auth_sv5.auth`)

One entry per **distinct** modulus. SoCs sharing the same modulus are
listed together. Public exponent is the canonical `0x010001` for all.

**AC modulus shared by 7 SoCs** (MT6763, MT6833, MT6853, MT6873, MT6877,
MT6885, MT6889); SHA-256 `1a89bd533b633a5b6e5c8ad908790f2dce3284f70525a7570a1101870096176b`;
**identical** to `SLA_Challenge.dll` modulus #1 (see Appendix A).

**MT6765** (unique); SHA-256
`36e3717ad4b3e8bac442e06440460e194b2edb8155306c10692a362b56ec9ccb`:

```
b8d3ade3a9eaf0d57a5a0e94d61f5818b4d4d4257d7e0bd58e5ce2d5c1f75a36
a1715f72c6c61cb5dabbe0f0fff63b4c5fdcd0a85c5a1c5b97da91dac7af6562
   …
```

(Full hex re-extracted by the reproducer script; truncated here for
readability — the exact bytes are uniquely identifiable by the
SHA-256 above and re-extractable from `MT6765/auth_sv5.auth` offset
`0x4c4`-`0x5c3`.)

**MT6765_18540** (unique); SHA-256 `a13ed7b7f399882f00e71ed34e140af7956ea863c56d26b9bc99265737a1e19f`.
**MT6765_20271 + MT6893** (shared); SHA-256 `7f9f5f563b4e685e85088d589297b7cd7eefe4489fc46bad7a5e5d02d5b2b1df`.
**MT6769** (unique); SHA-256 `5acd248fa2a32da97229eae1bafb71b455bec74d2495882a1d1c8adae4797bee`.
**MT6771** (unique); SHA-256 `32e1113f484f7c1523949bc4e946e7032be249be8b8c80369071104fd3112ef0`.
**MT6771_18531 + MT6779** (shared); SHA-256 `79d3e01abdf71bd4a96459598965d0802757ba9f60b6d116b606d860a3349052`.

These are only listed by fingerprint here because (a) reproducing 6 ×
512 hex chars is noise, (b) the script in
[`scripts/analysis/extract_mtk_sla_keys.py`](../../scripts/analysis/extract_mtk_sla_keys.py)
re-extracts the bytes deterministically from the `auth_sv5.auth`
files in the source repo.

---

[issue]: https://github.com/R0rt1z2/kaeru/issues/5
[capstone]: https://www.capstone-engine.org/
