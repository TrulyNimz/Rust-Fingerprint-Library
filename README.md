# Rust-Fingerprint-Library

Vendor-agnostic, cross-platform fingerprint scanner SDK for Node.js, built with Rust and napi-rs. Compiles to a single `.node` binary with zero runtime npm dependencies.

> Repository: <https://github.com/TrulyNimz/Rust-Fingerprint-Library>

**Status**: SecuGen (Windows, via 32-bit IPC bridge) is verified end-to-end against real hardware (Hamster Plus, firmware 4117). WBF and Neurotec vendor modules compile and are usable for detection/init; full capture/match coverage varies by sensor (see notes below).

## Platform & Vendor Support

| Platform | Vendor  | Model         | Strategy | Status |
|----------|---------|---------------|----------|--------|
| Windows  | SecuGen | Hamster Plus  | Out-of-process bridge (32-bit DLL) | Verified (full) |
| Windows  | WBF (any) | Goodix, Synaptics, etc. | Native WinBio API (64-bit) | Init only (see note) |
| macOS    | —       | —             | Direct FFI (64-bit dylib) | Planned |
| Linux    | —       | —             | Direct FFI (64-bit .so) | Planned |

> **WBF Note**: The Windows Biometric Framework vendor (`initScanner('wbf')`) can detect and enumerate any WBF-registered fingerprint sensor. However, MOC (Match-on-Chip) sensors like the Goodix/Suprema BioMini Slim 2 keep fingerprint data on-chip and the Windows biometric service holds an exclusive lock when Windows Hello is enrolled. Capture/verify/identify require the vendor's native SDK for full functionality. Non-MOC sensors (swipe/area sensors with host-based matching) may support full WBF capture.

> The TypeScript API is identical across all platforms and vendors. Only the underlying vendor implementation changes.

## Architecture

```
                       ┌───────────────────────────────────┐
                       │  Node.js / TypeScript application │
                       │  import { initScanner, ... }      │
                       └───────────────┬───────────────────┘
                                       │ napi-rs FFI
                       ┌───────────────▼───────────────────┐
                       │  64-bit .node addon               │
                       │  FingerprintScanner trait dispatch │
                       └───────────────┬───────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            │                          │                          │
 ┌──────────▼──────────┐  ┌───────────▼──────────┐  ┌───────────▼──────────┐
 │  SecuGen (Windows)  │  │  Vendor B (macOS)    │  │  Vendor C (Linux)    │
 │  IPC → 32-bit bridge│  │  direct FFI to .dylib│  │  direct FFI to .so  │
 └──────────┬──────────┘  └──────────────────────┘  └──────────────────────┘
            │ stdin/stdout JSON lines
 ┌──────────▼──────────┐
 │  secugen-bridge.exe │
 │  32-bit, owns DLL   │
 └─────────────────────┘
```

### Why the bridge on Windows?

SecuGen's `sgfplib.dll` is 32-bit only. A 64-bit Node.js process cannot load it directly. The SDK spawns a 32-bit child process that owns the DLL and communicates over stdin/stdout JSON lines. On macOS and Linux, most fingerprint SDKs ship 64-bit native libraries, so vendor implementations link directly with no bridge overhead.

### Design Principles

- **One trait, many vendors**: Every vendor implements `FingerprintScanner` (init, capture, enroll, verify, identify, disconnect). The SDK dispatches at runtime based on the vendor string.
- **Platform-specific internals, platform-agnostic API**: `initScanner('secugen')` on Windows and `initScanner('some-vendor')` on macOS return the same `DeviceInfo` shape.
- **Zero runtime npm dependencies**: The `.node` binary is self-contained.

## Prerequisites

### All Platforms

- **Rust** (1.70+): https://rustup.rs
- **Node.js** (18+)
- **napi-rs CLI**: `npm install -g @napi-rs/cli`

### Windows (SecuGen)

- **32-bit Rust target**: `rustup target add i686-pc-windows-msvc`
- **MSVC Build Tools**: For compiling the stub `sgwsqlib.dll`
- **SecuGen FDx SDK Pro**: `sgfplib.dll` (32-bit) — not redistributable, obtain from SecuGen

### macOS / Linux

No additional prerequisites beyond Rust and Node.js. Vendor-specific SDK libraries will be documented per vendor.

## Build

### Windows (SecuGen)

```bash
# 1. Build the stub sgwsqlib.dll (32-bit) from bridge/sgwsqlib_stub.c.
#    From a "x86 Native Tools Command Prompt for VS" inside the bridge/ directory:
cd bridge
cl @cl_args.rsp
cd ..

# 2. Build the 32-bit bridge binary
cargo build --target i686-pc-windows-msvc --release -p secugen-bridge

# 3. Build the 64-bit napi-rs addon
cd sdk && npx napi build --platform --release && cd ..

# 4. Stage runtime files next to the .node file
cp target/i686-pc-windows-msvc/release/secugen-bridge.exe sdk/
cp bridge/sgwsqlib.dll sdk/
```

`sgfplib.dll`, `sgfpamx.dll`, and `sgfdu05m.dll` must be available via `SECUGEN_DLL_PATH` / `SECUGEN_SDK_PATH` or sit next to the bridge executable (see "Setup" below).

### macOS / Linux

```bash
# No bridge needed — just build the napi-rs addon
cd sdk && npx napi build --platform --release
```

## Setup

### SecuGen DLL Resolution (Windows)

The bridge process finds `sgfplib.dll` in this order:

1. `SECUGEN_DLL_PATH` env var (exact path to DLL)
2. `SECUGEN_SDK_PATH` env var (directory containing DLL)
3. Same directory as `secugen-bridge.exe`
4. Known SDK install paths

The following DLLs must be in the same directory as `sgfplib.dll`:

| DLL | Purpose | Source |
|-----|---------|--------|
| `sgfpamx.dll` | Matching algorithm | SecuGen SDK |
| `sgfdu05m.dll` | Device driver (varies by model) | SecuGen SDK |
| `sgwsqlib.dll` | WSQ codec | Stub provided (see below) |

### Stub sgwsqlib.dll

`sgfplib.dll` imports WSQ codec functions from `sgwsqlib.dll`, which is not included in the standard SDK download. A minimal stub is provided that satisfies the import table (WSQ compression is not used by this SDK). Build it from the `bridge/` directory:

```bash
cl /nologo /LD /Fe:sgwsqlib.dll sgwsqlib_stub.c /link /DEF:sgwsqlib.def
```

Copy the resulting `sgwsqlib.dll` alongside `sgfplib.dll`.

### Bridge Executable Resolution

The SDK finds `secugen-bridge.exe` in this order:

1. `SECUGEN_BRIDGE_PATH` env var (exact path)
2. Same directory as the loaded `.node` addon
3. Same directory as `node.exe`

The CWD is **not** searched: a process whose working directory is attacker-writable would otherwise spawn a planted `secugen-bridge.exe`.

## Usage

```typescript
import {
  initScanner,
  captureFingerprint,
  enrollUser,
  verifyUser,
  identifyUser,
  disconnectScanner,
  getScannerStatus,
} from 'fingerprint-sdk'

// Initialize — auto-detects vendor, or pass 'secugen' explicitly
const device = await initScanner()
console.log(`${device.vendor} ${device.model} @ ${device.dpi} DPI`)

// Capture a fingerprint
const scan = await captureFingerprint({ minQuality: 70, timeoutMs: 15000 })
console.log(`Quality: ${scan.quality}, Template: ${scan.template.length} bytes`)

// Enroll a user (captures 3 samples, keeps best)
const template = await enrollUser('user-123')

// Verify against a stored template (1:1)
const result = await verifyUser('user-123', template)
console.log(`Match: ${result.matched}, Score: ${result.score}`)

// Identify against multiple templates (1:N)
const match = await identifyUser([template])
console.log(`Identified: ${match.userId}`)

// Disconnect (releases device, kills bridge process on Windows)
await disconnectScanner()
```

## API Reference

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `initScanner(vendor?)` | `Promise<DeviceInfo>` | Initialize scanner. Auto-detects vendor if omitted. |
| `captureFingerprint(options?)` | `Promise<ScanResult>` | Capture a fingerprint image and extract template. |
| `enrollUser(userId, samples?)` | `Promise<Template>` | Capture multiple samples, return best. Default: 3 samples. |
| `verifyUser(userId, template)` | `Promise<MatchResult>` | 1:1 match against a stored template. |
| `identifyUser(templates)` | `Promise<MatchResult>` | 1:N search across a template list. |
| `disconnectScanner()` | `Promise<void>` | Release hardware and clean up. |
| `getScannerStatus()` | `Promise<ScannerStatusInfo>` | Check connection status. |

### Types

```typescript
interface DeviceInfo {
  vendor: string
  model: string
  serial: string
  firmware: string
  imageWidth: number
  imageHeight: number
  dpi: number
}

interface ScanResult {
  image: number[]        // Raw grayscale pixels (width x height)
  quality: number        // 0-100
  template: number[]     // Vendor-specific minutiae template
  timestamp: number      // Unix epoch ms
}

interface Template {
  userId: string
  data: number[]
  createdAt: number
}

interface MatchResult {
  matched: boolean
  score: number
  userId?: string        // Present when matched
}

interface CaptureOptions {
  timeoutMs?: number     // Default: 10000
  minQuality?: number    // Default: 60
}
```

## Error Handling

All errors include a machine-readable code prefix: `[CODE] message`.

| Code | Description |
|------|-------------|
| `DEVICE_NOT_FOUND` | No scanner hardware detected |
| `CAPTURE_TIMEOUT` | Finger not placed within timeout |
| `LOW_QUALITY` | Captured image below quality threshold |
| `MATCH_FAILED` | Template matching failed |
| `SDK_ERROR` | Vendor SDK or bridge process error |
| `UNSUPPORTED_VENDOR` | Requested vendor not implemented |
| `NOT_INITIALIZED` | Call `initScanner()` first |

## Project Structure

```
Rust-Fingerprint-Library/                Cargo workspace
  protocol/                              Shared IPC types (BridgeCommand, BridgeResponse)
    src/lib.rs
  bridge/                                32-bit bridge binary (Windows only)
    src/
      main.rs                            stdin/stdout JSON line loop
      ffi.rs                             LoadLibraryW/GetProcAddress runtime loading
    sgwsqlib_stub.c                      Stub DLL source for missing import dependency
    sgwsqlib.def                         Linker definition for stdcall exports
    cl_args.rsp                          MSVC response file for building the stub
  sdk/                                   64-bit napi-rs addon (all platforms)
    src/
      lib.rs                             napi-rs async exports
      update_check.rs                    GitHub Releases update check
      fp_core/
        traits.rs                        FingerprintScanner trait (vendor contract)
        types.rs                         Shared types with #[napi(object)]
        errors.rs                        Error enum with codes
      vendors/
        mod.rs                           Vendor registry and dispatch
        secugen/mod.rs                   SecuGen IPC client (Windows)
        wbf/mod.rs                       Windows Biometric Framework client (Windows)
        neurotec/mod.rs                  Neurotec FFV SDK client (Windows)
        template/mod.rs                  Blank vendor scaffold
    package.json
  updater/                               Optional self-updater CLI (downloads releases from GitHub)
    src/
      main.rs, lib.rs, github.rs, assets.rs, apply.rs, version.rs
  examples/
    basic.ts                             Full usage example (SecuGen)
    quick_test.ts                        Minimal init + capture (SecuGen)
    wbf_test.ts, wbf_quick.ts            WBF examples
```

## Adding a New Vendor

1. Copy `sdk/src/vendors/template/` to `sdk/src/vendors/<vendor_name>/`
2. Implement the `FingerprintScanner` trait:
   - **macOS/Linux**: Link the vendor's 64-bit native library directly via FFI
   - **Windows (32-bit DLL)**: Create a bridge binary in `bridge/` and use IPC
3. Register the vendor in `sdk/src/vendors/mod.rs`
4. Use `#[cfg(target_os = "...")]` for platform-specific vendor selection
5. The public TypeScript API requires no changes

## Updates

The SDK exposes an opt-in `checkForUpdate()` function (queries the configured GitHub Releases endpoint). A standalone `fingerprint-updater` CLI (in the `updater/` crate) can also download and apply releases:

```bash
cargo build --release -p fingerprint-updater
./target/release/fingerprint-updater check
./target/release/fingerprint-updater update
./target/release/fingerprint-updater rollback
```

Set the `GITHUB_TOKEN` env var to authenticate against private repositories or to raise rate limits.

### Release signing (required for production builds)

The updater verifies every downloaded zip with an Ed25519 signature. **Without an embedded public key it refuses to apply updates** unless `--allow-unsigned` is passed (development only — anyone who compromises the GitHub release can ship arbitrary code to your installs).

**1. Generate a keypair (once, on an offline machine, store the secret key safely):**

```bash
# Any Ed25519 keypair generator works; e.g. with openssl 3.0+:
openssl genpkey -algorithm ed25519 -out ed25519-priv.pem
openssl pkey -in ed25519-priv.pem -pubout -outform DER 2>/dev/null \
  | tail -c 32 | xxd -p -c 32     # 64 hex chars = the public key to embed
```

**2. Build the updater with the public key baked in:**

```bash
FINGERPRINT_UPDATE_PUBKEY=<64-hex-pubkey> cargo build --release -p fingerprint-updater
```

**3. Sign every release zip and publish the signature alongside the artifact:**

```bash
# Produces a 64-byte raw signature file
openssl pkeyutl -sign -inkey ed25519-priv.pem \
  -rawin -in fingerprint-sdk-v0.2.0-win32-x64.zip \
  -out fingerprint-sdk-v0.2.0-win32-x64.sig
```

The asset name must be `fingerprint-sdk-v<version>-win32-x64.sig`. The updater fetches it from the same GitHub release as the zip and verifies before extraction.

> Existing `.sha256` checksum files remain supported as a defense-in-depth integrity check, but **signatures are the authenticity check** — checksums hosted next to the zip prove nothing if the release itself is compromised.

## Biometric data handling

Fingerprint images and templates are special-category personal data under GDPR Article 9, BIPA, and similar regimes. This SDK applies basic in-memory hygiene on its side of the boundary:

- Intermediate image/template buffers in the 32-bit bridge are zeroized after each IPC round-trip
- The JSON IPC payload (which carries raw bytes) is zeroized on both ends after send/receive
- Cloned template bytes inside the SDK marshalling layer are zeroized after the command is dispatched

**Once data crosses into JavaScript, the calling application owns its lifecycle.** Anything you receive from `captureFingerprint`, `enrollUser`, or `verifyUser` lives in the V8 heap and Rust cannot zeroize it for you. Treat templates and raw images as you would any other regulated PII:

- Encrypt at rest (use a dedicated secrets manager / KMS, not plain disk)
- Avoid persisting raw images unless explicitly required — store only the matched template ID
- Restrict log output: never log template bytes, image bytes, or `userId` together with biometric scores
- Where possible, hand off to a `Buffer` and explicitly `buffer.fill(0)` after use

## Known Limitations

- **Verified vendor**: SecuGen is the only vendor exercised end-to-end on real hardware so far. WBF and Neurotec modules compile and can initialise compatible devices; capture/match behaviour depends on the underlying sensor (MOC sensors expose limited functionality through WBF — see WBF note above).
- **Windows-only**: All three current vendor modules are Windows-only. macOS / Linux vendor implementations would link a 64-bit native library directly (no bridge required).
- **Single scanner**: The global state supports one connected scanner at a time.
- **No automatic reconnect**: If the bridge process crashes, call `disconnectScanner()` then `initScanner()` again.
- **Binary data as `number[]`**: Images and templates are JSON arrays. A future optimization could use `Buffer` via napi-rs for better performance with large payloads.

## Contributing

Pull requests and issues are welcome at <https://github.com/TrulyNimz/Rust-Fingerprint-Library>. New vendors should follow the `sdk/src/vendors/template/` scaffold (see the section above).

## License

MIT
