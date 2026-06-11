# Cross-platform SecuGen support (Linux + macOS) via direct FFI

**Date:** 2026-06-11
**Status:** approved (architecture); spec pending user review
**Owner:** TrulyNimz
**Repo:** <https://github.com/TrulyNimz/Rust-Fingerprint-Library>

## Goal

Make the existing TypeScript API (`initScanner`, `captureFingerprint`, `enrollUser`, `verifyUser`, `identifyUser`, `disconnectScanner`, `getScannerStatus`) work against the SecuGen Hamster Plus (and other SGFPM-compatible SecuGen devices) on Linux and macOS, while:

- Keeping zero runtime npm dependencies (still ships as a single `.node` per platform).
- Keeping zero added Rust crates beyond `libc` (which is already a transitive dep, surfaced only as a `cfg(not(windows))` direct dep — no new external code).
- Preserving the Windows IPC bridge unchanged (the 32-bit `sgfplib.dll` constraint that motivates it still exists).
- Plug-and-play: scanner can be unplugged/replugged between `disconnect` / `init` cycles without restarting Node.
- Containing the in-process FFI blast radius so a missing library, missing symbol, or vendor SDK error never crashes the host Node process.

## Non-goals

- Linux/macOS support for the WBF or Neurotec vendor modules (Neurotec FFV does ship Linux; out of scope for this spec).
- macOS Touch ID integration (not technically possible — Apple's `LocalAuthentication` framework only exposes "authenticate this user", never image or template data).
- Bundling the SecuGen runtime (`libsgfplib.so` / `.dylib`) inside the .node binary. Licensing forbids redistribution; the user installs it the same way they install `sgfplib.dll` on Windows.
- Cross-compiling. Each platform builds on its own host.
- Automatic scanner reconnect during a long-lived session (consistent with current Windows behaviour: user calls `disconnect()` + `initScanner()` again).

## Background — what works today

The existing layout (post-cleanup, commit `a233866`):

- `protocol/` — shared `BridgeCommand` / `BridgeResponse` IPC types
- `bridge/` — 32-bit Windows binary; loads `sgfplib.dll` with the hardened `LoadLibraryExW` + `AddDllDirectory` flow in `bridge/src/ffi.rs`; speaks JSON line protocol over stdin/stdout.
- `sdk/` — 64-bit napi-rs addon; `vendors/mod.rs` dispatches `secugen` → `SecuGenScanner` (spawns the 32-bit bridge); `wbf`, `neurotec` are `#[cfg(windows)]`-gated.
- `updater/` — standalone GitHub-Releases self-updater CLI.

Windows uses the IPC bridge **because** the SecuGen SDK ships 32-bit-only on Windows. A 64-bit Node process can't load a 32-bit DLL in-process; hence the child-process pattern.

On Linux and macOS, SecuGen ships **64-bit** shared libraries:

- Linux: `libsgfplib.so` (typically alongside `libsgfpamx.so`, device driver `.so`s).
- macOS: `libsgfplib.dylib` (and matching `.dylib` dependencies).

A 64-bit Node process can `dlopen` these directly. There is no architecture-mismatch reason for a bridge process off Windows, so the IPC pattern is not used there — direct FFI keeps latency low and avoids the extra binary.

The C ABI is identical across the three platforms: same SGFPM_* function names, same struct layouts (`SGDeviceInfoParam`, `SGFingerInfo`), same return codes. The `extern "system"` calling convention in `bridge/src/ffi.rs` collapses to `extern "C"` everywhere except 32-bit Windows, so the existing function-pointer type aliases work as-is on Linux/macOS.

## Architecture

### Crate layout (after change)

```
sdk/src/vendors/secugen/
  mod.rs            SecuGenScanner enum-style facade; selects backend by cfg.
  constants.rs      (unchanged)
  ffi_types.rs      Cross-platform C struct/type definitions and fn-pointer aliases.
                    Pulled from bridge/src/ffi.rs (the platform-agnostic half).
  bridge.rs         #[cfg(windows)] — the IPC client currently inlined in mod.rs.
  native.rs         #[cfg(not(windows))] — new direct-FFI client using dlopen via libc.
```

`bridge/src/ffi.rs` keeps its Windows-specific loader (`LoadLibraryExW`, `AddDllDirectory`, `SetDefaultDllDirectories`) and the `SgfpLib` impl. The cross-platform struct/type definitions can either be duplicated into `sdk/.../ffi_types.rs` (~70 lines) or factored into a tiny shared `secugen-ffi-types` crate. **Decision: duplicate.** The shared types are small and stable (they mirror an external SDK contract that doesn't change), and a new shared crate adds workspace churn for negligible payoff. If a future vendor reuses these types, we revisit.

### `SecuGenScanner` facade

`mod.rs` exposes one public type, `SecuGenScanner`, that holds a `Mutex<Option<Backend>>` where `Backend` is:

```rust
enum Backend {
    #[cfg(windows)]
    Bridge(BridgeProcess),         // moved from current mod.rs
    #[cfg(not(windows))]
    Native(NativeClient),          // new
}
```

The `FingerprintScanner` trait impl pattern-matches the backend and delegates. This keeps `vendors/mod.rs` unchanged: it still constructs `SecuGenScanner::new()` and the cfg lives one level lower.

### `native.rs` — the new direct-FFI client

Responsibilities:

1. Discover the SecuGen shared library on disk (see *Library discovery* below).
2. Hand-rolled dlopen via `libc::{dlopen, dlsym, dlclose, dlerror}` — no `libloading` crate. All FFI symbols listed in *Symbol surface* are looked up with `RTLD_NOW` so any missing symbol fails at `init()` time, not mid-operation.
3. Hold a `LoadedLib` struct mirroring the bridge's `SgfpLib` (handle + resolved fn pointers + safe wrappers around them).
4. Implement `init`, `capture`, `enroll`, `verify`, `identify`, `get_quality`, `disconnect` using the same logic flow as `bridge/src/main.rs` — captured templates and image bytes are returned in-process rather than serialised over stdin/stdout.

Concurrency: the SecuGen handle is owned by the `NativeClient` and protected by the same outer `Mutex<Option<Backend>>` that already gates the bridge. No internal locking beyond that.

`Drop` on `NativeClient` closes the device, terminates the SDK, and `dlclose`s the library — the same teardown order the bridge does on exit. This makes hot-replug after `disconnect()` clean (the next `init()` re-dlopens fresh).

### Library discovery (Linux/macOS)

Mirror the Windows lookup order so operators have one mental model. First match wins:

1. `SECUGEN_LIB_PATH` env var — exact path to the shared library. Cross-platform name.
2. `SECUGEN_SDK_PATH` env var — directory; we append the platform-specific filename.
3. Sibling of the Node process executable (`std::env::current_exe()` → its parent directory). Note: this resolves to `node`'s directory, which is rarely useful in practice — `SECUGEN_LIB_PATH` / `SECUGEN_SDK_PATH` is the recommended operator knob. We keep this step for parity with the Windows lookup, not because we expect it to match.
4. Standard system paths:
   - Linux: `/usr/local/lib/libsgfplib.so`, `/usr/lib/libsgfplib.so`, `/opt/SecuGen/lib/libsgfplib.so`.
   - macOS: `/usr/local/lib/libsgfplib.dylib`, `/opt/SecuGen/lib/libsgfplib.dylib`.
5. Bare filename (`libsgfplib.so` / `libsgfplib.dylib`) handed to `dlopen`, letting the OS loader's own search (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, system caches) take over.

`SECUGEN_DLL_PATH` continues to work on Windows only; on non-Windows it's ignored to keep the operator-facing convention crisp ("DLL" implies Windows).

### Symbol surface

The Linux/macOS path resolves exactly the symbols the Windows bridge resolves today:

```
SGFPM_Create, SGFPM_Terminate,
SGFPM_Init, SGFPM_OpenDevice, SGFPM_CloseDevice,
SGFPM_GetDeviceInfo, SGFPM_GetMaxTemplateSize,
SGFPM_GetImageEx, SGFPM_GetImageQuality,
SGFPM_CreateTemplate, SGFPM_MatchTemplate, SGFPM_GetMatchingScore
```

No new symbols. No platform-conditional symbols. Anything we'd want to add later (`SGFPM_SetTemplateFormat`, `SGFPM_GetSensorInfo`, etc.) lands in a follow-up.

### Dispatch in `vendors/mod.rs`

```
get_scanner("secugen")  → SecuGenScanner::new()           # both OS families
get_scanner("auto")     → on Windows:  WbfScanner first
                          on non-Win:  SecuGenScanner directly
```

`wbf`, `neurotec`, `windows`, `neurotechnology` strings keep returning `UnsupportedVendor` on non-Windows (already the case via cfg-gated module imports; we add an explicit error message clarifying the platform reason).

## Plug-and-play guarantees

A scanner can be unplugged mid-session and replugged later. The promise is:

- **During `init`:** if no device is present, return `FingerprintError::DeviceNotFound` (code `DEVICE_NOT_FOUND`). The library may or may not stay dlopen'd internally — that's an implementation detail, but the public state goes back to "not initialised".
- **During `capture`/`verify`/`identify`:** if the SDK returns a device-not-found or timeout error mid-call, we surface it as `DEVICE_NOT_FOUND` or `CAPTURE_TIMEOUT` and leave the scanner state set so `disconnect()` works.
- **After `disconnect`:** internal state is fully released — close device, terminate handle, `dlclose` library. A subsequent `initScanner()` re-runs the full discovery + load cycle, so a scanner plugged in after a failed init will be picked up without restarting Node.
- **No auto-reconnect mid-call.** Consistent with current Windows behaviour; explicit in the README.

## Trade-off mitigation: blast radius

Direct FFI runs vendor code in-process. The mitigations:

1. **Symbol resolution at load.** `dlopen` with `RTLD_NOW` forces all required symbols to resolve immediately. A broken/incomplete SDK install fails at `init()` with `SDK_ERROR`, not at `capture()` six minutes later.
2. **Health check after init.** Right after `SGFPM_OpenDevice` we call `SGFPM_GetDeviceInfo` (same as today). A device that "opened" but returns garbage info fails fast.
3. **All FFI calls return `Result`.** No `.unwrap()` on vendor return codes. Mapped to `FingerprintError` variants identically to the current bridge logic.
4. **Panic firewall at the async boundary.** The current `tokio::task::spawn_blocking(...).await.unwrap()` pattern in `sdk/src/lib.rs` re-raises panics into the async runtime — that's a latent foot-gun, not a firewall. As part of this work we replace each `.await.unwrap()` with handling of `JoinError`: a `JoinError::is_panic()` maps to `FingerprintError::SdkError("vendor library panicked")`, which surfaces as a clean JS `SDK_ERROR` exception. Cancellation cases (`JoinError::is_cancelled()`) map similarly. We do *not* add a per-call `catch_unwind` on top — `spawn_blocking` already isolates the panic into a `JoinError`; the change is in how we read that error.
5. **Library handle isolation.** The `LoadedLib` is owned by a single `NativeClient`. There is no shared/global library handle; `disconnect()` truly releases the load.
6. **Bounded payloads.** The bridge already caps inbound IPC at 64 MiB (`MAX_IPC_LINE`). On the native path, image and template buffers are sized from `SGFPM_GetDeviceInfo` / `SGFPM_GetMaxTemplateSize` — vendor-controlled, but bounded by the SDK's reported geometry, not by an attacker-controllable input. We document this.

A panicking vendor `.so` is fundamentally not preventable without process isolation. We accept that and rely on (1)–(5) to make it vanishingly unlikely in practice.

## Dependencies

- New direct dep: `libc = "0.2"` in `sdk/Cargo.toml`, gated `[target.'cfg(not(windows))'.dependencies]`. Already a transitive dep of `tokio`/`reqwest`, so zero added compile cost and zero npm impact.
- No new vendor crates. No `libloading`. No FFI helper crates.

## Build matrix

| Platform | Steps |
|----------|-------|
| Linux (x86_64) | `cd sdk && npx napi build --platform --release` → `fingerprint-sdk.linux-x64-gnu.node` |
| Linux (aarch64) | Same; napi-rs produces `linux-arm64-gnu.node`. Requires the matching SecuGen SDK build (vendor-provided). |
| macOS (x86_64) | Same; produces `darwin-x64.node`. |
| macOS (arm64) | Same; produces `darwin-arm64.node`. Requires SecuGen's Apple-silicon build (if available). |
| Windows | Unchanged two-step: 32-bit bridge build + 64-bit napi addon. |

Cross-compilation is out of scope. The user builds on each target host.

## Testing & verification

This session runs on Windows-only hardware, so the Linux/macOS path will be checked statically and via smoke-flags during development. The user (or CI) runs real-hardware verification on each OS after the implementation lands.

**Static / build:**

- `cargo check --target x86_64-unknown-linux-gnu -p fingerprint-sdk` (if cross toolchain present) — compiles the `cfg(not(windows))` arm.
- `cargo check --target x86_64-apple-darwin -p fingerprint-sdk` (if installed).
- Fallback if neither cross target is available locally: a temporary build-time flag (`--cfg force_native_secugen`) flips the cfg gate so the Windows host compiles the non-Windows path. The flag is removed before merging.
- Windows build path must still pass `cargo build --target i686-pc-windows-msvc -p secugen-bridge` and the existing bridge runtime smoke test (`echo '{"action":"init"}' | secugen-bridge.exe` returns the device info JSON).

**Runtime smoke (per platform, on the implementing operator's host):**

- `npx ts-node examples/quick_test.ts` should reach `Capture OK!` with the Hamster Plus plugged in.
- Unplug mid-session; rerun: should fail cleanly with `DEVICE_NOT_FOUND`, then succeed after replug + `initScanner()` again.
- `SECUGEN_LIB_PATH` honoured: rename the library, set the env var to the new path, capture should still work.
- Missing library: unset env vars, remove the file from `/usr/local/lib`; `initScanner('secugen')` returns `SDK_ERROR` with a message naming the search paths attempted. The Node process stays up.

**Unit-level (host-agnostic):**

- `find_lib_path()` discovery order has a Rust unit test (uses temp dirs and env-var overrides; no real library load).
- Error mapping from SDK return codes to `FingerprintError` is a table-driven test reused across Windows bridge and Linux/macOS native paths.

## Documentation updates

- `README.md` Platform & Vendor Support table: add Linux and macOS rows for SecuGen, status "Direct FFI (64-bit .so/.dylib)".
- New "Linux setup" and "macOS setup" subsections under *Setup*, mirroring the Windows DLL section. Document `SECUGEN_LIB_PATH`, `SECUGEN_SDK_PATH`, the system path fallback order, and how to install the SecuGen SDK on each OS (link to vendor downloads — no redistribution).
- *Build* section gets the Linux/macOS one-line build command.
- *Known Limitations* gains a clear "macOS Touch ID is not supported" line so consumers don't infer it from the macOS row.

## Out-of-scope follow-ups (parked, not part of this work)

- Neurotec FFV Linux/macOS support (the SDK exists; mirrors this pattern).
- Streaming/buffer-mode return of image bytes via napi-rs `Buffer` instead of `number[]`.
- CI prebuilds for all four platform-arch combos.
- Workspace-shared `secugen-ffi-types` crate (only if a second consumer materialises).

## Risks

- **Vendor SDK availability on macOS arm64** — SecuGen's macOS distribution lags Windows; if Apple-silicon binaries don't ship, the arm64 macOS row stays "build supported, vendor library required". README will say so plainly.
- **dlopen behaviour drift across distros** — older glibc separates `dlopen` into `libdl`; modern glibc folded it into `libc`. The `libc` crate handles the link directive. Confirmed: no manual link-arg work needed.
- **Symbol mangling** — None: SecuGen exports plain C symbols on all platforms (the Windows mangling came from 32-bit stdcall + the bonus `sgwsqlib` stub problem; neither applies here).
