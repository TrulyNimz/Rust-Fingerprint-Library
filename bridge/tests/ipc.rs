//! End-to-end IPC tests: spawn the real bridge binary, talk to it over
//! stdin/stdout JSON lines, assert on its responses.
//!
//! These tests don't load the SecuGen DLL, so they exercise the IPC framing
//! and state-machine paths only. Anything that needs `sgfplib.dll` ends with
//! a clean `SDK_ERROR`, which is exactly what we want to verify.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Path to the freshly built bridge binary. Set by Cargo for integration tests
/// that target the `secugen-bridge` bin in the same package.
const BRIDGE_EXE: &str = env!("CARGO_BIN_EXE_secugen-bridge");

/// Generous timeout; every test below should respond in well under a second.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Test harness: owns a bridge child process and a background reader thread
/// that funnels every stdout line through a channel. Killing the child on Drop
/// guards against zombie processes if a test panics.
struct Bridge {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
}

impl Bridge {
    fn spawn() -> Self {
        let mut child = Command::new(BRIDGE_EXE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Discard stderr so test output stays clean. The bridge only writes
            // to stderr on panic, which the test will surface via the exit code.
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn bridge");

        let stdin = child.stdin.take().expect("stdin pipe");
        let stdout = child.stdout.take().expect("stdout pipe");

        // Read stdout in a dedicated thread so the test can apply timeouts.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(l) = line else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });

        Self { child, stdin, rx }
    }

    fn send(&mut self, json: &str) {
        writeln!(self.stdin, "{}", json).expect("write to bridge stdin");
        self.stdin.flush().expect("flush bridge stdin");
    }

    fn recv(&self) -> String {
        self.rx
            .recv_timeout(RESPONSE_TIMEOUT)
            .expect("bridge response within timeout")
    }

    /// Try to receive; returns None on timeout/EOF without panicking.
    fn try_recv(&self, timeout: Duration) -> Option<String> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ─── State-machine tests (no DLL required) ─────────────────────────────────

#[test]
fn capture_before_init_returns_not_initialized() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"capture","timeout_ms":1000,"min_quality":60}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""status":"error""#) && resp.contains(r#""code":"NOT_INITIALIZED""#),
        "expected NOT_INITIALIZED error, got: {resp}"
    );
}

#[test]
fn verify_before_init_returns_not_initialized() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"verify","user_id":"alice","template_data":[1,2,3]}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""code":"NOT_INITIALIZED""#),
        "expected NOT_INITIALIZED, got: {resp}"
    );
}

#[test]
fn identify_before_init_returns_not_initialized() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"identify","templates":[]}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""code":"NOT_INITIALIZED""#),
        "expected NOT_INITIALIZED, got: {resp}"
    );
}

#[test]
fn enroll_before_init_returns_not_initialized() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"enroll","user_id":"bob","samples":3}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""code":"NOT_INITIALIZED""#),
        "expected NOT_INITIALIZED, got: {resp}"
    );
}

#[test]
fn get_quality_before_init_returns_not_initialized() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"get_quality","image":[0,0,0,0]}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""code":"NOT_INITIALIZED""#),
        "expected NOT_INITIALIZED, got: {resp}"
    );
}

#[test]
fn disconnect_without_init_is_noop_ok() {
    let mut bridge = Bridge::spawn();
    bridge.send(r#"{"action":"disconnect"}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""status":"ok""#) && resp.contains(r#""type":"void""#),
        "expected ok/void response, got: {resp}"
    );
}

// ─── Framing & robustness ──────────────────────────────────────────────────

#[test]
fn malformed_json_returns_error_and_stream_survives() {
    let mut bridge = Bridge::spawn();

    // Garbage in → SDK_ERROR out.
    bridge.send("this is not json at all");
    let resp1 = bridge.recv();
    assert!(
        resp1.contains(r#""status":"error""#)
            && resp1.contains(r#""code":"SDK_ERROR""#)
            && resp1.contains("Invalid command"),
        "expected SDK_ERROR/Invalid command, got: {resp1}"
    );

    // Stream MUST still respond to the next command (the loop continues, not breaks).
    bridge.send(r#"{"action":"disconnect"}"#);
    let resp2 = bridge.recv();
    assert!(
        resp2.contains(r#""status":"ok""#),
        "stream did not survive malformed JSON; got: {resp2}"
    );
}

#[test]
fn unknown_action_returns_invalid_command() {
    let mut bridge = Bridge::spawn();
    // Valid JSON shape, but the action tag isn't one we know.
    bridge.send(r#"{"action":"do_a_barrel_roll"}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""status":"error""#) && resp.contains("Invalid command"),
        "expected serde tag error, got: {resp}"
    );
}

#[test]
fn empty_lines_are_skipped() {
    let mut bridge = Bridge::spawn();

    // Send three blank lines; bridge should ignore them and remain silent.
    bridge.send("");
    bridge.send("");
    bridge.send("");

    // Nothing should come back within a short window.
    assert!(
        bridge.try_recv(Duration::from_millis(200)).is_none(),
        "bridge unexpectedly responded to blank lines"
    );

    // Then a real command works.
    bridge.send(r#"{"action":"disconnect"}"#);
    let resp = bridge.recv();
    assert!(
        resp.contains(r#""status":"ok""#),
        "post-blanks command failed: {resp}"
    );
}

#[test]
fn multiple_commands_round_trip_in_order() {
    let mut bridge = Bridge::spawn();

    // Fire several commands back-to-back; each should get its own response and
    // they must arrive in send order (no interleaving).
    bridge.send(r#"{"action":"capture","timeout_ms":1,"min_quality":1}"#);
    bridge.send(r#"{"action":"enroll","user_id":"x","samples":1}"#);
    bridge.send(r#"{"action":"disconnect"}"#);

    let r1 = bridge.recv();
    let r2 = bridge.recv();
    let r3 = bridge.recv();

    assert!(r1.contains(r#""code":"NOT_INITIALIZED""#), "r1: {r1}");
    assert!(r2.contains(r#""code":"NOT_INITIALIZED""#), "r2: {r2}");
    assert!(
        r3.contains(r#""status":"ok""#) && r3.contains(r#""type":"void""#),
        "r3: {r3}"
    );
}

// ─── Init without DLL (graceful failure, not panic) ────────────────────────

#[test]
fn init_without_dll_returns_sdk_error_not_panic() {
    // Point SECUGEN_DLL_PATH at a path that does not exist, so the bridge
    // can't possibly find a real DLL. Critically, this must produce a JSON
    // error response, NOT a Rust panic / silent exit.
    let mut child = Command::new(BRIDGE_EXE)
        .env("SECUGEN_DLL_PATH", r"C:\does\not\exist\sgfplib.dll")
        .env("SECUGEN_SDK_PATH", r"C:\does\not\exist")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bridge");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(l) = line else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
    });

    writeln!(stdin, r#"{{"action":"init"}}"#).expect("write init");
    stdin.flush().expect("flush");

    let resp = rx
        .recv_timeout(RESPONSE_TIMEOUT)
        .expect("init response within timeout");

    assert!(
        resp.contains(r#""status":"error""#),
        "init should fail cleanly without DLL, got: {resp}"
    );
    // Either the loader rejects the path up-front (SDK_ERROR / Failed to load)
    // or it falls through to the fallback search and returns a device error.
    assert!(
        resp.contains("SDK_ERROR") || resp.contains("DEVICE_NOT_FOUND"),
        "expected SDK_ERROR or DEVICE_NOT_FOUND, got: {resp}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
