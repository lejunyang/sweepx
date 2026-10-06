//! Real process/pipe acceptance against isolated browser data, without installing an extension.
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const ORIGIN: &str = "chrome-extension://bcidfcdfefinmefhopannchcnicdopad/";
struct Host {
    child: Child,
    messages: mpsc::Receiver<Value>,
}
impl Host {
    fn start(executable: &Path, home: &Path) -> Self {
        let mut child = Command::new(executable)
            .arg(ORIGIN)
            .env("HOME", home)
            .env("LOCALAPPDATA", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, messages) = mpsc::sync_channel(16);
        std::thread::spawn(move || {
            loop {
                let mut header = [0; 4];
                if stdout.read_exact(&mut header).is_err() {
                    break;
                }
                let length = u32::from_ne_bytes(header) as usize;
                assert!(length < 1024 * 1024);
                let mut bytes = vec![0; length];
                stdout.read_exact(&mut bytes).unwrap();
                if sender
                    .send(serde_json::from_slice(&bytes).unwrap())
                    .is_err()
                {
                    break;
                }
            }
        });
        Self { child, messages }
    }
    fn send(&mut self, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin
            .write_all(&(bytes.len() as u32).to_ne_bytes())
            .unwrap();
        stdin.write_all(&bytes).unwrap();
        stdin.flush().unwrap();
    }
    fn next(&self) -> Value {
        self.messages
            .recv_timeout(Duration::from_secs(15))
            .expect("bounded native response")
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let base = temp.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let base = temp.path().to_path_buf();
    let bundle = base.join("bundle");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("sweepx"))
        .args(["browser-extension", "bundle", "--output"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let filename = if cfg!(windows) {
        "sweepx-browser-host.exe"
    } else {
        "sweepx-browser-host"
    };
    (temp, base, bundle.join(filename))
}

fn indexed_db(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    let profile = home.join("Library/Application Support/Google/Chrome/Default");
    #[cfg(target_os = "linux")]
    let profile = home.join(".config/google-chrome/Default");
    #[cfg(windows)]
    let profile = home.join("Google/Chrome/User Data/Default");
    profile.join("IndexedDB/https_example.test_8443.indexeddb.leveldb")
}

#[test]
fn exported_host_scans_the_fixture_and_preserves_browser_owned_plan_contract() {
    let (_temp, home, executable) = fixture();
    let directory = indexed_db(&home);
    std::fs::create_dir_all(&directory).unwrap();
    let payload = directory.join("fixture.data");
    std::fs::write(&payload, b"seven!!").unwrap();
    let mut host = Host::start(&executable, &home);
    host.send(json!({"op":"hello","id":"r1"}));
    assert_eq!(host.next()["kind"], "hello");
    host.send(json!({"op":"scan","id":"r2","browser":"chrome","profile":"Default"}));
    let mut domains = Vec::new();
    let mut done = false;
    for _ in 0..24 {
        let message = host.next();
        assert_eq!(message["id"], "r2");
        assert_ne!(message["kind"], "error", "{message}");
        if message["collection"] == "domains" {
            domains.extend(message["rows"].as_array().unwrap().clone());
        }
        if message["kind"] == "done" {
            done = true;
            break;
        }
    }
    assert!(done);
    let row = domains
        .iter()
        .find(|r| r["domain"] == "example.test")
        .unwrap();
    assert_eq!(row["bytes"], "7");
    assert_eq!(row["sizeComplete"], true);
    host.send(json!({"op":"plan","id":"r3","browser":"chrome","profile":"Default","domain":"example.test"}));
    let plan = host.next();
    assert_eq!(
        plan["plan"]["origins"],
        json!(["https://example.test:8443"])
    );
    assert_eq!(plan["plan"]["recoverable"], false);
    // A profile refusal is correlated and does not kill a healthy connection.
    host.send(json!({"op":"plan","id":"r4","browser":"chrome","profile":"Profile 1","domain":"example.test"}));
    assert_eq!(host.next()["kind"], "error");
    host.send(json!({"op":"hello","id":"r5"}));
    assert_eq!(host.next()["kind"], "hello");
    assert_eq!(std::fs::read(&payload).unwrap(), b"seven!!");
}

#[test]
fn exported_host_rejects_unregistered_origin_and_cli_can_queue_then_record_rejection() {
    let (_temp, home, executable) = fixture();
    let output = Command::new(&executable)
        .arg("chrome-extension://foreign/")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let directory = indexed_db(&home);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("data"), b"keep").unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("sweepx"))
        .env("HOME", &home)
        .env("LOCALAPPDATA", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .args([
            "browser-extension",
            "request",
            "--browser",
            "chrome",
            "--profile",
            "Default",
            "--domain",
            "example.test",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let queued: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(queued["applied"], false);
    let mut host = Host::start(&executable, &home);
    host.send(json!({"op":"pending","id":"r1","browser":"edge","profile":"Default"}));
    let other_selection = host.next();
    assert!(other_selection["request"].is_null());
    assert_eq!(other_selection["state"], "different_selection");
    host.send(json!({"op":"pending","id":"r2","browser":"chrome","profile":"Default"}));
    let pending = host.next();
    assert_eq!(pending["state"], "ready");
    assert_eq!(pending["request"]["plan"]["domain"], "example.test");
    host.send(json!({"op":"complete","id":"r3","request_id":pending["request"]["requestId"],"status":"rejected","mode":null}));
    assert_eq!(host.next()["result"]["status"], "rejected");
    host.send(json!({"op":"pending","id":"r4","browser":"chrome","profile":"Default"}));
    assert_eq!(host.next()["state"], "none");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("sweepx"))
        .env("HOME", &home)
        .env("LOCALAPPDATA", &home)
        .args(["browser-extension", "status"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(status["pending"].is_null());
    assert_eq!(status["lastResult"]["status"], "rejected");
    assert_eq!(std::fs::read(directory.join("data")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn registration_updates_only_owned_host_and_preserves_old_bundle_and_foreign_manifest() {
    let (_temp, home, executable) = fixture();
    let bundle = executable.parent().unwrap();
    let register = |path: &Path, replace: bool| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("sweepx"));
        command
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .args([
                "browser-extension",
                "register",
                "--browser",
                "chrome",
                "--bundle",
            ])
            .arg(path);
        if replace {
            command.arg("--replace");
        }
        command.output().unwrap()
    };
    let first = register(bundle, false);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let result: Value = serde_json::from_slice(&first.stdout).unwrap();
    let manifest = PathBuf::from(result["manifest"].as_str().unwrap());
    let original = std::fs::read(&manifest).unwrap();
    assert!(!register(bundle, false).status.success());
    assert_eq!(std::fs::read(&manifest).unwrap(), original);
    let updated = home.join("updated-bundle");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("sweepx"))
        .args(["browser-extension", "bundle", "--output"])
        .arg(&updated)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(register(&updated, true).status.success());
    let changed: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(
        changed["path"],
        updated.join("sweepx-browser-host").to_str().unwrap()
    );
    assert!(executable.exists());
    // Same basename is insufficient: refuse another extension's native host registration.
    let foreign = br#"{"name":"org.sweepx.browser_bridge","type":"stdio","allowed_origins":["chrome-extension://foreign/"]}"#;
    std::fs::write(&manifest, foreign).unwrap();
    assert!(!register(&updated, true).status.success());
    assert_eq!(std::fs::read(&manifest).unwrap(), foreign);
    // A bundle with a modified executable is also refused before registration replacement.
    std::fs::write(updated.join("sweepx-browser-host"), b"modified").unwrap();
    assert!(!register(&updated, true).status.success());
    assert_eq!(std::fs::read(&manifest).unwrap(), foreign);
}
