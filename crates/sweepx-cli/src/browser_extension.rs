//! Bundled browser adapter and a local, extension-initiated Native Messaging bridge.
//!
//! The bridge has no filesystem deletion or arbitrary path/command endpoint. Native inventory
//! stays report-only; the extension calls the browser API after explicit profile/domain review.
//! One private pending request and one last result bound the CLI-to-extension mailbox. A browser
//! completion report does not establish reclaimed space or independently prove active profile.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sweepx_cache::native::Directory;
use sweepx_core::CancellationToken;
use sweepx_core::browser_storage::{
    BrowserStorageAnalysis, analyze_site_storage, cleanup_plan, default_installations,
};

const HOST: &str = "org.sweepx.browser_bridge";
const EXTENSION_ID: &str = "bcidfcdfefinmefhopannchcnicdopad";
const ORIGIN: &str = "chrome-extension://bcidfcdfefinmefhopannchcnicdopad/";
const INPUT_CAP: usize = 64 * 1024;
const OUTPUT_CAP: usize = 768 * 1024;
const EXECUTABLE_CAP: u64 = 256 * 1024 * 1024;
const REQUEST_TTL: u64 = 15 * 60;
const ASSETS: &[(&str, &str)] = &[
    (
        "manifest.json",
        include_str!("../assets/chromium-cleanup/manifest.json"),
    ),
    (
        "open.js",
        include_str!("../assets/chromium-cleanup/open.js"),
    ),
    (
        "review.html",
        include_str!("../assets/chromium-cleanup/review.html"),
    ),
    (
        "review.css",
        include_str!("../assets/chromium-cleanup/review.css"),
    ),
    (
        "review.mjs",
        include_str!("../assets/chromium-cleanup/review.mjs"),
    ),
    (
        "logic.mjs",
        include_str!("../assets/chromium-cleanup/logic.mjs"),
    ),
    (
        "bridge.mjs",
        include_str!("../assets/chromium-cleanup/bridge.mjs"),
    ),
];

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Export embedded extension and a stable host executable into a NEW private directory.
    /// For updates export a new bundle, register it with --replace, then reload the extension.
    Bundle {
        #[arg(long, value_name = "NEW_ABSOLUTE_DIRECTORY")]
        output: PathBuf,
    },
    /// Register the bundled host for stable Chrome/Edge on macOS/Linux, without admin policy.
    /// This grants the fixed extension ID access to read-only SweepX inventory and requests.
    Register {
        #[arg(long, value_parser = ["chrome", "edge"])]
        browser: String,
        #[arg(long, value_name = "ABSOLUTE_BUNDLE_DIRECTORY")]
        bundle: PathBuf,
        /// Replace only an existing SweepX registration; never overwrite another host.
        #[arg(long)]
        replace: bool,
    },
    /// Queue ONE exact domain for review in the extension; does not delete or auto-open pages.
    Request {
        #[arg(long, value_parser = ["chrome", "edge", "chrome-beta", "chrome-dev", "edge-beta", "edge-dev"])]
        browser: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        domain: String,
    },
    /// Read the pending request and last browser-reported result; never creates missing state.
    Status,
}

pub(crate) fn run(command: Commands) -> ExitCode {
    let result = match command {
        Commands::Bundle { output } => export_bundle(&output),
        Commands::Register {
            browser,
            bundle,
            replace,
        } => register(&browser, &bundle, replace),
        Commands::Request {
            browser,
            profile,
            domain,
        } => queue_request(&bridge_root(), &browser, &profile, &domain),
        Commands::Status => mailbox_status(&bridge_root()),
    };
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(3)
        }
    }
}

fn host_filename() -> &'static str {
    if cfg!(windows) {
        "sweepx-browser-host.exe"
    } else {
        "sweepx-browser-host"
    }
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > EXECUTABLE_CAP {
        return Err(io::Error::other("executable_size_limit"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > EXECUTABLE_CAP {
            return Err(io::Error::other("executable_size_limit"));
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn host_manifest(bundle: &Path) -> io::Result<Value> {
    let path = bundle.join(host_filename());
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("host_path_requires_utf8"))?;
    Ok(
        json!({"name":HOST,"description":"SweepX browser inventory and reviewed cleanup bridge",
        "path":path,"type":"stdio","allowed_origins":[ORIGIN]}),
    )
}

fn export_bundle(output: &Path) -> io::Result<Value> {
    if !output.is_absolute() {
        return Err(io::Error::other("bundle_path_must_be_absolute"));
    }
    match std::fs::symlink_metadata(output) {
        Ok(_) => return Err(io::Error::other("bundle_directory_already_exists")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let root = Directory::open(output, true)?;
    let extension = root.create_child("extension")?;
    for (name, contents) in ASSETS {
        let mut file = extension.create_state_file(name)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    let mut source = File::open(std::env::current_exe()?)?;
    if source.metadata()?.len() > EXECUTABLE_CAP {
        return Err(io::Error::other("executable_size_limit"));
    }
    let mut executable = root.create_state_file(host_filename())?;
    let copied = io::copy(
        &mut Read::by_ref(&mut source).take(EXECUTABLE_CAP + 1),
        &mut executable,
    )?;
    if copied > EXECUTABLE_CAP {
        return Err(io::Error::other("executable_size_limit"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        executable.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    executable.sync_all()?;
    // Windows exclusive creation denies other readers until close, including digest checks.
    drop(executable);
    let manifest = host_manifest(output)?;
    root.write_json("org.sweepx.browser_bridge.json", &manifest, INPUT_CAP)?;
    root.write_json(
        "bundle.json",
        &json!({"schema":"sweepx.browser_extension.bundle/v1",
        "sweepxVersion":env!("CARGO_PKG_VERSION"),"extensionId":EXTENSION_ID,
        "hostSha256":hash_file(&output.join(host_filename()))?}),
        INPUT_CAP,
    )?;
    let mut guide = root.create_state_file("INSTALL.txt")?;
    guide.write_all(format!(
        "SweepX 浏览器扩展 / Browser extension\n\n1. sweepx browser-extension register --browser chrome --bundle '{}'\n   Edge: --browser edge. Updating an existing SweepX host: add --replace.\n2. In the matching browser profile, open its Extensions page, enable Developer mode, Load unpacked: {}/extension\n3. Click SweepX, choose the matching browser/profile and scan. Review each domain before removal.\n\n更新 / Update: export a NEW bundle with the new SweepX version, register --replace, and load/reload the new extension directory. Local unpacked updates are manual; no store release exists.\n\nmacOS/Linux registration supported. Windows: register HKCU Software\\Google\\Chrome (or Microsoft\\Edge)\\NativeMessagingHosts\\{HOST} default REG_SZ as the absolute path to org.sweepx.browser_bridge.json. Registry installation is not automated.\n\nPermissions: browsingData, nativeMessaging; no host/all-URL, cookie, history or page-injection permission. Browser policy may refuse; do not bypass it. Removal has no Trash. Keep this bundle at its installed path. Extension ID {EXTENSION_ID}.\n",
        output.display(),output.display()).as_bytes())?;
    guide.sync_all()?;
    Ok(
        json!({"schema":"sweepx.browser_extension.bundle/v1","bundle":output,
        "extensionDirectory":output.join("extension"),"extensionId":EXTENSION_ID,
        "hostRegistered":false,"extensionInstalled":false,"guide":output.join("INSTALL.txt")}),
    )
}

fn read_json(directory: &Directory, name: &str) -> io::Result<Option<Value>> {
    match directory.read_bytes(name, INPUT_CAP as u64) {
        Ok(read) => {
            let bytes = read
                .contents
                .ok_or_else(|| io::Error::other("bridge_record_size_limit"))?;
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(io::Error::other)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn registration_path(browser: &str) -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("home_unavailable"))?;
    #[cfg(target_os = "macos")]
    let root = PathBuf::from(home)
        .join("Library/Application Support")
        .join(if browser == "chrome" {
            "Google/Chrome"
        } else {
            "Microsoft Edge"
        });
    #[cfg(not(target_os = "macos"))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".config"))
        .join(if browser == "chrome" {
            "google-chrome"
        } else {
            "microsoft-edge"
        });
    Ok(root.join("NativeMessagingHosts"))
}

fn register(browser: &str, bundle: &Path, replace: bool) -> io::Result<Value> {
    let root = Directory::open(bundle, false)?;
    let extension = root.child("extension")?;
    for (name, contents) in ASSETS {
        let observed = extension.read_bytes(name, INPUT_CAP as u64)?;
        if observed.contents.as_deref() != Some(contents.as_bytes()) {
            return Err(io::Error::other(
                "bundle_assets_do_not_match_this_sweepx_version",
            ));
        }
    }
    let metadata = read_json(&root, "bundle.json")?
        .ok_or_else(|| io::Error::other("bundle_metadata_missing"))?;
    // Open through retained private authority before hashing the display path. The copied
    // executable is user-managed software, not scanned/deletion authority. Registration can
    // become stale if the user subsequently edits/moves it; Chrome reports connection failure.
    let executable = root
        .read_bytes(host_filename(), EXECUTABLE_CAP)?
        .contents
        .ok_or_else(|| io::Error::other("executable_size_limit"))?;
    let digest = format!("{:x}", Sha256::digest(&executable));
    if metadata["hostSha256"].as_str() != Some(digest.as_str())
        || digest != hash_file(&std::env::current_exe()?)?
    {
        return Err(io::Error::other("bundle_host_digest_mismatch"));
    }
    let manifest = host_manifest(bundle)?;
    if read_json(&root, "org.sweepx.browser_bridge.json")? != Some(manifest.clone()) {
        return Err(io::Error::other("bundle_manifest_mismatch"));
    }
    #[cfg(unix)]
    {
        let path = registration_path(browser)?;
        let directory = Directory::open(&path, true)?;
        let _lock = directory.lock()?;
        let name = "org.sweepx.browser_bridge.json";
        if let Some(existing) = read_json(&directory, name)? {
            if !replace {
                return Err(io::Error::other("registration_exists_use_replace"));
            }
            if existing["name"] != HOST
                || existing["allowed_origins"] != json!([ORIGIN])
                || existing["type"] != "stdio"
            {
                return Err(io::Error::other("existing_registration_is_not_sweepx"));
            }
        }
        directory.write_json(name, &manifest, INPUT_CAP)?;
        Ok(
            json!({"schema":"sweepx.browser_extension.registration/v1","browser":browser,
            "manifest":path.join(name),"extensionId":EXTENSION_ID,"hostRegistered":true,
            "extensionInstalled":false,"next":"Load unpacked extension directory in the matching browser profile"}),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (browser, replace);
        Err(io::Error::other(
            "windows_registration_requires_manual_HKCU_setup_see_INSTALL_txt",
        ))
    }
}

fn bridge_root() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA");
    #[cfg(not(windows))]
    let base = std::env::var_os("HOME");
    base.map(PathBuf::from)
        .unwrap_or_default()
        .join(".sweepx-browser-bridge")
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(io::Error::other)
}

fn valid_selection(browser: &str, profile: &str) -> io::Result<()> {
    if ![
        "chrome",
        "edge",
        "chrome-beta",
        "chrome-dev",
        "edge-beta",
        "edge-dev",
    ]
    .contains(&browser)
        || profile.len() > 80
        || !(profile == "Default"
            || profile
                .strip_prefix("Profile ")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())))
    {
        return Err(io::Error::other("unsupported_browser_profile"));
    }
    Ok(())
}

fn scan(
    browser: &str,
    profile: &str,
    cancel: &CancellationToken,
) -> io::Result<BrowserStorageAnalysis> {
    valid_selection(browser, profile)?;
    let mut installations = default_installations();
    installations.retain(|i| i.browser == browser);
    Ok(analyze_site_storage(&installations, Some(profile), cancel))
}

fn queue_request(root: &Path, browser: &str, profile: &str, domain: &str) -> io::Result<Value> {
    let analysis = scan(browser, profile, &CancellationToken::new())?;
    let plan = cleanup_plan(&analysis, browser, profile, domain).map_err(io::Error::other)?;
    publish_request(root, serde_json::to_value(plan).map_err(io::Error::other)?)
}

fn publish_request(root: &Path, plan: Value) -> io::Result<Value> {
    let directory = Directory::open(root, true)?;
    let _lock = directory.lock()?;
    let time = now()?;
    if let Some(existing) = read_json(&directory, "pending.json")?
        && existing["expiresAt"]
            .as_u64()
            .is_some_and(|expiry| expiry > time)
    {
        return Err(io::Error::other(
            "pending_request_exists_review_or_wait_for_expiry",
        ));
    }
    let request = json!({"schema":"sweepx.browser_bridge.request/v1",
        "requestId":format!("{}-{}",SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos(),std::process::id()),"createdAt":time,
        "expiresAt":time+REQUEST_TTL,"plan":plan});
    directory.write_json("pending.json", &request, INPUT_CAP)?;
    Ok(json!({"queued":true,"applied":false,"request":request,
        "next":"Open SweepX extension in the matching profile and review the pending request"}))
}

fn mailbox_status(root: &Path) -> io::Result<Value> {
    let directory = match Directory::open(root, false) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(json!({"pending":null,"lastResult":null}));
        }
        Err(e) => return Err(e),
    };
    let _lock = directory.lock()?;
    Ok(json!({"pending":read_json(&directory,"pending.json")?,
        "lastResult":read_json(&directory,"result.json")?,"now":now()?}))
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Hello {
        id: String,
    },
    Scan {
        id: String,
        browser: String,
        profile: String,
    },
    Plan {
        id: String,
        browser: String,
        profile: String,
        domain: String,
    },
    Pending {
        id: String,
        browser: String,
        profile: String,
    },
    Complete {
        id: String,
        request_id: String,
        status: Completion,
        mode: Option<RemovalMode>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Completion {
    BrowserCompleted,
    Failed,
    Rejected,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RemovalMode {
    Cache,
    Storage,
}
impl Request {
    fn id(&self) -> &str {
        match self {
            Self::Hello { id }
            | Self::Scan { id, .. }
            | Self::Plan { id, .. }
            | Self::Pending { id, .. }
            | Self::Complete { id, .. } => id,
        }
    }
}

pub(crate) fn is_host_invocation() -> bool {
    std::env::args_os()
        .next()
        .and_then(|p| PathBuf::from(p).file_name().map(|n| n == host_filename()))
        .unwrap_or(false)
}

pub(crate) fn host_main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(4).collect();
    if args.first().and_then(|a| a.to_str()) != Some(ORIGIN)
        || args.len() > 2
        || args.get(1).is_some_and(|a| {
            !a.to_str().is_some_and(|s| {
                s.strip_prefix("--parent-window=")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })
        })
    {
        eprintln!("native_host_requires_registered_extension_origin");
        return ExitCode::from(3);
    }
    let cancel = CancellationToken::new();
    let reader_cancel = cancel.clone();
    // One reader and eight bounded frames. EOF or malformed input cancels an in-flight scan.
    // A blocked kernel read can delay detection; the native scanner's cancellation is cooperative.
    let (sender, receiver) = std::sync::mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            match read_frame(&mut input) {
                Ok(Some(value)) => match sender.try_send(Ok(value)) {
                    Ok(()) => (),
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        reader_cancel.cancel();
                        let _ = sender.send(Err(io::Error::other("native_message_queue_limit")));
                        break;
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                },
                Ok(None) => {
                    reader_cancel.cancel();
                    break;
                }
                Err(e) => {
                    reader_cancel.cancel();
                    let _ = sender.send(Err(e));
                    break;
                }
            }
        }
    });
    let mut output = io::stdout().lock();
    let mut inventory: Option<(String, String, BrowserStorageAnalysis)> = None;
    // Persistent browser ports may poll while a review tab is open. There is no detached
    // service: browser disconnect ends this process, and scans only start on explicit requests.
    for frame in receiver {
        let result = (|| {
            let value = frame?;
            let request: Request = serde_json::from_value(value).map_err(io::Error::other)?;
            if request.id().is_empty()
                || request.id().len() > 64
                || !request
                    .id()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(io::Error::other("invalid_request_id"));
            }
            let id = request.id().to_owned();
            let response = (|| Ok::<Value, io::Error>(match request {
                Request::Hello { .. } => json!({"kind":"hello","id":id,"protocol":1,"hostVersion":env!("CARGO_PKG_VERSION"),"extensionId":EXTENSION_ID}),
                Request::Scan { browser, profile, .. } => {
                    // Release the old report before starting another bounded analysis.
                    inventory = None;
                    let analysis = scan(&browser, &profile, &cancel)?;
                    stream_inventory(&mut output, &id, &analysis)?;
                    inventory = Some((browser, profile, analysis));
                    json!({"kind":"done","id":id})
                }
                Request::Plan { browser, profile, domain, .. } => {
                    valid_selection(&browser, &profile)?;
                    let (_, _, analysis) = inventory.as_ref().filter(|(b,p,_)| *b == browser && *p == profile)
                        .ok_or_else(|| io::Error::other("scan_required_for_selected_profile"))?;
                    let plan = cleanup_plan(analysis, &browser, &profile, &domain).map_err(io::Error::other)?;
                    json!({"kind":"plan","id":id,"plan":plan})
                }
                Request::Pending { browser, profile, .. } => {
                    valid_selection(&browser, &profile)?;
                    let status = mailbox_status(&bridge_root())?;
                    let pending = status["pending"].as_object().filter(|p|
                        p.get("expiresAt").and_then(Value::as_u64).is_some_and(|t| t > now().unwrap_or(u64::MAX))
                        && p.get("plan").is_some_and(|v| v["browser"] == browser && v["profile"] == profile));
                    json!({"kind":"pending","id":id,"request":pending})
                }
                Request::Complete { request_id, status, mode, .. } => {
                    let result = complete_request(&bridge_root(), &request_id, status, mode)?;
                    json!({"kind":"recorded","id":id,"result":result})
                }
            }))().unwrap_or_else(|e| json!({"kind":"error","id":id,"error":e.to_string()}));
            write_frame(&mut output, &response)
        })();
        if let Err(e) = result {
            // Protocol errors do not fall through to CLI stdout. Close rather than guess a
            // request correlation; the adapter rejects all unfinished work on disconnect.
            eprintln!("browser_bridge: {e}");
            let _ = write_frame(&mut output, &json!({"kind":"fatal","error":e.to_string()}));
            return ExitCode::from(3);
        }
    }
    ExitCode::SUCCESS
}

fn complete_request(
    root: &Path,
    request_id: &str,
    status: Completion,
    mode: Option<RemovalMode>,
) -> io::Result<Value> {
    if !matches!(status, Completion::Rejected) && mode.is_none() {
        return Err(io::Error::other("completion_requires_removal_mode"));
    }
    let directory = Directory::open(root, false)?;
    let _lock = directory.lock()?;
    let pending = read_json(&directory, "pending.json")?
        .ok_or_else(|| io::Error::other("no_pending_request"))?;
    if pending["requestId"] != request_id
        || pending["expiresAt"]
            .as_u64()
            .is_none_or(|t| t <= now().unwrap_or(u64::MAX))
    {
        return Err(io::Error::other("pending_request_mismatch_or_expired"));
    }
    let result = json!({"schema":"sweepx.browser_bridge.result/v1","requestId":request_id,
        "status":status,"mode":mode,"plan":pending["plan"],"reportedAt":now()?,
        "evidence":"browser_extension_report","reclaimedBytes":null,"independentlyVerified":false});
    directory.write_json("result.json", &result, INPUT_CAP)?;
    // Only disposable request metadata is unlinked, never browser storage or user files.
    directory.remove("pending.json")?;
    Ok(result)
}

fn stream_inventory(
    output: &mut impl Write,
    id: &str,
    analysis: &BrowserStorageAnalysis,
) -> io::Result<()> {
    let mut report = crate::site_storage_command::render_json(analysis, None);
    let domains = report["domains"].take();
    let profiles = report["profiles"].take();
    // The same summaries as the CLI; profiles are split into category facts and origin rows.
    // Paths are unnecessary for browser operations and never leave the native host here.
    write_frame(output, &json!({"kind":"start","id":id,"report":report}))?;
    for chunk in domains
        .as_array()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .chunks(20)
    {
        write_frame(
            output,
            &json!({"kind":"rows","id":id,"collection":"domains","rows":chunk}),
        )?;
    }
    for mut profile in profiles.as_array().into_iter().flatten().cloned() {
        let origins = profile["origins"].take();
        profile
            .as_object_mut()
            .expect("serialized report")
            .remove("subsystemPath");
        write_frame(
            output,
            &json!({"kind":"rows","id":id,"collection":"categories","rows":[profile.clone()]}),
        )?;
        for chunk in origins
            .as_array()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .chunks(20)
        {
            let rows: Vec<_> = chunk
                .iter()
                .map(|row| {
                    let mut row = (*row).clone();
                    row.as_object_mut()
                        .expect("serialized origin")
                        .remove("directories");
                    row["browser"] = profile["browser"].clone();
                    row["profileName"] = profile["profileName"].clone();
                    row["subsystem"] = profile["subsystem"].clone();
                    row
                })
                .collect();
            write_frame(
                output,
                &json!({"kind":"rows","id":id,"collection":"origins","rows":rows}),
            )?;
        }
    }
    Ok(())
}

fn read_frame(input: &mut impl Read) -> io::Result<Option<Value>> {
    let mut header = [0; 4];
    if input.read(&mut header[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut header[1..])?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > INPUT_CAP {
        return Err(io::Error::other("native_message_input_limit"));
    }
    let mut payload = vec![0; length];
    input.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(io::Error::other)
}

fn write_frame(output: &mut impl Write, value: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.len() > OUTPUT_CAP {
        return Err(io::Error::other("native_message_output_limit"));
    }
    output.write_all(&(payload.len() as u32).to_ne_bytes())?;
    output.write_all(&payload)?;
    output.flush()
}

#[cfg(test)]
mod tests;
