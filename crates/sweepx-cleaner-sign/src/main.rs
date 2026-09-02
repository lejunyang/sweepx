//! Command line entry point for development-time cleaner package signing.
//!
//! Argument parsing is hand-rolled to avoid adding a CLI framework dependency to a
//! tool that ships to no one and takes at most three inputs.

use std::path::PathBuf;
use std::process::ExitCode;

use sweepx_cleaner_sign::{SigningKeyFile, sign_package};
use time::OffsetDateTime;

const USAGE: &str = "\
sweepx-cleaner-sign — development-time signing for SweepX cleaner packages

USAGE:
    sweepx-cleaner-sign keygen --key <PATH> --key-id <ID> --publisher <ID>
    sweepx-cleaner-sign sign   --package <DIR> --key <PATH>

COMMANDS:
    keygen    Generate a development signing key and print its trust-store entry.
    sign      Recompute rule digests and packageDigest, write SIGNATURE, then verify
              the result through the real catalog loader.

NOTES:
    Key ids must contain \"dev\". This tool mints development signatures only; a
    release key belongs in a controlled environment, not in a working tree.
    After keygen, add the printed TrustedKey entry to BUILTIN_TRUST_STORE in
    crates/sweepx-catalog/src/lib.rs before the signed package will load.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print!("{USAGE}");
        return Err("no command given".to_owned());
    };
    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "keygen" => keygen(&rest),
        "sign" => sign(&rest),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => {
            print!("{USAGE}");
            Err(format!("unknown command {other:?}"))
        }
    }
}

fn keygen(args: &[String]) -> Result<(), String> {
    let key = required(args, "--key")?;
    let key_id = required(args, "--key-id")?;
    let publisher = required(args, "--publisher")?;
    let path = PathBuf::from(key);
    if path.exists() {
        // Overwriting silently would invalidate every package already signed with the
        // existing key, with no way to recover it.
        return Err(format!(
            "{} already exists; remove it explicitly to replace the key",
            path.display()
        ));
    }
    let generated = SigningKeyFile::generate(key_id, publisher, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    generated.write(&path).map_err(|error| error.to_string())?;
    println!("wrote {}", path.display());
    println!(
        "\nadd this to BUILTIN_TRUST_STORE in crates/sweepx-catalog/src/lib.rs:\n\n{}\n",
        generated.trust_store_entry()
    );
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    let package = PathBuf::from(required(args, "--package")?);
    let key = PathBuf::from(required(args, "--key")?);
    let outcome = sign_package(&package, &key, OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    println!("package digest: {}", outcome.package_digest);
    println!(
        "cleaner.json:   {}",
        if outcome.manifest_updated {
            "rewritten"
        } else {
            "unchanged"
        }
    );
    if outcome.publisher_rekeyed {
        println!("publisher:      repointed at the signing key");
    }
    println!("signed files:   {}", outcome.signed_paths.len());
    for path in &outcome.signed_paths {
        println!("  {path}");
    }
    println!("verified through the catalog loader using the signing key");
    if !outcome.key_is_builtin_trusted {
        // Not a failure: the package is internally consistent. But the shipped binary
        // only accepts compiled-in anchors, so say so plainly instead of letting the
        // contributor hit an opaque UnknownKey error at runtime.
        eprintln!(
            "\nnote: this key is not in BUILTIN_TRUST_STORE, so the shipped binary will\n      \
             reject the package until the trust-store entry is added (see `keygen` output)."
        );
    }
    Ok(())
}

fn required(args: &[String], flag: &str) -> Result<String, String> {
    let position = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("missing required {flag}"))?;
    args.get(position + 1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}
