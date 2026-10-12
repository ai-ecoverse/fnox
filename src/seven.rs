use crate::error::{FnoxError, Result};
use fnox_core::sealed::{self, Wait};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn fnox_seven_signal(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "wasi")]
mod sys {
    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        pub fn callback_signal(name: *const u8, len: u32);
    }

    #[link(wasm_import_module = "slicc")]
    unsafe extern "C" {
        pub fn sigaction_set(signal: u32, disposition: u32, flags: u32) -> u16;
    }
}

pub fn catch_interrupts() {
    #[cfg(target_os = "wasi")]
    unsafe {
        let name = b"fnox_seven_signal";
        sys::callback_signal(name.as_ptr(), name.len() as u32);
        sys::sigaction_set(2, 2, 0);
        sys::sigaction_set(15, 2, 0);
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn request_value(name: &str) -> Result<String> {
    catch_interrupts();
    let request = sealed::request_value(name, Some(&format!("Value for {name}")))?;
    if request.state == "done" {
        return request
            .placeholder
            .ok_or_else(|| FnoxError::Seven("seven: request done without a placeholder".into()));
    }
    let id = request
        .id
        .ok_or_else(|| FnoxError::Seven("seven: request answered without an id".into()))?;
    eprintln!("Enter the value for {name} in seven's vault dialog (Ctrl-C cancels).");
    match sealed::wait_for(
        &id,
        Duration::from_secs(1),
        Duration::from_secs(300),
        &interrupted,
    )? {
        Wait::Done(done) => done
            .placeholder
            .ok_or_else(|| FnoxError::Seven("seven: request done without a placeholder".into())),
        Wait::Cancelled => {
            eprintln!("Cancelled.");
            std::process::exit(130);
        }
        Wait::Ended(ended) => Err(FnoxError::Seven(format!(
            "seven: the request for {name} ended: {}",
            ended.state
        ))),
    }
}

pub struct PreparedExec {
    pub program: std::path::PathBuf,
    pub ticket: String,
    pub kept: Vec<String>,
}

pub fn prepare_exec(
    command: &[String],
    sealed: &[String],
    cwd: &std::path::Path,
    path_var: Option<&std::ffi::OsStr>,
) -> std::result::Result<PreparedExec, PrepareError> {
    let program = resolve_program(&command[0], path_var, cwd).map_err(PrepareError::Program)?;
    let program_str = program.to_string_lossy().to_string();
    let mut argv = vec![program_str.clone()];
    argv.extend(command[1..].iter().cloned());
    let granted = sealed::materialize(sealed, &program_str, &argv, &cwd.to_string_lossy())
        .map_err(PrepareError::Seven)?;
    let kept = sealed
        .iter()
        .filter(|name| !granted.real.get(*name).copied().unwrap_or(false))
        .cloned()
        .collect();
    Ok(PreparedExec {
        program,
        ticket: granted.ticket,
        kept,
    })
}

pub enum PrepareError {
    Program(std::io::Error),
    Seven(FnoxError),
}

pub fn sealed_secret_names(
    config: &crate::config::Config,
    profile: &[String],
) -> Result<indexmap::IndexSet<String>> {
    let providers = config.get_providers(profile)?;
    let default_provider = config.get_default_provider(profile)?;
    let mut names = indexmap::IndexSet::new();
    for (key, secret) in config.get_secrets(profile)? {
        let provider_name = secret.provider().map(str::to_string).or_else(|| {
            secret
                .value()
                .is_some()
                .then(|| default_provider.clone())
                .flatten()
        });
        let sealed = provider_name
            .and_then(|name| providers.get(&name).map(|p| p.provider_type() == "sealed"))
            .unwrap_or(false);
        if sealed {
            names.insert(key);
        }
    }
    Ok(names)
}

pub fn resolve_program(
    command: &str,
    path_var: Option<&std::ffi::OsStr>,
    cwd: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
    let candidate = if command.contains('/') {
        let candidate = cwd.join(command);
        candidate.is_file().then_some(candidate)
    } else {
        path_var
            .map(split_path_var)
            .into_iter()
            .flatten()
            .map(|dir: PathBuf| {
                if dir.as_os_str().is_empty() {
                    cwd.join(command)
                } else if dir.is_relative() {
                    cwd.join(dir).join(command)
                } else {
                    dir.join(command)
                }
            })
            .find(|candidate: &PathBuf| candidate.is_file())
    };
    let candidate = candidate.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{command}: command not found"),
        )
    })?;
    resolve_symlinks(Path::new(&candidate))
}

#[cfg(target_os = "wasi")]
fn split_path_var(value: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    value
        .to_string_lossy()
        .split(':')
        .map(std::path::PathBuf::from)
        .collect()
}

#[cfg(not(target_os = "wasi"))]
fn split_path_var(value: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    std::env::split_paths(value).collect()
}

fn resolve_symlinks(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    use std::path::{Component, PathBuf};
    let mut pending: Vec<std::ffi::OsString> = path
        .components()
        .rev()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    let mut resolved = PathBuf::from("/");
    let mut hops = 0;
    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&part);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    return Err(std::io::Error::other("too many levels of symbolic links"));
                }
                let target = std::fs::read_link(&next)?;
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                for c in target.components().rev() {
                    match c {
                        Component::Normal(name) => pending.push(name.to_os_string()),
                        Component::ParentDir => pending.push("..".into()),
                        _ => {}
                    }
                }
            }
            _ => resolved = next,
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn resolve_program_searches_path_and_follows_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let bin = root.join("bin");
        let real = root.join("real");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("tool"), "").unwrap();
        std::os::unix::fs::symlink("../real/tool", bin.join("tool")).unwrap();
        let path = std::env::join_paths([root.join("missing"), bin.clone()]).unwrap();
        let found = resolve_program("tool", Some(&path), &root).unwrap();
        assert_eq!(found, real.join("tool"));
        let relative = resolve_program("./bin/tool", None, &root).unwrap();
        assert_eq!(relative, real.join("tool"));
        let err = resolve_program("nope", Some(&path), &root).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    fn tool_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/curl"), "").unwrap();
        (dir, root)
    }

    #[test]
    fn prepare_exec_materializes_the_resolved_program() {
        let (_dir, root) = tool_dir();
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.reply(serde_json::json!({ "v": 1, "ticket": "tk", "expiresAt": 0, "real": { "GH": true, "NPM": false } }));
        let path = std::env::join_paths([root.join("bin")]).unwrap();
        let command = vec![
            "curl".to_string(),
            "-sS".to_string(),
            "https://api.github.com".to_string(),
        ];
        let sealed = vec!["GH".to_string(), "NPM".to_string()];
        let prepared = match prepare_exec(&command, &sealed, &root, Some(&path)) {
            Ok(p) => p,
            Err(_) => panic!("prepare failed"),
        };
        assert_eq!(prepared.program, root.join("bin/curl"));
        assert_eq!(prepared.ticket, "tk");
        assert_eq!(prepared.kept, vec!["NPM".to_string()]);
        let sent = mock.requests.lock().unwrap()[0].clone();
        let program = root.join("bin/curl").to_string_lossy().to_string();
        assert_eq!(sent["op"], serde_json::json!("materialize"));
        assert_eq!(sent["path"], serde_json::json!(program));
        assert_eq!(
            sent["argv"],
            serde_json::json!([program, "-sS", "https://api.github.com"])
        );
        assert_eq!(sent["cwd"], serde_json::json!(root.to_string_lossy()));
        assert_eq!(sent["names"], serde_json::json!(["GH", "NPM"]));
        fnox_core::sealed::set_transport(None);
    }

    #[test]
    fn prepare_exec_does_not_ask_the_vault_for_a_missing_program() {
        let (_dir, root) = tool_dir();
        let (_g, mock) = fnox_core::sealed::testing::install();
        let path = std::env::join_paths([root.join("bin")]).unwrap();
        let command = vec!["nope".to_string()];
        assert!(matches!(
            prepare_exec(&command, &["GH".to_string()], &root, Some(&path)),
            Err(PrepareError::Program(_))
        ));
        assert!(mock.ops().is_empty());
        fnox_core::sealed::set_transport(None);
    }

    #[test]
    fn prepare_exec_fails_closed_without_the_device() {
        let (_dir, root) = tool_dir();
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.fail(std::io::Error::from(std::io::ErrorKind::NotFound));
        let path = std::env::join_paths([root.join("bin")]).unwrap();
        match prepare_exec(
            &["curl".to_string()],
            &["GH".to_string()],
            &root,
            Some(&path),
        ) {
            Err(PrepareError::Seven(e)) => assert_eq!(e.to_string(), fnox_core::sealed::MISSING),
            _ => panic!("expected the missing-device error"),
        }
        fnox_core::sealed::set_transport(None);
    }

    #[test]
    fn request_value_returns_the_placeholder_when_done() {
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.reply(serde_json::json!({ "v": 1, "state": "pending", "id": "rq1" }));
        mock.reply(
            serde_json::json!({ "v": 1, "state": "done", "placeholder": "ph", "record": "inert" }),
        );
        assert_eq!(request_value("TOKEN").unwrap(), "ph");
        let first = mock.requests.lock().unwrap()[0].clone();
        assert_eq!(first["kind"], serde_json::json!("value"));
        assert_eq!(first["name"], serde_json::json!("TOKEN"));
        assert_eq!(mock.ops(), vec!["request", "status"]);
        fnox_core::sealed::set_transport(None);
    }

    #[test]
    fn request_value_reports_a_closed_dialog() {
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.reply(serde_json::json!({ "v": 1, "state": "pending", "id": "rq2" }));
        mock.reply(serde_json::json!({ "v": 1, "state": "cancelled" }));
        let err = request_value("TOKEN").unwrap_err().to_string();
        assert_eq!(err, "seven: the request for TOKEN ended: cancelled");
        fnox_core::sealed::set_transport(None);
    }
}
