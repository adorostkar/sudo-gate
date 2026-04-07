use crate::config::SecurityConfig;
use crate::ipc::Request;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RequesterIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct NormalizedCommand {
    pub exe: String,
    pub argv: Vec<String>,
    pub display: String,
}

pub fn validate_request_shape(req: &Request, security: &SecurityConfig) -> Result<()> {
    if req.reason.trim().is_empty() {
        bail!("reason is required");
    }
    if req.reason.len() > security.max_reason_len {
        bail!(
            "reason too long ({} > {})",
            req.reason.len(),
            security.max_reason_len
        );
    }
    if req.argv.is_empty() {
        bail!("argv is required");
    }
    if req.argv.len() > security.max_arg_count {
        bail!(
            "too many argv entries ({} > {})",
            req.argv.len(),
            security.max_arg_count
        );
    }
    for arg in &req.argv {
        if arg.len() > security.max_arg_len {
            bail!(
                "argument too long ({} > {})",
                arg.len(),
                security.max_arg_len
            );
        }
    }
    Ok(())
}

pub fn validate_requester(identity: &RequesterIdentity, security: &SecurityConfig) -> Result<()> {
    if !security.requester_allow_uids.is_empty()
        && !security.requester_allow_uids.contains(&identity.uid)
    {
        bail!("requester uid {} is not allowed", identity.uid);
    }
    Ok(())
}

pub fn canonicalize_command(argv: &[String]) -> Result<NormalizedCommand> {
    if argv.is_empty() {
        bail!("argv is required");
    }

    let exe_path = Path::new(&argv[0]);
    if !exe_path.is_absolute() {
        bail!("executable path must be absolute");
    }

    let canonical = fs::canonicalize(exe_path)
        .with_context(|| format!("canonicalize executable: {}", exe_path.display()))?;
    let exe = canonical.to_string_lossy().to_string();

    let mut normalized_argv = Vec::with_capacity(argv.len());
    normalized_argv.push(exe.clone());
    normalized_argv.extend(argv.iter().skip(1).cloned());

    Ok(NormalizedCommand {
        display: render_cmd(&normalized_argv),
        exe,
        argv: normalized_argv,
    })
}

fn render_cmd(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if arg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._/:".contains(c))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\\', "\\\\").replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
