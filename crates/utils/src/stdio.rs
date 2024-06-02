use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

pub fn make_stdout_stderr<P>(command: P, envs: &HashMap<String, String>) -> Result<(Stdio, Stdio)>
where
    P: AsRef<Path>,
{
    let command = command.as_ref();
    let filename = command
        .file_name()
        .context("Failed to obtain basename from command path")?;
    let filename = filename
        .to_str()
        .context("Failed to process command as it contains invalid UTF-8")?;
    let base = if envs.contains_key("XDG_RUNTIME_DIR") {
        Path::new(&envs["XDG_RUNTIME_DIR"])
    } else {
        Path::new("/tmp")
    };
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let path_stdout = base.join(format!("krun-{filename}-{ts}.stdout"));
    let path_stderr = base.join(format!("krun-{filename}-{ts}.stderr"));
    Ok((
        File::create_new(path_stdout)?.into(),
        File::create_new(path_stderr)?.into(),
    ))
}
