use serde_json::Value;
use std::process::Command;

/// Execute a named tool with the given arguments. Returns (success, output).
pub fn execute_tool(tool_name: &str, args: &Value) -> (bool, String) {
    match tool_name {
        "write_file" => tool_write_file(args),
        "read_file" => tool_read_file(args),
        "run_command" | "run_cmd" | "shell" => tool_run_command(args),
        "list_dir" | "ls" => tool_list_dir(args),
        "create_dir" | "mkdir" => tool_create_dir(args),
        "delete_file" | "rm" => tool_delete_file(args),
        "file_exists" => tool_file_exists(args),
        _ => (
            false,
            format!(
                "Tool '{}' not recognized. Available: write_file, read_file, run_command, list_dir, create_dir, delete_file, file_exists",
                tool_name
            ),
        ),
    }
}

fn tool_write_file(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    let content = match args["content"].as_str() {
        Some(c) => c,
        None => return (false, "Missing 'content' argument".into()),
    };
    // Create parent directories if needed
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::write(path, content) {
        Ok(()) => (true, format!("Wrote {} bytes to {}", content.len(), path)),
        Err(e) => (false, format!("Failed to write {}: {}", path, e)),
    }
}

fn tool_read_file(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    match std::fs::read_to_string(path) {
        Ok(content) => (true, content),
        Err(e) => (false, format!("Failed to read {}: {}", path, e)),
    }
}

fn tool_run_command(args: &Value) -> (bool, String) {
    let cmd_str = match args["command"].as_str() {
        Some(c) => c,
        None => return (false, "Missing 'command' argument".into()),
    };
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };
    match Command::new(shell).arg(flag).arg(cmd_str).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let success = output.status.success();
            let mut result = stdout;
            if !stderr.is_empty() {
                result.push_str("\n[stderr]\n");
                result.push_str(&stderr);
            }
            (success, result)
        }
        Err(e) => (false, format!("Failed to run command: {}", e)),
    }
}

fn tool_list_dir(args: &Value) -> (bool, String) {
    let path = args["path"].as_str().unwrap_or(".");
    let recursive = args["recursive"].as_bool().unwrap_or(false);
    match list_dir_recursive(path, recursive) {
        Ok(result) => (true, result),
        Err(e) => (false, format!("Failed to list {}: {}", path, e)),
    }
}

fn list_dir_recursive(path: &str, recursive: bool) -> Result<String, std::io::Error> {
    let mut lines = Vec::new();
    let entries = std::fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        let kind = if meta.is_dir() { "d" } else { "f" };
        lines.push(format!("{} {} ({}b)", kind, entry.file_name().to_string_lossy(), meta.len()));
        if recursive && meta.is_dir() {
            let sub = entry.path();
            if let Ok(sub_lines) = list_dir_recursive(&sub.to_string_lossy(), true) {
                for sl in sub_lines.lines() {
                    lines.push(format!("  {}", sl));
                }
            }
        }
    }
    Ok(lines.join("\n"))
}

fn tool_create_dir(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    match std::fs::create_dir_all(path) {
        Ok(()) => (true, format!("Created directory: {}", path)),
        Err(e) => (false, format!("Failed to create {}: {}", path, e)),
    }
}

fn tool_delete_file(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    match std::fs::remove_file(path) {
        Ok(()) => (true, format!("Deleted: {}", path)),
        Err(e) => (false, format!("Failed to delete {}: {}", path, e)),
    }
}

fn tool_file_exists(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    let exists = std::path::Path::new(path).exists();
    (true, format!("{}", exists))
}
