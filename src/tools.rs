use serde_json::Value;
use std::process::{Command, Stdio};
use std::io::{Read, Write};

/// Execute a named tool with the given arguments. Returns (success, output).
pub fn execute_tool(tool_name: &str, args: &Value) -> (bool, String) {
    match tool_name {
        // File system
        "write_file" => tool_write_file(args),
        "read_file" => tool_read_file(args),
        "list_dir" | "ls" => tool_list_dir(args),
        "create_dir" | "mkdir" | "make_dir" => tool_create_dir(args),
        "delete_file" | "rm" => tool_delete_file(args),
        "file_exists" => tool_file_exists(args),
        "copy_file" | "cp" => tool_copy_file(args),
        "move_file" | "mv" | "rename" => tool_move_file(args),
        "file_size" => tool_file_size(args),

        // Shell / system
        "run_command" | "run_cmd" | "shell" => tool_run_command(args),
        "list_drives" | "drives" => tool_list_drives(args),
        "env_var" | "get_env" => tool_env_var(args),
        "whoami" => tool_whoami(args),
        "sleep" => tool_sleep(args),

        // Network
        "http_get" => tool_http_get(args),

        // AI / planning
        "write_todos" => tool_write_todos(args),

        _ => (
            false,
            format!(
                "Tool '{}' not recognized. Available: write_file, read_file, run_command, list_dir, create_dir, delete_file, file_exists, copy_file, move_file, file_size, list_drives, http_get, env_var, whoami, sleep, write_todos",
                tool_name
            ),
        ),
    }
}

// ── File system tools ─────────────────────────────────────────

fn tool_write_file(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    let content = match args["content"].as_str() {
        Some(c) => c,
        None => return (false, "Missing 'content' argument".into()),
    };
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
    let max_bytes = args["max_bytes"].as_u64().unwrap_or(1_000_000) as usize;
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.len() > max_bytes {
                (
                    true,
                    format!(
                        "{}\n... [truncated at {} bytes, total {} bytes]",
                        &content[..max_bytes],
                        max_bytes,
                        content.len()
                    ),
                )
            } else {
                (true, content)
            }
        }
        Err(e) => (false, format!("Failed to read {}: {}", path, e)),
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
        lines.push(format!(
            "{} {} ({}b)",
            kind,
            entry.file_name().to_string_lossy(),
            meta.len()
        ));
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

fn tool_copy_file(args: &Value) -> (bool, String) {
    let src = match args["src"].as_str() {
        Some(s) => s,
        None => return (false, "Missing 'src' argument".into()),
    };
    let dst = match args["dst"].as_str() {
        Some(d) => d,
        None => return (false, "Missing 'dst' argument".into()),
    };
    if let Some(parent) = std::path::Path::new(dst).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::copy(src, dst) {
        Ok(bytes) => (true, format!("Copied {} bytes from {} to {}", bytes, src, dst)),
        Err(e) => (false, format!("Failed to copy {} → {}: {}", src, dst, e)),
    }
}

fn tool_move_file(args: &Value) -> (bool, String) {
    let src = match args["src"].as_str() {
        Some(s) => s,
        None => return (false, "Missing 'src' argument".into()),
    };
    let dst = match args["dst"].as_str() {
        Some(d) => d,
        None => return (false, "Missing 'dst' argument".into()),
    };
    if let Some(parent) = std::path::Path::new(dst).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::rename(src, dst) {
        Ok(()) => (true, format!("Moved {} → {}", src, dst)),
        Err(e) => (false, format!("Failed to move {} → {}: {}", src, dst, e)),
    }
}

fn tool_file_size(args: &Value) -> (bool, String) {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return (false, "Missing 'path' argument".into()),
    };
    match std::fs::metadata(path) {
        Ok(meta) => {
            let bytes = meta.len();
            if meta.is_dir() {
                (true, format!("{} (directory)", human_size(bytes)))
            } else {
                (true, format!("{} bytes ({})", bytes, human_size(bytes)))
            }
        }
        Err(e) => (false, format!("Failed to stat {}: {}", path, e)),
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.1} {}", size, UNITS[unit_idx])
}

// ── Shell / system tools ──────────────────────────────────────

fn tool_run_command(args: &Value) -> (bool, String) {
    let cmd_str = match args["command"].as_str() {
        Some(c) => c,
        None => return (false, "Missing 'command' argument".into()),
    };
    let cwd = args["cwd"].as_str();
    let timeout_secs = args["timeout"].as_u64().unwrap_or(30);
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };

    let mut child = match Command::new(shell)
        .arg(flag)
        .arg(cmd_str)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(cwd.unwrap_or("."))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to spawn command: {}", e)),
    };

    // Wait with timeout — kill the child if it exceeds the limit
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }
                let success = status.success();
                let mut result = stdout;
                if !stderr.is_empty() {
                    result.push_str("\n[stderr]\n");
                    result.push_str(&stderr);
                }
                return (success, result);
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (false, format!("Command timed out after {}s", timeout_secs));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                let _ = child.kill();
                return (false, format!("Command error: {}", e));
            }
        }
    }
}

fn tool_list_drives(_args: &Value) -> (bool, String) {
    let drives: Vec<String> = if cfg!(windows) {
        ('A'..='Z')
            .map(|c| format!("{}:\\", c))
            .filter(|d| std::path::Path::new(d).exists())
            .collect()
    } else {
        vec!["/".to_string()]
    };
    if drives.is_empty() {
        (true, "(no drives found)".into())
    } else {
        (true, drives.join("\n"))
    }
}

fn tool_env_var(args: &Value) -> (bool, String) {
    let name = args["name"].as_str();
    match name {
        Some(n) => match std::env::var(n) {
            Ok(val) => (true, val),
            Err(_) => (true, "(not set)".into()),
        },
        None => {
            // List all, but cap at 200 vars to avoid blowing up output
            let all: Vec<(String, String)> = std::env::vars().collect();
            let total = all.len();
            let max_show = args["max"].as_u64().unwrap_or(200) as usize;
            let mut vars: Vec<String> = all
                .iter()
                .take(max_show)
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            vars.sort();
            let mut result = vars.join("\n");
            if total > max_show {
                result.push_str(&format!(
                    "\n... [showing {}/{} vars; use 'name' to query a specific one]",
                    max_show, total
                ));
            }
            (true, result)
        }
    }
}

fn tool_whoami(_args: &Value) -> (bool, String) {
    let hostname = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    } else {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    };
    let user = if cfg!(windows) {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
    } else {
        std::env::var("USER").unwrap_or_else(|_| "unknown".into())
    };
    let os = std::env::consts::OS;
    (true, format!("{}@{} ({})", user, hostname, os))
}

fn tool_sleep(args: &Value) -> (bool, String) {
    let ms = args["ms"].as_u64().unwrap_or(1000);
    let actual_ms = ms.min(60_000); // cap at 60s
    std::thread::sleep(std::time::Duration::from_millis(actual_ms));
    (true, format!("Slept {}ms", actual_ms))
}

// ── Network tools ─────────────────────────────────────────────

fn tool_http_get(args: &Value) -> (bool, String) {
    let url = match args["url"].as_str() {
        Some(u) => u,
        None => return (false, "Missing 'url' argument".into()),
    };

    let parsed = match parse_url(url) {
        Ok(p) => p,
        Err(e) => return (false, e),
    };

    let addr = format!("{}:{}", parsed.host, parsed.port);
    let timeout = std::time::Duration::from_secs(args["timeout"].as_u64().unwrap_or(10));

    match std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap()),
        timeout,
    ) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(timeout)).ok();
            stream.set_write_timeout(Some(timeout)).ok();

            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Swarm/0.1\r\n\r\n",
                parsed.path, parsed.host
            );
            if stream.write_all(request.as_bytes()).is_err() {
                return (false, "Failed to send HTTP request".into());
            }

            let mut response = Vec::new();
            if stream.read_to_end(&mut response).is_err() {
                return (false, "Failed to read HTTP response".into());
            }

            let resp_str = String::from_utf8_lossy(&response);
            // Extract status code from first line
            let first_line = resp_str.lines().next().unwrap_or("HTTP/1.1 ???");
            let is_success = first_line.contains("200") || first_line.contains("201") || first_line.contains("204");

            let truncated: String = resp_str.chars().take(10_000).collect();
            let mut result = truncated;
            if resp_str.len() > 10_000 {
                result.push_str(&format!(
                    "\n... [truncated, {} more chars]",
                    resp_str.len() - 10_000
                ));
            }
            (is_success, result)
        }
        Err(e) => (false, format!("HTTP connection failed: {}", e)),
    }
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let url = if !url.contains("://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    };

    let without_scheme = url
        .strip_prefix("https://")
        .unwrap_or_else(|| url.strip_prefix("http://").unwrap_or(&url));

    let (host_port, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let port: u16 = host_port[idx + 1..]
                .parse()
                .map_err(|_| format!("Invalid port in URL: {}", url))?;
            (&host_port[..idx], port)
        }
        None => {
            let default_port = if url.starts_with("https://") { 443 } else { 80 };
            (host_port, default_port)
        }
    };

    Ok(ParsedUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

// ── AI / planning tools ───────────────────────────────────────

fn tool_write_todos(args: &Value) -> (bool, String) {
    let path = args["path"].as_str().unwrap_or("TODO.md");
    let title = args["title"].as_str().unwrap_or("# TODO");
    let todos = match args["todos"].as_array() {
        Some(t) => t,
        None => return (false, "Missing 'todos' argument (JSON array of {task, completed})".into()),
    };

    let mut lines = vec![title.to_string(), String::new()];
    let mut done_count = 0;
    let total = todos.len();

    for (_i, todo) in todos.iter().enumerate() {
        let task = todo["task"].as_str().unwrap_or("unnamed task");
        let completed = todo["completed"].as_bool().unwrap_or(false);
        let check = if completed { "x" } else { " " };
        lines.push(format!("- [{}] {}", check, task));
        if completed {
            done_count += 1;
        }
        if let Some(subtasks) = todo["subtasks"].as_array() {
            for sub in subtasks {
                let sub_task = sub["task"].as_str().unwrap_or("subtask");
                let sub_done = sub["completed"].as_bool().unwrap_or(false);
                let sub_check = if sub_done { "x" } else { " " };
                lines.push(format!("  - [{}] {}", sub_check, sub_task));
            }
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "_{}/{} completed_{}",
        done_count,
        total,
        if done_count == total { " ✅" } else { "" }
    ));

    let content = lines.join("\n");

    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    match std::fs::write(path, &content) {
        Ok(()) => (
            true,
            format!(
                "Wrote TODO.md with {}/{} tasks{}",
                done_count,
                total,
                if done_count == total {
                    " (all done!)"
                } else {
                    ""
                }
            ),
        ),
        Err(e) => (false, format!("Failed to write {}: {}", path, e)),
    }
}
