//! Binary tool call protocol.
//!
//! Compact wire format for invoking tools — 1 byte magic, 1 byte tool ID,
//! then packed strings for target, requester, and JSON arguments.
//!
//! Wire format (after decryption):
//!
//! ```text
//! Byte 0:    0x01 (magic = binary tool call — not JSON)
//! Byte 1:    tool_id (u8) — see registry below
//! Bytes 2-3: target_len  (u16, big-endian)
//! Bytes 4..:  target      (UTF-8 string)
//! Next 2:    requester_len (u16, big-endian)
//! Next ..:   requester     (UTF-8 string)
//! Next 4:    args_len      (u32, big-endian)
//! Next ..:   args_json     (UTF-8 JSON string)
//! ```
//!
//! Total per-tool-call overhead: 12 bytes + target + requester.
//!
//! ## Tool Registry
//!
//! | ID    | Name                | Category    |
//! |-------|---------------------|-------------|
//! | 0x01  | write_file          | file        |
//! | 0x02  | read_file           | file        |
//! | 0x03  | run_command         | shell       |
//! | 0x04  | list_dir            | file        |
//! | 0x05  | create_dir          | file        |
//! | 0x06  | delete_file         | file        |
//! | 0x07  | file_exists         | file        |
//! | 0x80  | spawn_agents        | ai-orch     |
//! | 0x81  | read_files          | ai-context  |
//! | 0x82  | read_subtree        | ai-context  |
//! | 0x83  | write_todos         | ai-plan     |
//! | 0x84  | suggest_followups   | ai-ux       |
//! | 0x85  | str_replace         | ai-edit     |
//! | 0x86  | ask_user            | ai-ux       |
//! | 0x87  | read_url            | ai-web      |
//! | 0x88  | render_ui           | ai-ux       |
//! | 0x89  | gravity_index       | ai-services |
//! | 0x8A  | file_picker         | ai-context  |
//! | 0x8B  | code_searcher       | ai-context  |
//! | 0x8C  | researcher_web      | ai-web      |
//! | 0x8D  | researcher_docs     | ai-web      |
//! | 0x8E  | basher              | ai-shell    |
//! | 0x8F  | tmux_cli            | ai-shell    |
//! | 0x90  | browser_use         | ai-browser  |
//! | 0x91  | code_reviewer       | ai-review   |
//! | 0x92  | thinker             | ai-think    |
//! | 0x93  | glob                | ai-context  |

use serde_json::Value;

/// Magic byte that signals "this decrypted frame is a binary tool call, not JSON."
pub const BINARY_TOOL_CALL_MAGIC: u8 = 0x01;

/// A decoded binary tool call.
#[derive(Debug, Clone)]
pub struct BinaryToolCall {
    pub tool_id: u8,
    pub target: String,
    pub requester: String,
    pub arguments: Value,
}

/// ── Encode ──────────────────────────────────────────────────

/// Pack a tool call into the binary wire format.
///
/// Returns a `Vec<u8>` ready to be encrypted and sent as a frame.
pub fn encode_binary_tool_call(
    tool_id: u8,
    target: &str,
    requester: &str,
    args_json: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // Magic byte
    buf.push(BINARY_TOOL_CALL_MAGIC);

    // Tool ID
    buf.push(tool_id);

    // Target (u16 len + bytes)
    let t = target.as_bytes();
    buf.extend_from_slice(&(t.len() as u16).to_be_bytes());
    buf.extend_from_slice(t);

    // Requester (u16 len + bytes)
    let r = requester.as_bytes();
    buf.extend_from_slice(&(r.len() as u16).to_be_bytes());
    buf.extend_from_slice(r);

    // Args JSON (u32 len + bytes)
    let a = args_json.as_bytes();
    buf.extend_from_slice(&(a.len() as u32).to_be_bytes());
    buf.extend_from_slice(a);

    buf
}

/// ── Decode ──────────────────────────────────────────────────

/// Try to decode a binary tool call from decrypted bytes.
///
/// Returns `Ok(Some(call))` on success, `Ok(None)` if the magic byte
/// doesn't match, or `Err(msg)` if the magic matches but the data is
/// corrupted / truncated.
pub fn decode_binary_tool_call(data: &[u8]) -> Result<Option<BinaryToolCall>, String> {
    if data.is_empty() || data[0] != BINARY_TOOL_CALL_MAGIC {
        return Ok(None);
    }

    if data.len() < 4 {
        return Err("Binary tool call too short (need at least 4 bytes)".into());
    }

    let tool_id = data[1];
    let mut pos: usize = 2;

    // Target
    let target_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + target_len + 2 {
        return Err("Binary tool call truncated at target".into());
    }
    let target = String::from_utf8_lossy(&data[pos..pos + target_len]).to_string();
    pos += target_len;

    // Requester
    let req_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + req_len + 4 {
        return Err("Binary tool call truncated at requester".into());
    }
    let requester = String::from_utf8_lossy(&data[pos..pos + req_len]).to_string();
    pos += req_len;

    // Args
    let args_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
        as usize;
    pos += 4;
    if data.len() < pos + args_len {
        return Err("Binary tool call truncated at args".into());
    }
    let args_str = String::from_utf8_lossy(&data[pos..pos + args_len]);
    let arguments: Value =
        serde_json::from_str(&args_str).map_err(|e| format!("Invalid args JSON: {}", e))?;

    Ok(Some(BinaryToolCall {
        tool_id,
        target,
        requester,
        arguments,
    }))
}

/// ── Tool name ↔ ID registry ─────────────────────────────────

/// Map a tool ID byte to its canonical name.
pub fn tool_id_to_name(id: u8) -> &'static str {
    match id {
        0x01 => "write_file",
        0x02 => "read_file",
        0x03 => "run_command",
        0x04 => "list_dir",
        0x05 => "create_dir",
        0x06 => "delete_file",
        0x07 => "file_exists",
        0x80 => "spawn_agents",
        0x81 => "read_files",
        0x82 => "read_subtree",
        0x83 => "write_todos",
        0x84 => "suggest_followups",
        0x85 => "str_replace",
        0x86 => "ask_user",
        0x87 => "read_url",
        0x88 => "render_ui",
        0x89 => "gravity_index",
        0x8A => "file_picker",
        0x8B => "code_searcher",
        0x8C => "researcher_web",
        0x8D => "researcher_docs",
        0x8E => "basher",
        0x8F => "tmux_cli",
        0x90 => "browser_use",
        0x91 => "code_reviewer",
        0x92 => "thinker",
        0x93 => "glob",
        _ => "unknown",
    }
}

/// Map a canonical tool name to its binary ID.
#[allow(dead_code)]
pub fn tool_name_to_id(name: &str) -> Option<u8> {
    match name {
        "write_file" => Some(0x01),
        "read_file" => Some(0x02),
        "run_command" | "run_cmd" | "shell" => Some(0x03),
        "list_dir" | "ls" => Some(0x04),
        "create_dir" | "mkdir" => Some(0x05),
        "delete_file" | "rm" => Some(0x06),
        "file_exists" => Some(0x07),
        "spawn_agents" => Some(0x80),
        "read_files" => Some(0x81),
        "read_subtree" => Some(0x82),
        "write_todos" => Some(0x83),
        "suggest_followups" => Some(0x84),
        "str_replace" => Some(0x85),
        "ask_user" => Some(0x86),
        "read_url" => Some(0x87),
        "render_ui" => Some(0x88),
        "gravity_index" => Some(0x89),
        "file_picker" => Some(0x8A),
        "code_searcher" => Some(0x8B),
        "researcher_web" => Some(0x8C),
        "researcher_docs" => Some(0x8D),
        "basher" => Some(0x8E),
        "tmux_cli" => Some(0x8F),
        "browser_use" => Some(0x90),
        "code_reviewer" => Some(0x91),
        "thinker" => Some(0x92),
        "glob" => Some(0x93),
        _ => None,
    }
}

/// Return a pretty-printed list of all known tools.
#[allow(dead_code)]
pub fn list_tools() -> Vec<(u8, &'static str, &'static str)> {
    vec![
        (0x01, "write_file", "Create or overwrite a file"),
        (0x02, "read_file", "Read one or more files from disk"),
        (0x03, "run_command", "Execute a shell command"),
        (0x04, "list_dir", "List files and directories"),
        (0x05, "create_dir", "Create directories recursively"),
        (0x06, "delete_file", "Delete a file"),
        (0x07, "file_exists", "Check whether a path exists"),
        (0x80, "spawn_agents", "Spawn specialized sub-agents"),
        (0x81, "read_files", "Read files with parsed metadata"),
        (0x82, "read_subtree", "Read a directory tree blob"),
        (0x83, "write_todos", "Track objectives via step-by-step plan"),
        (0x84, "suggest_followups", "Suggest next-step followup actions"),
        (0x85, "str_replace", "Edit files with exact-string replacement"),
        (0x86, "ask_user", "Ask the user multiple-choice questions"),
        (0x87, "read_url", "Fetch a URL and extract readable text"),
        (0x88, "render_ui", "Render interactive UI widgets"),
        (0x89, "gravity_index", "Discover and compare 3rd-party services"),
        (0x8A, "file_picker", "Fuzzy-search for relevant files"),
        (0x8B, "code_searcher", "Run ripgrep queries over the codebase"),
        (0x8C, "researcher_web", "Browse the web for information"),
        (0x8D, "researcher_docs", "Read technical library documentation"),
        (0x8E, "basher", "Run a single terminal command"),
        (0x8F, "tmux_cli", "Interact with CLI apps via tmux"),
        (0x90, "browser_use", "Automate Chrome via DevTools"),
        (0x91, "code_reviewer", "Review code changes for bugs"),
        (0x92, "thinker", "Deep reasoning with Gemini"),
        (0x93, "glob", "Find files by glob pattern"),
    ]
}

/// Check if a decrypted payload starts with the binary tool call magic.
#[inline]
pub fn is_binary_tool_call(data: &[u8]) -> bool {
    data.first() == Some(&BINARY_TOOL_CALL_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encode_decode() {
        let encoded = encode_binary_tool_call(
            0x01,
            "agent-42",
            "buffy",
            r#"{"path":"/tmp/test.txt","content":"hello"}"#,
        );

        // Should start with magic
        assert_eq!(encoded[0], 0x01);
        assert_eq!(encoded[1], 0x01); // write_file

        let decoded = decode_binary_tool_call(&encoded).unwrap().unwrap();
        assert_eq!(decoded.tool_id, 0x01);
        assert_eq!(decoded.target, "agent-42");
        assert_eq!(decoded.requester, "buffy");
        assert_eq!(decoded.arguments["path"], "/tmp/test.txt");
        assert_eq!(decoded.arguments["content"], "hello");
    }

    #[test]
    fn magic_detection() {
        assert!(is_binary_tool_call(&[0x01]));
        assert!(is_binary_tool_call(&[0x01, 0x02, 0x00]));
        assert!(!is_binary_tool_call(&[0x7B])); // JSON '{'
        assert!(!is_binary_tool_call(&[]));
    }

    #[test]
    fn non_magic_returns_none() {
        assert!(decode_binary_tool_call(b"{\"type\":\"Join\"}")
            .unwrap()
            .is_none());
    }

    #[test]
    fn name_id_roundtrip() {
        for (id, name, _) in list_tools() {
            assert_eq!(tool_id_to_name(id), name);
            assert_eq!(tool_name_to_id(name), Some(id));
        }
    }

    #[test]
    fn all_aliases_map() {
        assert_eq!(tool_name_to_id("run_command"), Some(0x03));
        assert_eq!(tool_name_to_id("run_cmd"), Some(0x03));
        assert_eq!(tool_name_to_id("shell"), Some(0x03));
        assert_eq!(tool_name_to_id("list_dir"), Some(0x04));
        assert_eq!(tool_name_to_id("ls"), Some(0x04));
        assert_eq!(tool_name_to_id("create_dir"), Some(0x05));
        assert_eq!(tool_name_to_id("mkdir"), Some(0x05));
        assert_eq!(tool_name_to_id("delete_file"), Some(0x06));
        assert_eq!(tool_name_to_id("rm"), Some(0x06));
    }
}
