//! Tool registry — maps tool IDs to names and descriptions.
//!
//! All packets are now binary (see packet.rs). The tool registry provides
//! the canonical name/ID mapping used by the `btc` command and `tools-list`.

/// Map a tool ID byte to its canonical name.
pub fn tool_id_to_name(id: u8) -> &'static str {
    match id {
        0x01 => "write_file", 0x02 => "read_file", 0x03 => "run_command",
        0x04 => "list_dir", 0x05 => "create_dir", 0x06 => "delete_file",
        0x07 => "file_exists", 0x08 => "list_drives", 0x09 => "http_get",
        0x0A => "copy_file", 0x0B => "move_file", 0x0C => "file_size",
        0x0D => "env_var", 0x0E => "sleep", 0x0F => "whoami",
        0x80 => "spawn_agents", 0x81 => "read_files", 0x82 => "read_subtree",
        0x83 => "write_todos", 0x84 => "suggest_followups", 0x85 => "str_replace",
        0x86 => "ask_user", 0x87 => "read_url", 0x88 => "render_ui",
        0x89 => "gravity_index", 0x8A => "file_picker", 0x8B => "code_searcher",
        0x8C => "researcher_web", 0x8D => "researcher_docs", 0x8E => "basher",
        0x8F => "tmux_cli", 0x90 => "browser_use", 0x91 => "code_reviewer",
        0x92 => "thinker", 0x93 => "glob",
        _ => "unknown",
    }
}

/// Map a canonical tool name to its binary ID.
#[allow(dead_code)]
pub fn tool_name_to_id(name: &str) -> Option<u8> {
    match name {
        "write_file" => Some(0x01), "read_file" => Some(0x02),
        "run_command" | "run_cmd" | "shell" => Some(0x03),
        "list_dir" | "ls" => Some(0x04),
        "create_dir" | "mkdir" | "make_dir" => Some(0x05),
        "delete_file" | "rm" => Some(0x06),
        "file_exists" => Some(0x07),
        "list_drives" | "drives" => Some(0x08),
        "http_get" => Some(0x09),
        "copy_file" | "cp" => Some(0x0A),
        "move_file" | "mv" | "rename" => Some(0x0B),
        "file_size" => Some(0x0C),
        "env_var" | "get_env" => Some(0x0D),
        "sleep" => Some(0x0E),
        "whoami" => Some(0x0F),
        "spawn_agents" => Some(0x80), "read_files" => Some(0x81),
        "read_subtree" => Some(0x82), "write_todos" => Some(0x83),
        "suggest_followups" => Some(0x84), "str_replace" => Some(0x85),
        "ask_user" => Some(0x86), "read_url" => Some(0x87),
        "render_ui" => Some(0x88), "gravity_index" => Some(0x89),
        "file_picker" => Some(0x8A), "code_searcher" => Some(0x8B),
        "researcher_web" => Some(0x8C), "researcher_docs" => Some(0x8D),
        "basher" => Some(0x8E), "tmux_cli" => Some(0x8F),
        "browser_use" => Some(0x90), "code_reviewer" => Some(0x91),
        "thinker" => Some(0x92), "glob" => Some(0x93),
        _ => None,
    }
}

/// Full tool list for display.
pub fn list_tools() -> Vec<(u8, &'static str, &'static str)> {
    vec![
        (0x01, "write_file", "Create or overwrite a file"),
        (0x02, "read_file", "Read a file from disk"),
        (0x03, "run_command", "Execute a shell command"),
        (0x04, "list_dir", "List files and directories"),
        (0x05, "create_dir", "Create directories recursively"),
        (0x06, "delete_file", "Delete a file"),
        (0x07, "file_exists", "Check whether a path exists"),
        (0x08, "list_drives", "List mounted drives/volumes"),
        (0x09, "http_get", "Perform an HTTP GET request"),
        (0x0A, "copy_file", "Copy a file from src to dst"),
        (0x0B, "move_file", "Move or rename a file"),
        (0x0C, "file_size", "Get the size of a file"),
        (0x0D, "env_var", "Get an environment variable"),
        (0x0E, "sleep", "Pause for N milliseconds"),
        (0x0F, "whoami", "Return hostname and username"),
        (0x80, "spawn_agents", "Spawn specialized sub-agents"),
        (0x81, "read_files", "Read files with parsed metadata"),
        (0x82, "read_subtree", "Read a directory tree blob"),
        (0x83, "write_todos", "Write a structured TODO.md file"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_aliases_map() {
        assert_eq!(tool_name_to_id("run_command"), Some(0x03));
        assert_eq!(tool_name_to_id("run_cmd"), Some(0x03));
        assert_eq!(tool_name_to_id("shell"), Some(0x03));
        assert_eq!(tool_name_to_id("list_dir"), Some(0x04));
        assert_eq!(tool_name_to_id("ls"), Some(0x04));
        assert_eq!(tool_name_to_id("create_dir"), Some(0x05));
        assert_eq!(tool_name_to_id("mkdir"), Some(0x05));
        assert_eq!(tool_name_to_id("make_dir"), Some(0x05));
        assert_eq!(tool_name_to_id("delete_file"), Some(0x06));
        assert_eq!(tool_name_to_id("rm"), Some(0x06));
        assert_eq!(tool_name_to_id("copy_file"), Some(0x0A));
        assert_eq!(tool_name_to_id("cp"), Some(0x0A));
        assert_eq!(tool_name_to_id("move_file"), Some(0x0B));
        assert_eq!(tool_name_to_id("mv"), Some(0x0B));
        assert_eq!(tool_name_to_id("rename"), Some(0x0B));
    }

    #[test]
    fn all_builtin_ids_known() {
        for id in 0x01u8..=0x0Fu8 {
            let name = tool_id_to_name(id);
            assert!(name != "unknown", "ID 0x{:02X} should be known", id);
        }
    }
}
