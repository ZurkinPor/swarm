use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;

use crate::crypto::Crypto;
use crate::packet::{self, Packet, ResponsePacket};
use crate::protocol::FrameCodec;

/// Connect to a swarm server and interact.
pub async fn run_client(
    server_addr: SocketAddr,
    crypto: Arc<Crypto>,
    username: String,
    role: Option<String>,
    capabilities: Vec<String>,
    workspace_mode: String,
    project_root: Option<String>,
) -> anyhow::Result<()> {
    println!(
        "[CLIENT] Connecting to swarm at {} as '{}' (role: {:?}, workspace: {})",
        server_addr, username, role, workspace_mode
    );

    let stream = TcpStream::connect(server_addr).await?;
    println!("[CLIENT] Connected!");

    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let mut framed = FramedRead::new(reader, FrameCodec);

    // Send JOIN
    let join_packet = Packet::Join(packet::JoinPayload {
        username: username.clone(),
        role: role.clone(),
        capabilities,
        workspace_mode: Some(workspace_mode),
        project_root,
    });
    send_packet(&writer, &crypto, &join_packet).await?;

    // Spawn a task to read incoming packets (notifications, responses, P2P requests)
    let writer_p2p = writer.clone();
    let writer_clone = writer.clone();
    let crypto_read = crypto.clone();
    let crypto_cmd = crypto.clone();
    let username_clone = username.clone();
    let username_read = username.clone();

    let read_handle = tokio::spawn(async move {
        while let Some(frame_result) = framed.next().await {
            let encrypted = match frame_result {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[CLIENT] Frame error: {}", e);
                    break;
                }
            };
            let decrypted = match crypto_read.decrypt(&encrypted) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[CLIENT] Decrypt error: {}", e);
                    continue;
                }
            };
            // Try to parse as a response first
            if let Ok(response) = serde_json::from_slice::<ResponsePacket>(&decrypted) {
                handle_response(&response);
                continue;
            }
            // Try to parse as a Packet (notification or P2P request)
            if let Ok(packet) = serde_json::from_slice::<Packet>(&decrypted) {
                // Check if it's a P2P request directed at us
                if let Some(response) =
                    handle_p2p_request(&packet, &username_read)
                {
                    // Send response back via the writer
                    let payload = serde_json::to_vec(&response).unwrap();
                    if let Ok(encrypted) = crypto_read.encrypt(&payload) {
                        let mut w = writer_p2p.lock().await;
                        let len = encrypted.len() as u32;
                        let _ = w.write_all(&len.to_be_bytes()).await;
                        let _ = w.write_all(&encrypted).await;
                        let _ = w.flush().await;
                    }
                    continue;
                }
                handle_incoming_packet(&packet, &username_read);
                continue;
            }
            eprintln!(
                "[CLIENT] Received unknown data: {}",
                String::from_utf8_lossy(&decrypted)
            );
        }
        println!("[CLIENT] Read loop ended");
    });

    // Interactive CLI prompt loop
    println!("[CLIENT] Type 'help' for commands, 'quit' to leave.");
    let stdin = tokio::io::stdin();
    let mut buf = String::new();
    let mut stdin_reader = tokio::io::BufReader::new(stdin);

    loop {
        buf.clear();
        print!("swarm> ");
        use std::io::Write;
        std::io::stdout().flush().ok();

        let n = stdin_reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        let line = buf.trim();
        if line.is_empty() {
            continue;
        }

        match line {
            "quit" | "exit" => break,
            "help" => print_help(),
            _ => {
                let packet = parse_command(line, &username_clone);
                if let Some(p) = packet {
                    send_packet(&writer_clone, &crypto_cmd, &p).await?;
                } else {
                    println!("Unknown command. Type 'help' for available commands.");
                }
            }
        }
    }

    // Send LEAVE
    let leave_packet = Packet::Leave(packet::LeavePayload {
        username: username.clone(),
        reason: Some("User exited".into()),
    });
    send_packet(&writer, &crypto, &leave_packet).await?;

    read_handle.abort();
    println!("[CLIENT] Disconnected from swarm.");
    Ok(())
}

async fn send_packet(
    writer: &Mutex<impl AsyncWriteExt + Unpin>,
    crypto: &Crypto,
    packet: &Packet,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(packet)?;
    let encrypted = crypto.encrypt(&payload)?;
    let mut w = writer.lock().await;
    let len = encrypted.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&encrypted).await?;
    w.flush().await?;
    Ok(())
}

/// Handle a P2P request forwarded from the server. Returns a ResponsePacket
/// if this is a P2P request directed at us.
fn handle_p2p_request(
    packet: &Packet,
    our_username: &str,
) -> Option<ResponsePacket> {
    match packet {
        Packet::ListDrives(payload) => {
            if payload.target == our_username {
                let drives = list_local_drives();
                Some(ResponsePacket::ListDrivesResult {
                    requester: payload.requester.clone(),
                    drives,
                })
            } else {
                None
            }
        }
        Packet::ListDir(payload) => {
            if payload.target == our_username {
                match list_local_dir(&payload.path, payload.recursive) {
                    Ok(entries) => Some(ResponsePacket::ListDirResult {
                        requester: payload.requester.clone(),
                        path: payload.path.clone(),
                        entries,
                    }),
                    Err(e) => Some(ResponsePacket::Error {
                        requester: payload.requester.clone(),
                        message: format!("Failed to list directory: {}", e),
                    }),
                }
            } else {
                None
            }
        }
        Packet::HttpRequest(payload) => {
            if payload.target == our_username {
                Some(ResponsePacket::HttpRequestResult {
                    requester: payload.requester.clone(),
                    status_code: 501,
                    headers: vec![],
                    body: "HTTP forwarding from client not yet implemented".into(),
                })
            } else {
                None
            }
        }
        Packet::ToolCall(payload) => {
            if payload.target == our_username {
                Some(ResponsePacket::ToolCallResult {
                    requester: payload.requester.clone(),
                    tool_name: payload.tool_name.clone(),
                    success: false,
                    output: format!(
                        "Tool '{}' not recognized on this agent.",
                        payload.tool_name
                    ),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn handle_response(resp: &ResponsePacket) {
    match resp {
        ResponsePacket::ListDrivesResult { drives, .. } => {
            println!("[DRIVES] {}", drives.join(", "));
        }
        ResponsePacket::ListDirResult { path, entries, .. } => {
            println!("[DIR] {}:", path);
            for entry in entries {
                let kind = if entry.is_dir { "[DIR]" } else { "[FILE]" };
                println!("  {} {} ({} bytes)", kind, entry.name, entry.size_bytes);
            }
        }
        ResponsePacket::HttpRequestResult {
            status_code,
            body,
            ..
        } => {
            println!("[HTTP] Status: {}", status_code);
            let preview: String = body.chars().take(500).collect();
            println!("[HTTP] Body: {}", preview);
            if body.len() > 500 {
                println!("... ({} more chars)", body.len() - 500);
            }
        }
        ResponsePacket::ToolCallResult {
            tool_name,
            success,
            output,
            ..
        } => {
            let status = if *success { "OK" } else { "FAILED" };
            println!("[TOOL:{}] {}: {}", tool_name, status, output);
        }
        ResponsePacket::ChannelListResult { channels, .. } => {
            if channels.is_empty() {
                println!("[CHANNELS] No visible channels.");
            } else {
                println!("[CHANNELS]");
                for ch in channels {
                    println!(
                        "  #{} ({} members, {} by {})",
                        ch.name, ch.member_count, ch.visibility, ch.created_by
                    );
                    if let Some(desc) = &ch.description {
                        if !desc.is_empty() {
                            println!("    {}", desc);
                        }
                    }
                }
            }
        }
        ResponsePacket::Error { message, .. } => {
            println!("[ERROR] {}", message);
        }
    }
}

fn handle_incoming_packet(packet: &Packet, our_username: &str) {
    match packet {
        Packet::Notify(n) => match n {
            packet::NotifyPayload::AgentJoined {
                username,
                role,
                workspace_mode,
                project_root,
            } => {
                let mode_str = workspace_mode.as_deref().unwrap_or("git");
                let root_str = project_root
                    .as_ref()
                    .map(|r| format!(" root={}", r))
                    .unwrap_or_default();
                println!(
                    "[SWARM] Agent '{}' joined (role: {:?}, workspace: {}{})",
                    username, role, mode_str, root_str
                );
            }
            packet::NotifyPayload::AgentLeft { username, reason } => {
                println!(
                    "[SWARM] Agent '{}' left{}",
                    username,
                    reason
                        .as_ref()
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default()
                );
            }
            packet::NotifyPayload::TaskCreated {
                task_id,
                title,
                assigned_role,
            } => {
                println!(
                    "[SWARM] Task created: '{}' (id: {}) role: {:?}",
                    title, task_id, assigned_role
                );
            }
            packet::NotifyPayload::TaskAssigned {
                task_id,
                username,
            } => {
                println!("[SWARM] Task {} assigned to '{}'", task_id, username);
            }
            packet::NotifyPayload::TaskCompleted {
                task_id,
                username,
                ..
            } => {
                println!("[SWARM] Task {} completed by '{}'", task_id, username);
            }
            packet::NotifyPayload::ChannelCreated {
                name,
                created_by,
                visibility,
                ..
            } => {
                println!(
                    "[SWARM] Channel '{}' created by '{}' ({})",
                    name, created_by, visibility
                );
            }
            packet::NotifyPayload::ChannelJoined {
                channel_name,
                username,
            } => {
                println!("[SWARM] '{}' joined channel '{}'", username, channel_name);
            }
            packet::NotifyPayload::ChannelLeft {
                channel_name,
                username,
            } => {
                println!("[SWARM] '{}' left channel '{}'", username, channel_name);
            }
            packet::NotifyPayload::ChannelDeleted {
                channel_name,
                deleted_by,
            } => {
                println!(
                    "[SWARM] Channel '{}' deleted by '{}'",
                    channel_name, deleted_by
                );
            }
            packet::NotifyPayload::StatusUpdate {
                username,
                status,
                task_id,
                progress_pct,
            } => {
                let extra = if let (Some(tid), Some(pct)) = (task_id, progress_pct) {
                    format!(" on task {} ({}%)", tid, pct)
                } else {
                    String::new()
                };
                println!("[SWARM] Agent '{}' is {}{}", username, status, extra);
            }
            packet::NotifyPayload::MessageReceived { from, to, body } => {
                if to == our_username {
                    println!("[MSG from {}] {}", from, body);
                }
            }
        },
        Packet::Message(msg) => {
            println!("[MSG] {}: {}", msg.from, msg.body);
        }
        _ => {
            // P2P requests are handled separately
        }
    }
}

fn parse_command(line: &str, username: &str) -> Option<Packet> {
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

    match cmd {
        "msg" | "message" => {
            let mut sub = rest.splitn(2, ' ');
            let target = sub.next()?;
            let body = sub.next().unwrap_or("");
            // #prefix means channel, otherwise direct
            let to = if let Some(channel) = target.strip_prefix('#') {
                packet::MessageTarget::Channel {
                    channel: channel.to_string(),
                }
            } else {
                packet::MessageTarget::Direct {
                    username: target.to_string(),
                }
            };
            Some(Packet::Message(packet::MessagePayload {
                from: username.to_string(),
                to,
                body: body.to_string(),
            }))
        }
        "task" => {
            let mut role = None;
            let mut title = rest.to_string();
            if let Some(idx) = rest.rfind("role:") {
                role = Some(rest[idx + 5..].trim().to_string());
                title = rest[..idx].trim().to_string();
            }
            Some(Packet::CreateTask(packet::CreateTaskPayload {
                title,
                description: String::new(),
                priority: packet::TaskPriority::Normal,
                assigned_role: role,
                assign_to: None,
            }))
        }
        "take" => {
            let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?;
            Some(Packet::TakeTask(packet::TakeTaskPayload {
                task_ids: vec![task_id],
                username: username.to_string(),
            }))
        }
        "done" => {
            let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?;
            Some(Packet::TaskComplete(packet::TaskCompletePayload {
                task_id,
                username: username.to_string(),
                result: None,
                artifacts: vec![],
            }))
        }
        "status" => {
            Some(Packet::Status(packet::StatusPayload {
                username: username.to_string(),
                status: packet::AgentStatus::Working,
                task_id: None,
                progress_pct: None,
                message: Some(rest.to_string()),
            }))
        }
        "channel" => {
            // channel <name> [description] [--private]
            let is_private = rest.contains("--private");
            let clean = rest.replace("--private", "").trim().to_string();
            let mut sub = clean.splitn(2, ' ');
            let name = sub.next().unwrap_or("").trim().to_string();
            let desc = sub.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if name.is_empty() {
                return None;
            }
            Some(Packet::CreateChannel(packet::CreateChannelPayload {
                name,
                created_by: username.to_string(),
                description: desc,
                visibility: if is_private {
                    Some("private".into())
                } else {
                    Some("public".into())
                },
            }))
        }
        "channels" | "list-channels" => {
            Some(Packet::ListChannels(packet::ListChannelsPayload {
                requester: username.to_string(),
            }))
        }
        "join" => {
            let name = rest.trim();
            if name.is_empty() {
                return None;
            }
            Some(Packet::JoinChannel(packet::JoinChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            }))
        }
        "leave" => {
            let name = rest.trim();
            if name.is_empty() {
                return None;
            }
            Some(Packet::LeaveChannel(packet::LeaveChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            }))
        }
        "delete-channel" => {
            let name = rest.trim();
            if name.is_empty() {
                return None;
            }
            Some(Packet::DeleteChannel(packet::DeleteChannelPayload {
                channel_name: name.to_string(),
                requested_by: username.to_string(),
            }))
        }
        "hide" => {
            let name = rest.trim();
            if name.is_empty() {
                return None;
            }
            Some(Packet::HideChannel(packet::HideChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            }))
        }
        "drives" => {
            let target = rest.trim();
            if target.is_empty() {
                return None;
            }
            Some(Packet::ListDrives(packet::ListDrivesPayload {
                requester: username.to_string(),
                target: target.to_string(),
            }))
        }
        "ls" | "dir" => {
            let mut sub = rest.splitn(2, ':');
            let target = sub.next()?;
            let path = sub.next().unwrap_or(".");
            Some(Packet::ListDir(packet::ListDirPayload {
                requester: username.to_string(),
                target: target.to_string(),
                path: path.to_string(),
                recursive: false,
            }))
        }
        "http" => {
            let mut sub = rest.splitn(3, ' ');
            let target = sub.next()?;
            let method = sub.next().unwrap_or("GET");
            let url = sub.next().unwrap_or("");
            let method = match method.to_uppercase().as_str() {
                "GET" => packet::HttpMethod::GET,
                "POST" => packet::HttpMethod::POST,
                "PUT" => packet::HttpMethod::PUT,
                "DELETE" => packet::HttpMethod::DELETE,
                _ => return None,
            };
            Some(Packet::HttpRequest(packet::HttpRequestPayload {
                requester: username.to_string(),
                target: target.to_string(),
                method,
                url: url.to_string(),
                headers: vec![],
                body: None,
                query_params: vec![],
            }))
        }
        "tool" => {
            let mut sub = rest.splitn(3, ' ');
            let target = sub.next()?;
            let tool_name = sub.next()?;
            let args_str = sub.next().unwrap_or("{}");
            let arguments: serde_json::Value = serde_json::from_str(args_str).ok()?;
            Some(Packet::ToolCall(packet::ToolCallPayload {
                requester: username.to_string(),
                target: target.to_string(),
                tool_name: tool_name.to_string(),
                arguments,
            }))
        }
        _ => None,
    }
}

// ── Local system helpers ──

fn list_local_drives() -> Vec<String> {
    if cfg!(windows) {
        ('A'..='Z')
            .map(|c| format!("{}:\\", c))
            .filter(|d| std::path::Path::new(d).exists())
            .collect()
    } else {
        vec!["/".to_string()]
    }
}

fn list_local_dir(path: &str, recursive: bool) -> anyhow::Result<Vec<packet::DirEntry>> {
    let mut result = Vec::new();
    let entries = std::fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let is_dir = metadata.is_dir();
        let entry_path = entry.path();
        result.push(packet::DirEntry {
            name: entry.file_name().to_string_lossy().into(),
            is_dir,
            size_bytes: metadata.len(),
        });
        if recursive && is_dir {
            let sub_path = entry_path.to_string_lossy().to_string();
            match list_local_dir(&sub_path, true) {
                Ok(sub_entries) => {
                    for se in sub_entries {
                        result.push(packet::DirEntry {
                            name: format!("{}/{}", entry.file_name().to_string_lossy(), se.name),
                            is_dir: se.is_dir,
                            size_bytes: se.size_bytes,
                        });
                    }
                }
                Err(_) => {} // skip inaccessible subdirs
            }
        }
    }
    Ok(result)
}

fn print_help() {
    println!("Swarm Client Commands:");
    println!("  Channels (private, encrypted Discord/Slack):");
    println!("  channel <name> [desc] [--private]  Create a channel");
    println!("  channels                            List visible channels");
    println!("  join <name>                         Join a channel");
    println!("  leave <name>                        Leave a channel");
    println!("  delete-channel <name>               Delete a channel you created");
    println!("  hide <name>                         Hide a channel from your list");
    println!("  Messaging:");
    println!("  msg <user> <body>                   Send a direct message");
    println!("  msg #<channel> <body>               Send a channel message");
    println!("  Tasks:");
    println!("  task <title> [role:<r>]             Create a new task");
    println!("  take <task_id>                      Claim a task");
    println!("  done <task_id>                      Mark a task as complete");
    println!("  status <msg>                        Update your status");
    println!("  Remote ops:");
    println!("  drives <target>                     List drives on a remote agent");
    println!("  ls <target>:<path>                  List directory on a remote agent");
    println!("  http <t> <method> <url>             Send HTTP request via remote agent");
    println!("  tool <t> <name> [args]              Invoke a tool on a remote agent");
    println!("  help                                Show this help");
    println!("  quit                                Leave the swarm");
}
