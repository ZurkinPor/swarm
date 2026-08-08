use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;

use crate::binary_tool;
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
    pipe_mode: bool,
) -> anyhow::Result<()> {
    if pipe_mode {
        run_pipe_mode(server_addr, crypto, username, role, capabilities, workspace_mode, project_root).await
    } else {
        run_interactive(server_addr, crypto, username, role, capabilities, workspace_mode, project_root).await
    }
}

// ── Interactive mode ──

async fn run_interactive(
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

    let writer_p2p = writer.clone();
    let writer_clone = writer.clone();
    let crypto_read = crypto.clone();
    let crypto_cmd = crypto.clone();
    let username_clone = username.clone();
    let username_read = username.clone();

    // Heartbeat task: send STATUS every 30s to keep connection alive
    let heartbeat_writer = writer.clone();
    let heartbeat_crypto = crypto.clone();
    let heartbeat_username = username.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let ping = Packet::Status(packet::StatusPayload {
                username: heartbeat_username.clone(),
                status: packet::AgentStatus::Idle,
                task_id: None,
                progress_pct: None,
                message: Some("heartbeat".into()),
            });
            if send_packet(&heartbeat_writer, &heartbeat_crypto, &ping).await.is_err() {
                break;
            }
        }
    });

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
            // ── Detect binary tool call (magic byte 0x01) ──
            if crate::binary_tool::is_binary_tool_call(&decrypted) {
                match crate::binary_tool::decode_binary_tool_call(&decrypted) {
                    Ok(Some(btc)) => {
                        if btc.target == username_read {
                            let tool_name = crate::binary_tool::tool_id_to_name(btc.tool_id);
                            eprintln!("[BINARY-TOOL] 0x{:02X} ({}) from {} → executing", btc.tool_id, tool_name, btc.requester);
                            let (success, output) = crate::tools::execute_tool(tool_name, &btc.arguments);
                            let response = ResponsePacket::ToolCallResult {
                                requester: btc.requester,
                                tool_name: tool_name.to_string(),
                                success,
                                output,
                            };
                            let payload = serde_json::to_vec(&response).unwrap();
                            if let Ok(encrypted) = crypto_read.encrypt(&payload) {
                                let mut w = writer_p2p.lock().await;
                                let len = encrypted.len() as u32;
                                let _ = w.write_all(&len.to_be_bytes()).await;
                                let _ = w.write_all(&encrypted).await;
                                let _ = w.flush().await;
                            }
                        }
                        continue;
                    }
                    _ => {}
                }
            }

            if let Ok(response) = serde_json::from_slice::<ResponsePacket>(&decrypted) {
                handle_response(&response);
                continue;
            }
            if let Ok(packet) = serde_json::from_slice::<Packet>(&decrypted) {
                if let Some(response) = handle_p2p_request(&packet, &username_read) {
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
                    send_packet_or_binary(&writer_clone, &crypto_cmd, &p).await?;
                } else {
                    println!("Unknown command. Type 'help' for available commands.");
                }
            }
        }
    }

    let leave_packet = Packet::Leave(packet::LeavePayload {
        username: username.clone(),
        reason: Some("User exited".into()),
    });
    send_packet(&writer, &crypto, &leave_packet).await?;

    heartbeat_handle.abort();
    read_handle.abort();
    println!("[CLIENT] Disconnected from swarm.");
    Ok(())
}

// ── Pipe mode (JSON stdin/stdout for AI harnesses) ──

async fn run_pipe_mode(
    server_addr: SocketAddr,
    crypto: Arc<Crypto>,
    username: String,
    role: Option<String>,
    capabilities: Vec<String>,
    workspace_mode: String,
    project_root: Option<String>,
) -> anyhow::Result<()> {
    eprintln!("[PIPE] Connecting to {} as '{}'", server_addr, username);

    let stream = TcpStream::connect(server_addr).await?;
    eprintln!("[PIPE] Connected");

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

    // Channel for the read task to send events to the main loop
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();

    let writer_p2p = writer.clone();
    let crypto_read = crypto.clone();
    let username_read = username.clone();

    // Heartbeat task for pipe mode
    let heartbeat_writer = writer.clone();
    let heartbeat_crypto = crypto.clone();
    let heartbeat_username = username.clone();
    let _heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let ping = Packet::Status(packet::StatusPayload {
                username: heartbeat_username.clone(),
                status: packet::AgentStatus::Idle,
                task_id: None,
                progress_pct: None,
                message: Some("heartbeat".into()),
            });
            if send_packet(&heartbeat_writer, &heartbeat_crypto, &ping).await.is_err() {
                break;
            }
        }
    });

    // Spawn read task — forwards incoming packets as JSON events
    let _read_handle = tokio::spawn(async move {
        while let Some(frame_result) = framed.next().await {
            let encrypted = match frame_result {
                Ok(f) => f,
                Err(_) => break,
            };
            let decrypted = match crypto_read.decrypt(&encrypted) {
                Ok(d) => d,
                Err(_) => continue,
            };
            // ── Detect binary tool call (magic byte 0x01) ──
            if crate::binary_tool::is_binary_tool_call(&decrypted) {
                match crate::binary_tool::decode_binary_tool_call(&decrypted) {
                    Ok(Some(btc)) => {
                        if btc.target == username_read {
                            let tool_name = crate::binary_tool::tool_id_to_name(btc.tool_id);
                            let (success, output) = crate::tools::execute_tool(tool_name, &btc.arguments);
                            let response = ResponsePacket::ToolCallResult {
                                requester: btc.requester.clone(),
                                tool_name: tool_name.to_string(),
                                success,
                                output,
                            };
                            let payload = serde_json::to_vec(&response).unwrap();
                            if let Ok(encrypted) = crypto_read.encrypt(&payload) {
                                let mut w = writer_p2p.lock().await;
                                let len = encrypted.len() as u32;
                                let _ = w.write_all(&len.to_be_bytes()).await;
                                let _ = w.write_all(&encrypted).await;
                                let _ = w.flush().await;
                            }
                        }
                        // Emit as event too
                        let _ = event_tx.send(json!({"type":"binary_tool_call","data":{"tool_id":format!("0x{:02X}", btc.tool_id),"tool_name":crate::binary_tool::tool_id_to_name(btc.tool_id),"target":btc.target,"requester":btc.requester,"arguments":btc.arguments}}));
                        continue;
                    }
                    _ => {}
                }
            }

            if let Ok(response) = serde_json::from_slice::<ResponsePacket>(&decrypted) {
                let json = serde_json::to_value(&response).unwrap();
                let _ = event_tx.send(json!({"type":"response","data":json}));
                continue;
            }
            if let Ok(packet) = serde_json::from_slice::<Packet>(&decrypted) {
                if let Some(response) = handle_p2p_request(&packet, &username_read) {
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
                let json = serde_json::to_value(&packet).unwrap();
                let _ = event_tx.send(json!({"type":"event","data":json}));
                continue;
            }
        }
    });

    // Signal ready
    let ready = json!({"type":"ready","username":username});
    println!("{}", serde_json::to_string(&ready).unwrap());

    // Read JSON commands from stdin, one per line
    let stdin = tokio::io::stdin();
    let mut buf = String::new();
    let mut stdin_reader = tokio::io::BufReader::new(stdin);

    loop {
        // Check for incoming events first (non-blocking)
        while let Ok(event) = event_rx.try_recv() {
            println!("{}", serde_json::to_string(&event).unwrap());
        }

        buf.clear();
        let n = match stdin_reader.read_line(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let line = buf.trim();
        if line.is_empty() {
            continue;
        }

        // Parse JSON command
        let cmd: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", serde_json::to_string(&json!({"type":"error","message":format!("Invalid JSON: {}", e)})).unwrap());
                continue;
            }
        };

        let cmd_type = cmd["cmd"].as_str().unwrap_or("");

        match cmd_type {
            "quit" | "exit" => break,
            _ => {
                match json_command_to_packet(&cmd, &username) {
                    Ok(Some(packet)) => {
                        send_packet_or_binary(&writer, &crypto, &packet).await?;
                    }
                    Ok(None) => {
                        // Unknown command, ignore
                    }
                    Err(e) => {
                        println!("{}", serde_json::to_string(&json!({"type":"error","message":e})).unwrap());
                    }
                }
            }
        }
    }

    // Drain remaining events
    while let Ok(event) = event_rx.try_recv() {
        println!("{}", serde_json::to_string(&event).unwrap());
    }

    let leave_packet = Packet::Leave(packet::LeavePayload {
        username: username.clone(),
        reason: Some("Pipe closed".into()),
    });
    send_packet(&writer, &crypto, &leave_packet).await?;

    eprintln!("[PIPE] Disconnected");
    Ok(())
}

/// Convert a JSON pipe command into a Packet. Returns Ok(None) for unknown commands.
fn json_command_to_packet(cmd: &Value, username: &str) -> Result<Option<Packet>, String> {
    let cmd_type = cmd["cmd"].as_str().unwrap_or("");
    match cmd_type {
        "msg" | "message" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let body = cmd["body"].as_str().unwrap_or("");
            let to = if let Some(channel) = target.strip_prefix('#') {
                packet::MessageTarget::Channel { channel: channel.to_string() }
            } else {
                packet::MessageTarget::Direct { username: target.to_string() }
            };
            Ok(Some(Packet::Message(packet::MessagePayload {
                from: username.to_string(),
                to,
                body: body.to_string(),
            })))
        }
        "task" => {
            let title = cmd["title"].as_str().ok_or("'title' required")?;
            let description = cmd["description"].as_str().unwrap_or("").to_string();
            let priority = match cmd["priority"].as_str().unwrap_or("normal") {
                "low" => packet::TaskPriority::Low,
                "high" => packet::TaskPriority::High,
                "critical" => packet::TaskPriority::Critical,
                _ => packet::TaskPriority::Normal,
            };
            let assigned_role = cmd["role"].as_str().map(|s| s.to_string());
            Ok(Some(Packet::CreateTask(packet::CreateTaskPayload {
                title: title.to_string(),
                description,
                priority,
                assigned_role,
                assign_to: None,
            })))
        }
        "take" => {
            let task_id = cmd["task_id"].as_str().ok_or("'task_id' required")?;
            let id = uuid::Uuid::parse_str(task_id).map_err(|e| e.to_string())?;
            Ok(Some(Packet::TakeTask(packet::TakeTaskPayload {
                task_ids: vec![id],
                username: username.to_string(),
            })))
        }
        "done" => {
            let task_id = cmd["task_id"].as_str().ok_or("'task_id' required")?;
            let id = uuid::Uuid::parse_str(task_id).map_err(|e| e.to_string())?;
            Ok(Some(Packet::TaskComplete(packet::TaskCompletePayload {
                task_id: id,
                username: username.to_string(),
                result: cmd["result"].as_str().map(|s| s.to_string()),
                artifacts: vec![],
            })))
        }
        "status" => {
            let msg = cmd["message"].as_str().unwrap_or("").to_string();
            Ok(Some(Packet::Status(packet::StatusPayload {
                username: username.to_string(),
                status: packet::AgentStatus::Working,
                task_id: None,
                progress_pct: None,
                message: Some(msg),
            })))
        }
        "channel" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            let description = cmd["description"].as_str().map(|s| s.to_string());
            let is_private = cmd["private"].as_bool().unwrap_or(false);
            Ok(Some(Packet::CreateChannel(packet::CreateChannelPayload {
                name: name.to_string(),
                created_by: username.to_string(),
                description,
                visibility: Some(if is_private { "private".into() } else { "public".into() }),
            })))
        }
        "channels" => {
            Ok(Some(Packet::ListChannels(packet::ListChannelsPayload {
                requester: username.to_string(),
            })))
        }
        "join" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            Ok(Some(Packet::JoinChannel(packet::JoinChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            })))
        }
        "leave" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            Ok(Some(Packet::LeaveChannel(packet::LeaveChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            })))
        }
        "delete-channel" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            Ok(Some(Packet::DeleteChannel(packet::DeleteChannelPayload {
                channel_name: name.to_string(),
                requested_by: username.to_string(),
            })))
        }
        "hide" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            Ok(Some(Packet::HideChannel(packet::HideChannelPayload {
                channel_name: name.to_string(),
                username: username.to_string(),
            })))
        }
        "drives" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            Ok(Some(Packet::ListDrives(packet::ListDrivesPayload {
                requester: username.to_string(),
                target: target.to_string(),
            })))
        }
        "ls" | "dir" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let path = cmd["path"].as_str().unwrap_or(".");
            Ok(Some(Packet::ListDir(packet::ListDirPayload {
                requester: username.to_string(),
                target: target.to_string(),
                path: path.to_string(),
                recursive: false,
            })))
        }
        "http" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let method_str = cmd["method"].as_str().unwrap_or("GET");
            let url = cmd["url"].as_str().ok_or("'url' required")?;
            let method = match method_str.to_uppercase().as_str() {
                "GET" => packet::HttpMethod::GET,
                "POST" => packet::HttpMethod::POST,
                "PUT" => packet::HttpMethod::PUT,
                "DELETE" => packet::HttpMethod::DELETE,
                _ => return Err(format!("Unknown method: {}", method_str)),
            };
            Ok(Some(Packet::HttpRequest(packet::HttpRequestPayload {
                requester: username.to_string(),
                target: target.to_string(),
                method,
                url: url.to_string(),
                headers: vec![],
                body: cmd["body"].as_str().map(|s| s.to_string()),
                query_params: vec![],
            })))
        }
        "tool" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let tool_name = cmd["tool_name"].as_str().ok_or("'tool_name' required")?;
            let arguments = cmd.get("args").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
            Ok(Some(Packet::ToolCall(packet::ToolCallPayload {
                requester: username.to_string(),
                target: target.to_string(),
                tool_name: tool_name.to_string(),
                arguments,
            })))
        }
        "btc" | "binary-tool" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            // Accept decimal or hex (0x prefix) tool ID
            let tool_id: u8 = if let Some(v) = cmd["tool_id"].as_u64() {
                v as u8
            } else if let Some(s) = cmd["tool_id"].as_str() {
                if let Some(hex) = s.strip_prefix("0x") {
                    u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?
                } else {
                    s.parse().map_err(|e| format!("Invalid tool_id: {}", e))?
                }
            } else {
                return Err("'tool_id' required (numeric byte value, e.g. 1 or 0x80)".into());
            };
            let args = cmd.get("args").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
            let args_json = serde_json::to_string(&args).map_err(|e| e.to_string())?;
            Ok(Some(Packet::ToolCall(packet::ToolCallPayload {
                requester: username.to_string(),
                target: target.to_string(),
                tool_name: format!("__binary_0x{:02X}__", tool_id),
                arguments: serde_json::json!({"__binary":true,"tool_id":tool_id,"args_json":args_json}),
            })))
        }
        "tools-list" | "tools_list" => {
            // Return tool list as a special response — pipe mode caller prints it
            let tools: Vec<Value> = binary_tool::list_tools().iter().map(|(id, name, desc)| {
                json!({"id":format!("0x{:02X}", id),"name":name,"description":desc})
            }).collect();
            println!("{}", serde_json::to_string(&json!({"type":"tool_list","tools":tools})).unwrap());
            Ok(None)
        }
        _ => Ok(None),
    }
}

// ── Shared helpers ──

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

/// Like send_packet, but if the packet is a ToolCall with a __binary marker,
/// encodes it using the compact binary wire format instead of JSON.
async fn send_packet_or_binary(
    writer: &Mutex<impl AsyncWriteExt + Unpin>,
    crypto: &Crypto,
    packet: &Packet,
) -> anyhow::Result<()> {
    if let Packet::ToolCall(payload) = packet {
        if payload.arguments.get("__binary").and_then(|v| v.as_bool()) == Some(true) {
            let tool_id = payload.arguments["tool_id"].as_u64().unwrap_or(0) as u8;
            let args_json = payload.arguments["args_json"].as_str().unwrap_or("{}");
            eprintln!(
                "[BINARY-SEND] tool 0x{:02X} → {}",
                tool_id, payload.target
            );
            let raw = binary_tool::encode_binary_tool_call(
                tool_id,
                &payload.target,
                &payload.requester,
                args_json,
            );
            let encrypted = crypto.encrypt(&raw)?;
            let mut w = writer.lock().await;
            let len = encrypted.len() as u32;
            w.write_all(&len.to_be_bytes()).await?;
            w.write_all(&encrypted).await?;
            w.flush().await?;
            return Ok(());
        }
    }
    send_packet(writer, crypto, packet).await
}

fn handle_p2p_request(
    packet: &Packet,
    our_username: &str,
) -> Option<ResponsePacket> {
    match packet {
        Packet::ListDrives(payload) => {
            if payload.target == our_username {
                Some(ResponsePacket::ListDrivesResult {
                    requester: payload.requester.clone(),
                    drives: list_local_drives(),
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
                    body: "HTTP forwarding not yet implemented".into(),
                })
            } else {
                None
            }
        }
        Packet::ToolCall(payload) => {
            if payload.target == our_username {
                let (success, output) = crate::tools::execute_tool(&payload.tool_name, &payload.arguments);
                eprintln!("[TOOL] {} from {} → {} ({})", payload.tool_name, payload.requester, if success { "OK" } else { "FAIL" }, output.chars().take(80).collect::<String>());
                Some(ResponsePacket::ToolCallResult {
                    requester: payload.requester.clone(),
                    tool_name: payload.tool_name.clone(),
                    success,
                    output,
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
        ResponsePacket::HttpRequestResult { status_code, body, .. } => {
            println!("[HTTP] Status: {}", status_code);
            let preview: String = body.chars().take(500).collect();
            println!("[HTTP] Body: {}", preview);
            if body.len() > 500 {
                println!("... ({} more chars)", body.len() - 500);
            }
        }
        ResponsePacket::ToolCallResult { tool_name, success, output, .. } => {
            let status = if *success { "OK" } else { "FAILED" };
            println!("[TOOL:{}] {}: {}", tool_name, status, output);
        }
        ResponsePacket::ChannelListResult { channels, .. } => {
            if channels.is_empty() {
                println!("[CHANNELS] No visible channels.");
            } else {
                println!("[CHANNELS]");
                for ch in channels {
                    println!("  #{} ({} members, {} by {})", ch.name, ch.member_count, ch.visibility, ch.created_by);
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
            packet::NotifyPayload::AgentJoined { username, role, workspace_mode, project_root } => {
                let mode_str = workspace_mode.as_deref().unwrap_or("git");
                let root_str = project_root.as_ref().map(|r| format!(" root={}", r)).unwrap_or_default();
                println!("[SWARM] Agent '{}' joined (role: {:?}, workspace: {}{})", username, role, mode_str, root_str);
            }
            packet::NotifyPayload::AgentLeft { username, reason } => {
                println!("[SWARM] Agent '{}' left{}", username, reason.as_ref().map(|r| format!(" ({})", r)).unwrap_or_default());
            }
            packet::NotifyPayload::TaskCreated { task_id, title, assigned_role } => {
                println!("[SWARM] Task created: '{}' (id: {}) role: {:?}", title, task_id, assigned_role);
            }
            packet::NotifyPayload::TaskAssigned { task_id, username } => {
                println!("[SWARM] Task {} assigned to '{}'", task_id, username);
            }
            packet::NotifyPayload::TaskCompleted { task_id, username, .. } => {
                println!("[SWARM] Task {} completed by '{}'", task_id, username);
            }
            packet::NotifyPayload::ChannelCreated { name, created_by, visibility, .. } => {
                println!("[SWARM] Channel '{}' created by '{}' ({})", name, created_by, visibility);
            }
            packet::NotifyPayload::ChannelJoined { channel_name, username } => {
                println!("[SWARM] '{}' joined channel '{}'", username, channel_name);
            }
            packet::NotifyPayload::ChannelLeft { channel_name, username } => {
                println!("[SWARM] '{}' left channel '{}'", username, channel_name);
            }
            packet::NotifyPayload::ChannelDeleted { channel_name, deleted_by } => {
                println!("[SWARM] Channel '{}' deleted by '{}'", channel_name, deleted_by);
            }
            packet::NotifyPayload::StatusUpdate { username, status, task_id, progress_pct } => {
                let extra = if let (Some(tid), Some(pct)) = (task_id, progress_pct) {
                    format!(" on task {} ({}%)", tid, pct)
                } else { String::new() };
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
        _ => {}
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
            let to = if let Some(channel) = target.strip_prefix('#') {
                packet::MessageTarget::Channel { channel: channel.to_string() }
            } else {
                packet::MessageTarget::Direct { username: target.to_string() }
            };
            Some(Packet::Message(packet::MessagePayload { from: username.to_string(), to, body: body.to_string() }))
        }
        "task" => {
            let mut role = None;
            let mut title = rest.to_string();
            if let Some(idx) = rest.rfind("role:") {
                role = Some(rest[idx + 5..].trim().to_string());
                title = rest[..idx].trim().to_string();
            }
            Some(Packet::CreateTask(packet::CreateTaskPayload { title, description: String::new(), priority: packet::TaskPriority::Normal, assigned_role: role, assign_to: None }))
        }
        "take" => {
            let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?;
            Some(Packet::TakeTask(packet::TakeTaskPayload { task_ids: vec![task_id], username: username.to_string() }))
        }
        "done" => {
            let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?;
            Some(Packet::TaskComplete(packet::TaskCompletePayload { task_id, username: username.to_string(), result: None, artifacts: vec![] }))
        }
        "status" => {
            Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Working, task_id: None, progress_pct: None, message: Some(rest.to_string()) }))
        }
        "channel" => {
            let is_private = rest.contains("--private");
            let clean = rest.replace("--private", "").trim().to_string();
            let mut sub = clean.splitn(2, ' ');
            let name = sub.next().unwrap_or("").trim().to_string();
            let desc = sub.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if name.is_empty() { return None; }
            Some(Packet::CreateChannel(packet::CreateChannelPayload {
                name, created_by: username.to_string(), description: desc,
                visibility: Some(if is_private { "private".into() } else { "public".into() }),
            }))
        }
        "channels" | "list-channels" => {
            Some(Packet::ListChannels(packet::ListChannelsPayload { requester: username.to_string() }))
        }
        "join" => {
            let name = rest.trim();
            if name.is_empty() { return None; }
            Some(Packet::JoinChannel(packet::JoinChannelPayload { channel_name: name.to_string(), username: username.to_string() }))
        }
        "leave" => {
            let name = rest.trim();
            if name.is_empty() { return None; }
            Some(Packet::LeaveChannel(packet::LeaveChannelPayload { channel_name: name.to_string(), username: username.to_string() }))
        }
        "delete-channel" => {
            let name = rest.trim();
            if name.is_empty() { return None; }
            Some(Packet::DeleteChannel(packet::DeleteChannelPayload { channel_name: name.to_string(), requested_by: username.to_string() }))
        }
        "hide" => {
            let name = rest.trim();
            if name.is_empty() { return None; }
            Some(Packet::HideChannel(packet::HideChannelPayload { channel_name: name.to_string(), username: username.to_string() }))
        }
        "drives" => {
            let target = rest.trim();
            if target.is_empty() { return None; }
            Some(Packet::ListDrives(packet::ListDrivesPayload { requester: username.to_string(), target: target.to_string() }))
        }
        "ls" | "dir" => {
            let mut sub = rest.splitn(2, ':');
            let target = sub.next()?;
            let path = sub.next().unwrap_or(".");
            Some(Packet::ListDir(packet::ListDirPayload { requester: username.to_string(), target: target.to_string(), path: path.to_string(), recursive: false }))
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
            Some(Packet::HttpRequest(packet::HttpRequestPayload { requester: username.to_string(), target: target.to_string(), method, url: url.to_string(), headers: vec![], body: None, query_params: vec![] }))
        }
        "tool" => {
            let mut sub = rest.splitn(3, ' ');
            let target = sub.next()?;
            let tool_name = sub.next()?;
            let args_str = sub.next().unwrap_or("{}");
            let arguments: serde_json::Value = serde_json::from_str(args_str).ok()?;
            Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: tool_name.to_string(), arguments }))
        }
        "btc" | "binary-tool" => {
            // Format: btc <target> <tool_id> <json_args>
            // tool_id can be decimal (e.g. 1) or hex (e.g. 0x80)
            let mut sub = rest.splitn(3, ' ');
            let target = sub.next()?;
            let id_str = sub.next()?;
            let args_str = sub.next().unwrap_or("{}");
            let tool_id: u8 = if let Some(hex) = id_str.strip_prefix("0x") {
                u8::from_str_radix(hex, 16).ok()?
            } else {
                id_str.parse().ok()?
            };
            let args: serde_json::Value = serde_json::from_str(args_str).ok()?;
            let args_json = serde_json::to_string(&args).ok()?;
            Some(Packet::ToolCall(packet::ToolCallPayload {
                requester: username.to_string(),
                target: target.to_string(),
                tool_name: format!("__binary_0x{:02X}__", tool_id),
                arguments: serde_json::json!({"__binary":true,"tool_id":tool_id,"args_json":args_json}),
            }))
        }
        "tools-list" | "tools_list" => {
            println!("Binary Tool ID Registry:");
            println!("{:<6} {:<22} {}", "ID", "Name", "Description");
            for (id, name, desc) in binary_tool::list_tools() {
                println!("0x{:02X}   {:<22} {}", id, name, desc);
            }
            // Return a benign status so caller doesn't print "Unknown command"
            Some(Packet::Status(packet::StatusPayload {
                username: username.to_string(),
                status: packet::AgentStatus::Idle,
                task_id: None,
                progress_pct: None,
                message: None,
            }))
        }
        _ => None,
    }
}

fn list_local_drives() -> Vec<String> {
    if cfg!(windows) {
        ('A'..='Z').map(|c| format!("{}:\\", c)).filter(|d| std::path::Path::new(d).exists()).collect()
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
        result.push(packet::DirEntry { name: entry.file_name().to_string_lossy().into(), is_dir, size_bytes: metadata.len() });
        if recursive && is_dir {
            let sub_path = entry_path.to_string_lossy().to_string();
            match list_local_dir(&sub_path, true) {
                Ok(sub_entries) => {
                    for se in sub_entries {
                        result.push(packet::DirEntry { name: format!("{}/{}", entry.file_name().to_string_lossy(), se.name), is_dir: se.is_dir, size_bytes: se.size_bytes });
                    }
                }
                Err(_) => {}
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
    println!("  btc <t> <id> [args]                 Binary tool call (byte ID)");
    println!("  tools-list                          List all binary tool IDs");
    println!("  help                                Show this help");
    println!("  quit                                Leave the swarm");
}
