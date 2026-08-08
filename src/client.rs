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
    is_orchestrator: bool,
) -> anyhow::Result<()> {
    if pipe_mode {
        run_pipe_mode(server_addr, crypto, username, role, capabilities, workspace_mode, project_root, is_orchestrator).await
    } else {
        run_interactive(server_addr, crypto, username, role, capabilities, workspace_mode, project_root, is_orchestrator).await
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
    is_orchestrator: bool,
) -> anyhow::Result<()> {
    println!(
        "[CLIENT] Connecting to swarm at {} as '{}' (role: {:?}, workspace: {}, orchestrator: {})",
        server_addr, username, role, workspace_mode, is_orchestrator
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
        is_orchestrator,
    });
    send_packet(&writer, &crypto, &join_packet).await?;

    let writer_p2p = writer.clone();
    let writer_clone = writer.clone();
    let crypto_read = crypto.clone();
    let crypto_cmd = crypto.clone();
    let username_clone = username.clone();
    let username_read = username.clone();

    // Heartbeat task
    let heartbeat_writer = writer.clone();
    let heartbeat_crypto = crypto.clone();
    let heartbeat_username = username.clone();
    let heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let ping = Packet::Status(packet::StatusPayload {
                username: heartbeat_username.clone(),
                status: packet::AgentStatus::Idle,
                task_id: None, progress_pct: None,
                message: Some("heartbeat".into()),
            });
            if send_packet(&heartbeat_writer, &heartbeat_crypto, &ping).await.is_err() { break; }
        }
    });

    let read_handle = tokio::spawn(async move {
        while let Some(frame_result) = framed.next().await {
            let encrypted = match frame_result {
                Ok(f) => f,
                Err(e) => { eprintln!("[CLIENT] Frame error: {}", e); break; }
            };
            let decrypted = match crypto_read.decrypt(&encrypted) {
                Ok(d) => d,
                Err(e) => { eprintln!("[CLIENT] Decrypt error: {}", e); continue; }
            };
            // Try binary Packet first
            if let Ok(packet) = Packet::decode(&decrypted) {
                if let Some(response) = handle_p2p_request(&packet, &username_read) {
                    let payload = response.encode();
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
            // Then try JSON ResponsePacket (P2P replies)
            if let Ok(response) = ResponsePacket::decode(&decrypted) {
                handle_response(&response); continue;
            }
            eprintln!("[CLIENT] Received unknown data: {}", String::from_utf8_lossy(&decrypted));
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
        if n == 0 { break; }
        let line = buf.trim();
        if line.is_empty() { continue; }

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

    let leave_packet = Packet::Leave(packet::LeavePayload { username: username.clone(), reason: Some("User exited".into()) });
    send_packet(&writer, &crypto, &leave_packet).await?;
    heartbeat_handle.abort();
    read_handle.abort();
    println!("[CLIENT] Disconnected from swarm.");
    Ok(())
}

// ── Pipe mode ──

async fn run_pipe_mode(
    server_addr: SocketAddr,
    crypto: Arc<Crypto>,
    username: String,
    role: Option<String>,
    capabilities: Vec<String>,
    workspace_mode: String,
    project_root: Option<String>,
    is_orchestrator: bool,
) -> anyhow::Result<()> {
    eprintln!("[PIPE] Connecting to {} as '{}'", server_addr, username);
    let stream = TcpStream::connect(server_addr).await?;
    eprintln!("[PIPE] Connected");
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let mut framed = FramedRead::new(reader, FrameCodec);

    let join_packet = Packet::Join(packet::JoinPayload {
        username: username.clone(), role: role.clone(), capabilities,
        workspace_mode: Some(workspace_mode), project_root, is_orchestrator,
    });
    send_packet(&writer, &crypto, &join_packet).await?;

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let writer_p2p = writer.clone();
    let crypto_read = crypto.clone();
    let username_read = username.clone();

    let heartbeat_writer = writer.clone();
    let heartbeat_crypto = crypto.clone();
    let heartbeat_username = username.clone();
    let _heartbeat_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let ping = Packet::Status(packet::StatusPayload { username: heartbeat_username.clone(), status: packet::AgentStatus::Idle, task_id: None, progress_pct: None, message: Some("heartbeat".into()) });
            if send_packet(&heartbeat_writer, &heartbeat_crypto, &ping).await.is_err() { break; }
        }
    });

    let _read_handle = tokio::spawn(async move {
        while let Some(frame_result) = framed.next().await {
            let encrypted = match frame_result { Ok(f) => f, Err(_) => break };
            let decrypted = match crypto_read.decrypt(&encrypted) { Ok(d) => d, Err(_) => continue };
            // Try binary Packet first
            if let Ok(packet) = Packet::decode(&decrypted) {
                if let Some(response) = handle_p2p_request(&packet, &username_read) {
                    let payload = response.encode();
                    if let Ok(encrypted) = crypto_read.encrypt(&payload) {
                        let mut w = writer_p2p.lock().await;
                        let len = encrypted.len() as u32;
                        let _ = w.write_all(&len.to_be_bytes()).await;
                        let _ = w.write_all(&encrypted).await;
                        let _ = w.flush().await;
                    }
                    continue;
                }
                let _ = event_tx.send(json!({"type":"event","packet_type":packet.describe()}));
                continue;
            }
            if let Ok(response) = ResponsePacket::decode(&decrypted) {
                let json = serde_json::to_value(&response).unwrap();
                let _ = event_tx.send(json!({"type":"response","data":json}));
                continue;
            }

        }
    });

    let ready = json!({"type":"ready","username":username,"orchestrator":is_orchestrator});
    println!("{}", serde_json::to_string(&ready).unwrap());

    let stdin = tokio::io::stdin();
    let mut buf = String::new();
    let mut stdin_reader = tokio::io::BufReader::new(stdin);

    loop {
        while let Ok(event) = event_rx.try_recv() {
            println!("{}", serde_json::to_string(&event).unwrap());
        }
        buf.clear();
        let n = match stdin_reader.read_line(&mut buf).await { Ok(n) => n, Err(_) => break };
        if n == 0 { break; }
        let line = buf.trim();
        if line.is_empty() { continue; }

        let cmd: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => { println!("{}", serde_json::to_string(&json!({"type":"error","message":format!("Invalid JSON: {}", e)})).unwrap()); continue; }
        };
        let cmd_type = cmd["cmd"].as_str().unwrap_or("");
        match cmd_type {
            "quit" | "exit" => break,
            _ => match json_command_to_packet(&cmd, &username) {
                Ok(Some(packet)) => send_packet(&writer, &crypto, &packet).await?,
                Ok(None) => {},
                Err(e) => println!("{}", serde_json::to_string(&json!({"type":"error","message":e})).unwrap()),
            }
        }
    }

    while let Ok(event) = event_rx.try_recv() {
        println!("{}", serde_json::to_string(&event).unwrap());
    }
    let leave_packet = Packet::Leave(packet::LeavePayload { username: username.clone(), reason: Some("Pipe closed".into()) });
    send_packet(&writer, &crypto, &leave_packet).await?;
    eprintln!("[PIPE] Disconnected");
    Ok(())
}

/// Convert a JSON pipe command into a Packet.
fn json_command_to_packet(cmd: &Value, username: &str) -> Result<Option<Packet>, String> {
    let cmd_type = cmd["cmd"].as_str().unwrap_or("");
    match cmd_type {
        "msg" | "message" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let body = cmd["body"].as_str().unwrap_or("");
            let to = if let Some(channel) = target.strip_prefix('#') { packet::MessageTarget::Channel { channel: channel.to_string() } } else { packet::MessageTarget::Direct { username: target.to_string() } };
            Ok(Some(Packet::Message(packet::MessagePayload { from: username.to_string(), to, body: body.to_string() })))
        }
        "task" => {
            let title = cmd["title"].as_str().ok_or("'title' required")?;
            let description = cmd["description"].as_str().unwrap_or("").to_string();
            let priority = match cmd["priority"].as_str().unwrap_or("normal") { "low" => packet::TaskPriority::Low, "high" => packet::TaskPriority::High, "critical" => packet::TaskPriority::Critical, _ => packet::TaskPriority::Normal };
            let assigned_role = cmd["role"].as_str().map(|s| s.to_string());
            Ok(Some(Packet::CreateTask(packet::CreateTaskPayload { title: title.to_string(), description, priority, assigned_role, assign_to: None })))
        }
        "take" => {
            let task_id = cmd["task_id"].as_str().ok_or("'task_id' required")?;
            let id = uuid::Uuid::parse_str(task_id).map_err(|e| e.to_string())?;
            Ok(Some(Packet::TakeTask(packet::TakeTaskPayload { task_ids: vec![id], username: username.to_string() })))
        }
        "assign" => {
            let task_id = cmd["task_id"].as_str().ok_or("'task_id' required")?;
            let assign_to = cmd["assign_to"].as_str().ok_or("'assign_to' required")?;
            let id = uuid::Uuid::parse_str(task_id).map_err(|e| e.to_string())?;
            Ok(Some(Packet::AssignTask(packet::AssignTaskPayload { assigned_by: username.to_string(), task_id: id, assign_to: assign_to.to_string() })))
        }
        "done" => {
            let task_id = cmd["task_id"].as_str().ok_or("'task_id' required")?;
            let id = uuid::Uuid::parse_str(task_id).map_err(|e| e.to_string())?;
            Ok(Some(Packet::TaskComplete(packet::TaskCompletePayload { task_id: id, username: username.to_string(), result: cmd["result"].as_str().map(|s| s.to_string()), artifacts: vec![] })))
        }
        "status" => {
            let msg = cmd["message"].as_str().unwrap_or("").to_string();
            Ok(Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Working, task_id: None, progress_pct: None, message: Some(msg) })))
        }
        "channel" => {
            let name = cmd["name"].as_str().ok_or("'name' required")?;
            let description = cmd["description"].as_str().map(|s| s.to_string());
            let is_private = cmd["private"].as_bool().unwrap_or(false);
            Ok(Some(Packet::CreateChannel(packet::CreateChannelPayload { name: name.to_string(), created_by: username.to_string(), description, visibility: Some(if is_private { "private".into() } else { "public".into() }) })))
        }
        "channels" => Ok(Some(Packet::ListChannels(packet::ListChannelsPayload { requester: username.to_string() }))),
        "join" => { let name = cmd["name"].as_str().ok_or("'name' required")?; Ok(Some(Packet::JoinChannel(packet::JoinChannelPayload { channel_name: name.to_string(), username: username.to_string() }))) }
        "leave" => { let name = cmd["name"].as_str().ok_or("'name' required")?; Ok(Some(Packet::LeaveChannel(packet::LeaveChannelPayload { channel_name: name.to_string(), username: username.to_string() }))) }
        "delete-channel" => { let name = cmd["name"].as_str().ok_or("'name' required")?; Ok(Some(Packet::DeleteChannel(packet::DeleteChannelPayload { channel_name: name.to_string(), requested_by: username.to_string() }))) }
        "hide" => { let name = cmd["name"].as_str().ok_or("'name' required")?; Ok(Some(Packet::HideChannel(packet::HideChannelPayload { channel_name: name.to_string(), username: username.to_string() }))) }
        "drives" => { let target = cmd["target"].as_str().ok_or("'target' required")?; Ok(Some(Packet::ListDrives(packet::ListDrivesPayload { requester: username.to_string(), target: target.to_string() }))) }
        "ls" | "dir" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let path = cmd["path"].as_str().unwrap_or(".");
            Ok(Some(Packet::ListDir(packet::ListDirPayload { requester: username.to_string(), target: target.to_string(), path: path.to_string(), recursive: false })))
        }
        "http" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let method_str = cmd["method"].as_str().unwrap_or("GET");
            let url = cmd["url"].as_str().ok_or("'url' required")?;
            let method = match method_str.to_uppercase().as_str() { "GET" => packet::HttpMethod::GET, "POST" => packet::HttpMethod::POST, "PUT" => packet::HttpMethod::PUT, "DELETE" => packet::HttpMethod::DELETE, _ => return Err(format!("Unknown method: {}", method_str)) };
            Ok(Some(Packet::HttpRequest(packet::HttpRequestPayload { requester: username.to_string(), target: target.to_string(), method, url: url.to_string(), headers: vec![], body: cmd["body"].as_str().map(|s| s.to_string()), query_params: vec![] })))
        }
        "tool" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let tool_name = cmd["tool_name"].as_str().ok_or("'tool_name' required")?;
            let arguments = cmd.get("args").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
            Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: tool_name.to_string(), arguments })))
        }
        "btc" | "binary-tool" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let tool_id: u8 = if let Some(v) = cmd["tool_id"].as_u64() { v as u8 } else if let Some(s) = cmd["tool_id"].as_str() { if let Some(hex) = s.strip_prefix("0x") { u8::from_str_radix(hex, 16).map_err(|e| e.to_string())? } else { s.parse().map_err(|e| format!("Invalid tool_id: {}", e))? } } else { return Err("'tool_id' required (e.g. 1 or 0x80)".into()); };
            let args = cmd.get("args").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
            let tool_name = binary_tool::tool_id_to_name(tool_id);
            Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: tool_name.to_string(), arguments: args })))
        }
        "cp" | "copy" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let src = cmd["src"].as_str().ok_or("'src' required")?; let dst = cmd["dst"].as_str().ok_or("'dst' required")?; Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "copy_file".into(), arguments: json!({"src":src,"dst":dst}) }))) }
        "mv" | "move" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let src = cmd["src"].as_str().ok_or("'src' required")?; let dst = cmd["dst"].as_str().ok_or("'dst' required")?; Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "move_file".into(), arguments: json!({"src":src,"dst":dst}) }))) }
        "size" | "file-size" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let path = cmd["path"].as_str().ok_or("'path' required")?; Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "file_size".into(), arguments: json!({"path":path}) }))) }
        "env" | "env-var" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let mut args = json!({}); if let Some(n) = cmd["name"].as_str() { args["name"] = json!(n); } Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "env_var".into(), arguments: args }))) }
        "sleep" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let ms = cmd["ms"].as_u64().unwrap_or(1000); Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "sleep".into(), arguments: json!({"ms":ms}) }))) }
        "whoami" => { let target = cmd["target"].as_str().ok_or("'target' required")?; Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "whoami".into(), arguments: serde_json::Value::Object(Default::default()) }))) }
        "todos" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let path = cmd["path"].as_str().unwrap_or("TODO.md"); let title = cmd["title"].as_str().unwrap_or("# TODO"); let todos = cmd.get("todos").cloned().unwrap_or(json!([])); Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "write_todos".into(), arguments: json!({"path":path,"title":title,"todos":todos}) }))) }
        "mkdir" | "make-dir" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let path = cmd["path"].as_str().ok_or("'path' required")?; Ok(Some(Packet::MakeDir(packet::MakeDirPayload { requester: username.to_string(), target: target.to_string(), path: path.to_string() }))) }
        "http-get" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let url = cmd["url"].as_str().ok_or("'url' required")?; let mut args = json!({"url":url}); if let Some(t) = cmd["timeout"].as_u64() { args["timeout"] = json!(t); } Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "http_get".into(), arguments: args }))) }
        "list-drives" => { let target = cmd["target"].as_str().ok_or("'target' required")?; Ok(Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "list_drives".into(), arguments: serde_json::Value::Object(Default::default()) }))) }
        "rm" | "delete-file" => { let target = cmd["target"].as_str().ok_or("'target' required")?; let path = cmd["path"].as_str().ok_or("'path' required")?; Ok(Some(Packet::DeleteFile(packet::DeleteFilePayload { requester: username.to_string(), target: target.to_string(), path: path.to_string() }))) }
        // ── Swarm file transfer packet commands ──
        "send" | "upload" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let local_path = cmd["local"].as_str().ok_or("'local' path required")?;
            let remote_path = cmd["remote"].as_str().ok_or("'remote' path required")?;
            let overwrite = cmd["overwrite"].as_bool().unwrap_or(false);
            let content = std::fs::read(local_path).map_err(|e| format!("Can't read local file: {}", e))?;
            Ok(Some(Packet::SendFile(packet::SendFilePayload { requester: username.to_string(), target: target.to_string(), path: remote_path.to_string(), content, overwrite })))
        }
        "recv" | "download" => {
            let target = cmd["target"].as_str().ok_or("'target' required")?;
            let path = cmd["path"].as_str().ok_or("'path' required")?;
            let max_bytes = cmd["max_bytes"].as_u64();
            Ok(Some(Packet::ReceiveFile(packet::ReceiveFilePayload { requester: username.to_string(), target: target.to_string(), path: path.to_string(), max_bytes })))
        }

        "tools-list" | "tools_list" => { let tools: Vec<Value> = binary_tool::list_tools().iter().map(|(id, name, desc)| json!({"id":format!("0x{:02X}", id),"name":name,"description":desc})).collect(); println!("{}", serde_json::to_string(&json!({"type":"tool_list","tools":tools})).unwrap()); Ok(None) }
        _ => Ok(None),
    }
}

// ── Shared helpers ──

async fn send_packet(writer: &Mutex<impl AsyncWriteExt + Unpin>, crypto: &Crypto, packet: &Packet) -> anyhow::Result<()> {
    let payload = packet.encode();
    let encrypted = crypto.encrypt(&payload)?;
    let mut w = writer.lock().await;
    let len = encrypted.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&encrypted).await?;
    w.flush().await?;
    Ok(())
}

fn handle_p2p_request(packet: &Packet, our_username: &str) -> Option<ResponsePacket> {
    match packet {
        Packet::ListDrives(payload) => if payload.target == our_username {
            let drives = if cfg!(windows) { ('A'..='Z').map(|c| format!("{}:\\", c)).filter(|d| std::path::Path::new(d).exists()).collect() } else { vec!["/".to_string()] };
            Some(ResponsePacket::ListDrivesResult { requester: payload.requester.clone(), drives })
        } else { None },
        Packet::ListDir(payload) => if payload.target == our_username {
            match list_local_dir(&payload.path, payload.recursive) {
                Ok(entries) => Some(ResponsePacket::ListDirResult { requester: payload.requester.clone(), path: payload.path.clone(), entries }),
                Err(e) => Some(ResponsePacket::Error { requester: payload.requester.clone(), message: format!("Failed to list directory: {}", e) }),
            }
        } else { None },
        Packet::HttpRequest(payload) => if payload.target == our_username { Some(ResponsePacket::HttpRequestResult { requester: payload.requester.clone(), status_code: 501, headers: vec![], body: "HTTP forwarding not yet implemented".into() }) } else { None },
        Packet::ToolCall(payload) => if payload.target == our_username {
            let (success, output) = crate::tools::execute_tool(&payload.tool_name, &payload.arguments);
            eprintln!("[TOOL] {} from {} → {} ({})", payload.tool_name, payload.requester, if success { "OK" } else { "FAIL" }, output.chars().take(80).collect::<String>());
            Some(ResponsePacket::ToolCallResult { requester: payload.requester.clone(), tool_name: payload.tool_name.clone(), success, output })
        } else { None },
        // ── Swarm File Transfer ──
        Packet::SendFile(payload) => if payload.target == our_username {
            eprintln!("[SWARM] Receiving file '{}' from {} ({} bytes)", payload.path, payload.requester, payload.content.len());
            match write_file_raw(&payload.path, &payload.content, payload.overwrite) {
                Ok(bytes) => Some(ResponsePacket::SendFileResult { requester: payload.requester.clone(), path: payload.path.clone(), bytes_written: bytes }),
                Err(e) => Some(ResponsePacket::Error { requester: payload.requester.clone(), message: e }),
            }
        } else { None },
        Packet::ReceiveFile(payload) => if payload.target == our_username {
            eprintln!("[SWARM] Sending file '{}' to {}", payload.path, payload.requester);
            match read_file_raw(&payload.path, payload.max_bytes.unwrap_or(10_000_000)) {
                Ok((content, size)) => Some(ResponsePacket::ReceiveFileResult { requester: payload.requester.clone(), path: payload.path.clone(), content, size_bytes: size }),
                Err(e) => Some(ResponsePacket::Error { requester: payload.requester.clone(), message: e }),
            }
        } else { None },
        Packet::DeleteFile(payload) => if payload.target == our_username {
            let deleted = std::fs::remove_file(&payload.path).is_ok();
            Some(ResponsePacket::DeleteFileResult { requester: payload.requester.clone(), path: payload.path.clone(), deleted })
        } else { None },
        Packet::MakeDir(payload) => if payload.target == our_username {
            let created = std::fs::create_dir_all(&payload.path).is_ok();
            Some(ResponsePacket::MakeDirResult { requester: payload.requester.clone(), path: payload.path.clone(), created })
        } else { None },
        _ => None,
    }
}

fn handle_response(resp: &ResponsePacket) {
    match resp {
        ResponsePacket::ListDrivesResult { drives, .. } => println!("[DRIVES] {}", drives.join(", ")),
        ResponsePacket::ListDirResult { path, entries, .. } => { println!("[DIR] {}:", path); for entry in entries { let kind = if entry.is_dir { "[DIR]" } else { "[FILE]" }; println!("  {} {} ({} bytes)", kind, entry.name, entry.size_bytes); } }
        ResponsePacket::HttpRequestResult { status_code, body, .. } => { println!("[HTTP] Status: {}", status_code); let preview: String = body.chars().take(500).collect(); println!("[HTTP] Body: {}", preview); if body.len() > 500 { println!("... ({} more chars)", body.len() - 500); } }
        ResponsePacket::ToolCallResult { tool_name, success, output, .. } => println!("[TOOL:{}] {}: {}", tool_name, if *success { "OK" } else { "FAILED" }, output),
        ResponsePacket::ChannelListResult { channels, .. } => if channels.is_empty() { println!("[CHANNELS] No visible channels."); } else { println!("[CHANNELS]"); for ch in channels { println!("  #{} ({} members, {} by {})", ch.name, ch.member_count, ch.visibility, ch.created_by); if let Some(desc) = &ch.description { if !desc.is_empty() { println!("    {}", desc); } } } }
        ResponsePacket::Error { message, .. } => println!("[ERROR] {}", message),
        ResponsePacket::SendFileResult { path, bytes_written, .. } => println!("[SWARM] Sent '{}' — {} bytes written", path, bytes_written),
        ResponsePacket::ReceiveFileResult { path, content, size_bytes, .. } => {
            println!("[SWARM] Received '{}' — {} bytes", path, size_bytes);
            let local_name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
            match write_file_raw(&local_name, content, true) {
                Ok(written) => println!("[SWARM] Saved as './{}' ({} bytes)", local_name, written),
                Err(e) => eprintln!("[SWARM] Failed to save: {}", e),
            }
        }
        ResponsePacket::DeleteFileResult { path, deleted, .. } => println!("[SWARM] Delete '{}': {}", path, if *deleted { "OK" } else { "FAILED (not found?)" }),
        ResponsePacket::MakeDirResult { path, created, .. } => println!("[SWARM] Mkdir '{}': {}", path, if *created { "OK" } else { "FAILED" }),
    }
}

fn handle_incoming_packet(packet: &Packet, our_username: &str) {
    match packet {
        Packet::Notify(n) => match n {
            packet::NotifyPayload::AgentJoined { username, role, workspace_mode, project_root, is_orchestrator } => {
                let mode_str = workspace_mode.as_deref().unwrap_or("git");
                let root_str = project_root.as_ref().map(|r| format!(" root={}", r)).unwrap_or_default();
                let orch_str = if *is_orchestrator { " [ORCHESTRATOR]" } else { "" };
                println!("[SWARM] Agent '{}' joined (role: {:?}, workspace: {}{}){}", username, role, mode_str, root_str, orch_str);
            }
            packet::NotifyPayload::AgentLeft { username, reason } => println!("[SWARM] Agent '{}' left{}", username, reason.as_ref().map(|r| format!(" ({})", r)).unwrap_or_default()),
            packet::NotifyPayload::TaskCreated { task_id, title, assigned_role } => println!("[SWARM] Task created: '{}' (id: {}) role: {:?}", title, task_id, assigned_role),
            packet::NotifyPayload::TaskAssigned { task_id, username } => println!("[SWARM] Task {} assigned to '{}'", task_id, username),
            packet::NotifyPayload::TaskCompleted { task_id, username, .. } => println!("[SWARM] Task {} completed by '{}'", task_id, username),
            packet::NotifyPayload::ChannelCreated { name, created_by, visibility, .. } => println!("[SWARM] Channel '{}' created by '{}' ({})", name, created_by, visibility),
            packet::NotifyPayload::ChannelJoined { channel_name, username } => println!("[SWARM] '{}' joined channel '{}'", username, channel_name),
            packet::NotifyPayload::ChannelLeft { channel_name, username } => println!("[SWARM] '{}' left channel '{}'", username, channel_name),
            packet::NotifyPayload::ChannelDeleted { channel_name, deleted_by } => println!("[SWARM] Channel '{}' deleted by '{}'", channel_name, deleted_by),
            packet::NotifyPayload::StatusUpdate { username, status, task_id, progress_pct } => {
                let extra = if let (Some(tid), Some(pct)) = (task_id, progress_pct) { format!(" on task {} ({}%)", tid, pct) } else { String::new() };
                println!("[SWARM] Agent '{}' is {}{}", username, status, extra);
            }
            packet::NotifyPayload::MessageReceived { from, to, body } => if to == our_username { println!("[MSG from {}] {}", from, body); }
        },
        Packet::Message(msg) => println!("[MSG] {}: {}", msg.from, msg.body),
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
            let to = if let Some(channel) = target.strip_prefix('#') { packet::MessageTarget::Channel { channel: channel.to_string() } } else { packet::MessageTarget::Direct { username: target.to_string() } };
            Some(Packet::Message(packet::MessagePayload { from: username.to_string(), to, body: body.to_string() }))
        }
        "task" => {
            let mut role = None; let mut title = rest.to_string();
            if let Some(idx) = rest.rfind("role:") { role = Some(rest[idx + 5..].trim().to_string()); title = rest[..idx].trim().to_string(); }
            Some(Packet::CreateTask(packet::CreateTaskPayload { title, description: String::new(), priority: packet::TaskPriority::Normal, assigned_role: role, assign_to: None }))
        }
        "take" => { let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?; Some(Packet::TakeTask(packet::TakeTaskPayload { task_ids: vec![task_id], username: username.to_string() })) }
        "assign" => {
            let mut sub = rest.splitn(2, ' ');
            let task_id_str = sub.next()?;
            let assign_to = sub.next()?;
            let task_id = uuid::Uuid::parse_str(task_id_str).ok()?;
            Some(Packet::AssignTask(packet::AssignTaskPayload { assigned_by: username.to_string(), task_id, assign_to: assign_to.to_string() }))
        }
        "done" => { let task_id = uuid::Uuid::parse_str(rest.trim()).ok()?; Some(Packet::TaskComplete(packet::TaskCompletePayload { task_id, username: username.to_string(), result: None, artifacts: vec![] })) }
        "status" => Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Working, task_id: None, progress_pct: None, message: Some(rest.to_string()) })),
        "channel" => {
            let is_private = rest.contains("--private"); let clean = rest.replace("--private", "").trim().to_string();
            let mut sub = clean.splitn(2, ' '); let name = sub.next().unwrap_or("").trim().to_string();
            let desc = sub.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if name.is_empty() { return None; }
            Some(Packet::CreateChannel(packet::CreateChannelPayload { name, created_by: username.to_string(), description: desc, visibility: Some(if is_private { "private".into() } else { "public".into() }) }))
        }
        "channels" | "list-channels" => Some(Packet::ListChannels(packet::ListChannelsPayload { requester: username.to_string() })),
        "join" => { let name = rest.trim(); if name.is_empty() { return None; } Some(Packet::JoinChannel(packet::JoinChannelPayload { channel_name: name.to_string(), username: username.to_string() })) }
        "leave" => { let name = rest.trim(); if name.is_empty() { return None; } Some(Packet::LeaveChannel(packet::LeaveChannelPayload { channel_name: name.to_string(), username: username.to_string() })) }
        "delete-channel" => { let name = rest.trim(); if name.is_empty() { return None; } Some(Packet::DeleteChannel(packet::DeleteChannelPayload { channel_name: name.to_string(), requested_by: username.to_string() })) }
        "hide" => { let name = rest.trim(); if name.is_empty() { return None; } Some(Packet::HideChannel(packet::HideChannelPayload { channel_name: name.to_string(), username: username.to_string() })) }
        "drives" => { let target = rest.trim(); if target.is_empty() { return None; } Some(Packet::ListDrives(packet::ListDrivesPayload { requester: username.to_string(), target: target.to_string() })) }
        "ls" | "dir" => { let mut sub = rest.splitn(2, ':'); let target = sub.next()?; let path = sub.next().unwrap_or("."); Some(Packet::ListDir(packet::ListDirPayload { requester: username.to_string(), target: target.to_string(), path: path.to_string(), recursive: false })) }
        "http" => {
            let mut sub = rest.splitn(3, ' '); let target = sub.next()?; let method = sub.next().unwrap_or("GET"); let url = sub.next().unwrap_or("");
            let method = match method.to_uppercase().as_str() { "GET" => packet::HttpMethod::GET, "POST" => packet::HttpMethod::POST, "PUT" => packet::HttpMethod::PUT, "DELETE" => packet::HttpMethod::DELETE, _ => return None };
            Some(Packet::HttpRequest(packet::HttpRequestPayload { requester: username.to_string(), target: target.to_string(), method, url: url.to_string(), headers: vec![], body: None, query_params: vec![] }))
        }
        "tool" => {
            let mut sub = rest.splitn(3, ' '); let target = sub.next()?; let tool_name = sub.next()?; let args_str = sub.next().unwrap_or("{}");
            let arguments: serde_json::Value = serde_json::from_str(args_str).ok()?;
            Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: tool_name.to_string(), arguments }))
        }
        "btc" | "binary-tool" => {
            let mut sub = rest.splitn(3, ' '); let target = sub.next()?; let id_str = sub.next()?; let args_str = sub.next().unwrap_or("{}");
            let tool_id: u8 = if let Some(hex) = id_str.strip_prefix("0x") { u8::from_str_radix(hex, 16).ok()? } else { id_str.parse().ok()? };
            let tool_name = binary_tool::tool_id_to_name(tool_id);
            let arguments: serde_json::Value = serde_json::from_str(args_str).ok()?;
            Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: tool_name.to_string(), arguments }))
        }
        "cp" | "copy" => { let mut sub = rest.splitn(3, ' '); let target = sub.next()?; let src = sub.next()?; let dst = sub.next()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "copy_file".into(), arguments: json!({"src":src,"dst":dst}) })) }
        "mv" | "move" => { let mut sub = rest.splitn(3, ' '); let target = sub.next()?; let src = sub.next()?; let dst = sub.next()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "move_file".into(), arguments: json!({"src":src,"dst":dst}) })) }
        "size" => { let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let path = sub.next()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "file_size".into(), arguments: json!({"path":path}) })) }
        "env" => { let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let name = sub.next(); let mut args = json!({}); if let Some(n) = name { args["name"] = json!(n); } Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "env_var".into(), arguments: args })) }
        "sleep" => { let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let ms: u64 = sub.next()?.parse().ok()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "sleep".into(), arguments: json!({"ms":ms}) })) }
        "whoami" => { let target = rest.trim(); if target.is_empty() { return None; } Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "whoami".into(), arguments: serde_json::Value::Object(Default::default()) })) }
        "todos" => { let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let todo_args = sub.next().unwrap_or("[]"); let todos: Value = serde_json::from_str(todo_args).ok()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "write_todos".into(), arguments: json!({"path":"TODO.md","todos":todos}) })) }
        "http-get" => { let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let url = sub.next()?; Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "http_get".into(), arguments: json!({"url":url}) })) }
        "list-drives" => { let target = rest.trim(); if target.is_empty() { return None; } Some(Packet::ToolCall(packet::ToolCallPayload { requester: username.to_string(), target: target.to_string(), tool_name: "list_drives".into(), arguments: serde_json::Value::Object(Default::default()) })) }
        // ── Swarm file transfer packet commands ──
        "send" | "upload" => {
            let mut sub = rest.splitn(3, ' ');
            let target = match sub.next() { Some(t) => t, None => { println!("Usage: send <target> <local_path> <remote_path>"); return None; } };
            let local = match sub.next() { Some(p) => p, None => { println!("Missing local path"); return None; } };
            let remote = match sub.next() { Some(p) => p, None => { println!("Missing remote path"); return None; } };
            // Size limit: 10 MB
            const MAX_SEND: u64 = 10_000_000;
            match std::fs::metadata(local) {
                Ok(meta) if meta.len() > MAX_SEND => {
                    println!("[SWARM] File too large: {:.1} MB (max: {} MB)", meta.len() as f64 / 1_000_000.0, MAX_SEND / 1_000_000);
                    return Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Idle, task_id: None, progress_pct: None, message: None }));
                }
                Err(e) => { println!("[SWARM] Cannot read '{}': {}", local, e); return Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Idle, task_id: None, progress_pct: None, message: None })); }
                _ => {}
            }
            let content = match std::fs::read(local) { Ok(b) => b, Err(e) => { println!("[SWARM] Failed to read '{}': {}", local, e); return Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Idle, task_id: None, progress_pct: None, message: None })); } };
            println!("[SWARM] Sending '{}' ({} bytes) → {}:{}", local, content.len(), target, remote);
            Some(Packet::SendFile(packet::SendFilePayload { requester: username.to_string(), target: target.to_string(), path: remote.to_string(), content, overwrite: false }))
        }
        "recv" | "download" => {
            let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let path = sub.next()?;
            Some(Packet::ReceiveFile(packet::ReceiveFilePayload { requester: username.to_string(), target: target.to_string(), path: path.to_string(), max_bytes: None }))
        }
        "rm" | "delete-file" => {
            let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let path = sub.next()?;
            Some(Packet::DeleteFile(packet::DeleteFilePayload { requester: username.to_string(), target: target.to_string(), path: path.to_string() }))
        }
        "mkdir" | "make-dir" => {
            let mut sub = rest.splitn(2, ' '); let target = sub.next()?; let path = sub.next()?;
            Some(Packet::MakeDir(packet::MakeDirPayload { requester: username.to_string(), target: target.to_string(), path: path.to_string() }))
        }
        "tools-list" | "tools_list" => {
            println!("Binary Tool ID Registry:");
            println!("{:<6} {:<22} {}", "ID", "Name", "Description");
            for (id, name, desc) in binary_tool::list_tools() { println!("0x{:02X}   {:<22} {}", id, name, desc); }
            Some(Packet::Status(packet::StatusPayload { username: username.to_string(), status: packet::AgentStatus::Idle, task_id: None, progress_pct: None, message: None }))
        }
        _ => None,
    }
}

// ── Raw file helpers (no base64, binary packets carry raw bytes) ──

fn write_file_raw(path: &str, data: &[u8], overwrite: bool) -> Result<u64, String> {
    if !overwrite && std::path::Path::new(path).exists() {
        return Err(format!("File '{}' already exists. Use overwrite=true to replace.", path));
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::write(path, data).map_err(|e| format!("Write failed: {}", e))?;
    Ok(data.len() as u64)
}

fn read_file_raw(path: &str, max_bytes: u64) -> Result<(Vec<u8>, u64), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Read failed: {}", e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("File too large: {} bytes (max: {})", bytes.len(), max_bytes));
    }
    let size = bytes.len() as u64;
    Ok((bytes, size))
}

fn list_local_dir(path: &str, recursive: bool) -> anyhow::Result<Vec<packet::DirEntry>> {
    let mut result = Vec::new();
    let entries = std::fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?; let metadata = entry.metadata()?; let is_dir = metadata.is_dir(); let entry_path = entry.path();
        result.push(packet::DirEntry { name: entry.file_name().to_string_lossy().into(), is_dir, size_bytes: metadata.len() });
        if recursive && is_dir {
            let sub_path = entry_path.to_string_lossy().to_string();
            match list_local_dir(&sub_path, true) {
                Ok(sub_entries) => { for se in sub_entries { result.push(packet::DirEntry { name: format!("{}/{}", entry.file_name().to_string_lossy(), se.name), is_dir: se.is_dir, size_bytes: se.size_bytes }); } }
                Err(_) => {}
            }
        }
    }
    Ok(result)
}

fn print_help() {
    println!("Swarm Client Commands:");
    println!("  Swarm Channels (self-contained encrypted chat):");
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
    println!("  assign <task_id> <user>             Assign a task (orchestrator only)");
    println!("  done <task_id>                      Mark a task as complete");
    println!("  status <msg>                        Update your status");
    println!("  Remote ops:");
    println!("  drives <target>                     List drives on a remote agent");
    println!("  ls <target>:<path>                  List directory on a remote agent");
    println!("  http <t> <method> <url>             Send HTTP request via remote agent");
    println!("  tool <t> <name> [args]              Invoke a tool on a remote agent");
    println!("  btc <t> <id> [args]                 Binary tool call (byte ID)");
    println!("  Tools (invoke on remote agents):");
    println!("  cp <t> <src> <dst>                  Copy a file on a remote agent");
    println!("  mv <t> <src> <dst>                  Move/rename a file on a remote agent");
    println!("  size <t> <path>                     Get file size on a remote agent");
    println!("  env <t> [name]                      Get env var on a remote agent");
    println!("  sleep <t> <ms>                      Pause a remote agent for N ms");
    println!("  whoami <t>                          Get hostname/user of a remote agent");
    println!("  todos <t> [json_array]              Write TODO.md on a remote agent");
    println!("  http-get <t> <url>                  HTTP GET on a remote agent");
    println!("  list-drives <t>                     List drives on a remote agent");
    println!("  Swarm File Transfer (first-class encrypted packets, no external protocol):");
    println!("  send <t> <local> <remote>           Upload a file (max 10MB)");
    println!("  recv <t> <remote_path>              Download a file");
    println!("  rm <t> <path>                       Delete a file");
    println!("  mkdir <t> <path>                    Create directory");
    println!("  tools-list                          List all binary tool IDs");
    println!("  help                                Show this help");
    println!("  quit                                Leave the swarm");
}
