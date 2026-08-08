use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::FramedRead;

use crate::crypto::Crypto;
use crate::packet::{self, Packet, ResponsePacket};
use crate::protocol::FrameCodec;
use crate::swarm::{ConnectionHandle, SwarmState};

pub struct Server {
    state: Arc<Mutex<SwarmState>>,
    crypto: Arc<Crypto>,
    bind_addr: SocketAddr,
}

impl Server {
    pub fn new(state: Arc<Mutex<SwarmState>>, crypto: Arc<Crypto>, bind_addr: SocketAddr) -> Self {
        Self {
            state,
            crypto,
            bind_addr,
        }
    }

    /// Run the server — accept connections and handle them concurrently.
    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        println!("[SERVER] Listening on {} (swarm port)", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            println!("[SERVER] New connection from {}", addr);
            let state = self.state.clone();
            let crypto = self.crypto.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, state, crypto, addr).await {
                    eprintln!("[SERVER] Client {} error: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    stream: TcpStream,
    state: Arc<Mutex<SwarmState>>,
    crypto: Arc<Crypto>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));

    // Create a channel for forwarding packets TO this client
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let mut framed = FramedRead::new(reader, FrameCodec);
    let mut username: Option<String> = None;
    let mut error_count: u32 = 0;
    let mut authenticated = false;

    // Subscribe to broadcast notifications
    let mut notify_rx = {
        let state = state.lock().await;
        state.subscribe_notifications()
    };

    // ── Forwarding task: reads from rx and writes encrypted frames to TCP ──
    let forward_writer = writer.clone();
    let forward_handle = tokio::spawn(async move {
        while let Some(encrypted) = rx.recv().await {
            let mut w = forward_writer.lock().await;
            if send_frame(&mut *w, &encrypted).await.is_err() {
                break;
            }
        }
    });

    // ── Notification task: pushes swarm broadcasts to this client ──
    let notify_writer = writer.clone();
    let notify_crypto = crypto.clone();
    let notify_handle = tokio::spawn(async move {
        while let Ok(notification) = notify_rx.recv().await {
            let packet = Packet::Notify(notification);
            let payload = packet.encode();
            if let Ok(encrypted) = notify_crypto.encrypt(&payload) {
                let mut w = notify_writer.lock().await;
                let _ = send_frame(&mut *w, &encrypted).await;
            }
        }
    });

    // ── Main read loop (60s heartbeat timeout) ──
    const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    loop {
        let frame_result = tokio::time::timeout(READ_TIMEOUT, framed.next()).await;
        let frame_result = match frame_result {
            Ok(Some(f)) => f,
            Ok(None) => break, // stream ended
            Err(_elapsed) => {
                // Read timeout — client is dead
                if let Some(ref uname) = username {
                    eprintln!("[SERVER] Heartbeat timeout — removing agent '{}'", uname);
                }
                break;
            }
        };
        let encrypted_frame = match frame_result {
            Ok(f) => f,
            Err(e) => {
                if authenticated {
                    eprintln!("[SERVER] Frame error from {}: {}", username.as_deref().unwrap_or("?"), e);
                } else {
                    error_count += 1;
                }
                break;
            }
        };

        let decrypted = match crypto.decrypt(&encrypted_frame) {
            Ok(d) => {
                authenticated = true;
                d
            }
            Err(_) => {
                error_count += 1;
                continue;
            }
        };

        // ── Try Packet (binary format) ──
        let packet: Packet = match Packet::decode(&decrypted) {
            Ok(p) => p,
            Err(e) => {
                // Also try ResponsePacket (P2P replies, still JSON for now)
                if let Ok(response) = ResponsePacket::decode(&decrypted) {
                    let requester = get_requester_from_response(&response);
                    println!("[SERVER] Response from {:?} → forwarding to '{}'", username, requester);
                    let state = state.lock().await;
                    if let Ok(encrypted) = crypto.encrypt(&decrypted) {
                        if !state.send_to_agent(&requester, encrypted) {
                            eprintln!("[SERVER] Cannot forward response: requester '{}' not found", requester);
                        }
                    }
                    continue;
                }
                eprintln!("[SERVER] Decode error: {}", e);
                continue;
            }
        };

        println!("[SERVER] Received: {} from {:?}", packet.describe(), username);

        let is_leave = matches!(packet, Packet::Leave(_));

        process_packet(&state, &crypto, &packet, &mut username, &tx).await;

        if is_leave {
            break;
        }
    }

    // Log if this was a noisy unauthenticated connection
    if !authenticated && error_count > 0 {
        eprintln!(
            "[SERVER] Rejected {} bad frames from {} (wrong key or non-swarm traffic)",
            error_count, addr
        );
    }

    // Cleanup
    if let Some(uname) = username.as_ref() {
        let mut state = state.lock().await;
        state.remove_agent(uname, Some("Connection closed".into()));
    }

    forward_handle.abort();
    notify_handle.abort();
    Ok(())
}

/// Process an incoming packet.
async fn process_packet(
    state: &Arc<Mutex<SwarmState>>,
    crypto: &Crypto,
    packet: &Packet,
    username: &mut Option<String>,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    match packet {
        Packet::Join(payload) => {
            let agent = crate::agent::Agent::new(
                payload.username.clone(),
                payload.role.clone(),
                payload.capabilities.clone(),
                payload.workspace_mode.clone(),
                payload.project_root.clone(),
                payload.is_orchestrator,
            );
            *username = Some(payload.username.clone());
            let conn = ConnectionHandle { tx: tx.clone() };
            let mut state = state.lock().await;
            state.add_agent(agent, conn);
            println!(
                "[SERVER] Agent '{}' joined (role: {:?}, workspace: {:?})",
                payload.username, payload.role, payload.workspace_mode
            );
        }

        Packet::Leave(_) => {}

        Packet::Notify(_) => {}

        Packet::CreateTask(payload) => {
            let created_by = username.clone().unwrap_or_else(|| "unknown".into());
            let mut state = state.lock().await;
            let task = state.create_task(
                payload.title.clone(),
                payload.description.clone(),
                payload.priority.clone(),
                payload.assigned_role.clone(),
                payload.assign_to.clone(),
                created_by,
            );
            println!("[SERVER] Task '{}' created (id: {})", task.title, task.id);
        }

        Packet::TakeTask(payload) => {
            let mut state = state.lock().await;
            // If an orchestrator is present, agents cannot take tasks — they must be assigned
            if state.has_orchestrator() {
                // Check if this agent is the orchestrator (orchestrator can still self-assign)
                let is_orch = state
                    .agents
                    .get(&payload.username)
                    .map(|a| a.is_orchestrator)
                    .unwrap_or(false);
                if !is_orch {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.username.clone(),
                            message: "An orchestrator is present — you cannot take tasks. Wait for the orchestrator to assign tasks to you.".into(),
                        },
                    );
                    return;
                }
            }
            let (taken, not_found) = state.take_task(&payload.username, &payload.task_ids);
            println!(
                "[SERVER] Agent '{}' took {} tasks",
                payload.username,
                taken.len()
            );
            if !not_found.is_empty() {
                send_response_to(
                    crypto,
                    tx,
                    &ResponsePacket::Error {
                        requester: payload.username.clone(),
                        message: format!("Tasks not found: {:?}", not_found),
                    },
                );
            }
        }

        Packet::AssignTask(payload) => {
            let mut state = state.lock().await;
            match state.assign_task(&payload.assigned_by, payload.task_id, &payload.assign_to)
            {
                Ok(title) => {
                    println!(
                        "[SERVER] Orchestrator '{}' assigned task '{}' to '{}'",
                        payload.assigned_by, title, payload.assign_to
                    );
                }
                Err(e) => {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.assigned_by.clone(),
                            message: e,
                        },
                    );
                }
            }
        }

        Packet::Status(payload) => {
            let mut state = state.lock().await;
            state.update_status(
                &payload.username,
                payload.status.clone(),
                payload.task_id,
                payload.progress_pct,
                payload.message.clone(),
            );
        }

        Packet::Message(payload) => {
            let mut state = state.lock().await;
            state.route_message(&payload.from, &payload.to, &payload.body, payload.timestamp);
        }

        Packet::CreateChannel(payload) => {
            let vis = match payload.visibility.as_deref() {
                Some("private") => crate::channel::ChannelVisibility::Private,
                _ => crate::channel::ChannelVisibility::Public,
            };
            let mut state = state.lock().await;
            if state
                .create_channel(
                    payload.name.clone(),
                    payload.created_by.clone(),
                    payload.description.clone(),
                    vis,
                )
                .is_none()
            {
                send_response_to(
                    crypto,
                    tx,
                    &ResponsePacket::Error {
                        requester: payload.created_by.clone(),
                        message: format!("Channel '{}' already exists", payload.name),
                    },
                );
            }
        }

        Packet::ListChannels(payload) => {
            let state = state.lock().await;
            let channels = state.list_visible_channels(&payload.requester);
            send_response_to(
                crypto,
                tx,
                &ResponsePacket::ChannelListResult {
                    requester: payload.requester.clone(),
                    channels,
                },
            );
        }

        Packet::JoinChannel(payload) => {
            let mut state = state.lock().await;
            match state.join_channel(&payload.channel_name, &payload.username) {
                Ok(()) => {}
                Err(e) => {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.username.clone(),
                            message: e,
                        },
                    );
                }
            }
        }

        Packet::LeaveChannel(payload) => {
            let mut state = state.lock().await;
            match state.leave_channel(&payload.channel_name, &payload.username) {
                Ok(()) => {}
                Err(e) => {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.username.clone(),
                            message: e,
                        },
                    );
                }
            }
        }

        Packet::DeleteChannel(payload) => {
            let mut state = state.lock().await;
            match state.delete_channel(&payload.channel_name, &payload.requested_by) {
                Ok(()) => {}
                Err(e) => {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.requested_by.clone(),
                            message: e,
                        },
                    );
                }
            }
        }

        Packet::HideChannel(payload) => {
            let mut state = state.lock().await;
            match state.hide_channel(&payload.channel_name, &payload.username) {
                Ok(()) => {}
                Err(e) => {
                    send_response_to(
                        crypto,
                        tx,
                        &ResponsePacket::Error {
                            requester: payload.username.clone(),
                            message: e,
                        },
                    );
                }
            }
        }

        Packet::TaskComplete(payload) => {
            let mut state = state.lock().await;
            let ok = state.complete_task(
                &payload.username,
                payload.task_id,
                payload.result.clone(),
                payload.artifacts.clone(),
            );
            if !ok {
                send_response_to(
                    crypto,
                    tx,
                    &ResponsePacket::Error {
                        requester: payload.username.clone(),
                        message: format!("Task {} not found", payload.task_id),
                    },
                );
            }
        }

        // ── P2P-routed packets ──

        Packet::ListDrives(payload) => {
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &payload.requester,
                || ResponsePacket::ListDrivesResult {
                    requester: payload.requester.clone(),
                    drives: list_local_drives(),
                },
            )
            .await;
        }

        Packet::ListDir(payload) => {
            let path = payload.path.clone();
            let recursive = payload.recursive;
            let requester = payload.requester.clone();
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || match list_local_dir(&path, recursive) {
                    Ok(entries) => ResponsePacket::ListDirResult {
                        requester: requester.clone(),
                        path: path.clone(),
                        entries,
                    },
                    Err(e) => ResponsePacket::Error {
                        requester: requester.clone(),
                        message: format!("Failed to list directory: {}", e),
                    },
                },
            )
            .await;
        }

        Packet::HttpRequest(payload) => {
            let requester = payload.requester.clone();
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || ResponsePacket::HttpRequestResult {
                    requester: requester.clone(),
                    status_code: 501,
                    headers: vec![],
                    body: "HTTP forwarding on server not implemented".into(),
                },
            )
            .await;
        }

        Packet::ToolCall(payload) => {
            let tool_name = payload.tool_name.clone();
            let requester = payload.requester.clone();
            let arguments = payload.arguments.clone();
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || {
                    let (success, output) = crate::tools::execute_tool(&tool_name, &arguments);
                    println!("[SERVER] Local tool '{}' → {}: {}", tool_name, if success { "OK" } else { "FAIL" }, output.chars().take(80).collect::<String>());
                    ResponsePacket::ToolCallResult {
                        requester: requester.clone(),
                        tool_name: tool_name.clone(),
                        success,
                        output,
                    }
                },
            )
            .await;
        }

        // ── Swarm File Transfer (handled locally on server too) ──

        Packet::SendFile(payload) => {
            let requester = payload.requester.clone();
            let path = payload.path.clone();
            let content = payload.content.clone();
            let overwrite = payload.overwrite;
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || {
                    match write_file_local(&path, &content, overwrite) {
                        Ok(bytes) => ResponsePacket::SendFileResult {
                            requester: requester.clone(),
                            path: path.clone(),
                            bytes_written: bytes,
                        },
                        Err(e) => ResponsePacket::Error {
                            requester: requester.clone(),
                            message: e,
                        },
                    }
                },
            )
            .await;
        }

        Packet::ReceiveFile(payload) => {
            let requester = payload.requester.clone();
            let path = payload.path.clone();
            let max_bytes = payload.max_bytes.unwrap_or(10_000_000);
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || {
                    match read_file_local(&path, max_bytes) {
                        Ok((content, size)) => ResponsePacket::ReceiveFileResult {
                            requester: requester.clone(),
                            path: path.clone(),
                            content,
                            size_bytes: size,
                        },
                        Err(e) => ResponsePacket::Error {
                            requester: requester.clone(),
                            message: e,
                        },
                    }
                },
            )
            .await;
        }

        Packet::DeleteFile(payload) => {
            let requester = payload.requester.clone();
            let path = payload.path.clone();
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || {
                    let deleted = std::fs::remove_file(&path).is_ok();
                    ResponsePacket::DeleteFileResult {
                        requester: requester.clone(),
                        path: path.clone(),
                        deleted,
                    }
                },
            )
            .await;
        }

        Packet::MakeDir(payload) => {
            let requester = payload.requester.clone();
            let path = payload.path.clone();
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || {
                    let created = std::fs::create_dir_all(&path).is_ok();
                    ResponsePacket::MakeDirResult {
                        requester: requester.clone(),
                        path: path.clone(),
                        created,
                    }
                },
            )
            .await;
        }

        Packet::ListUsers(payload) => {
            let state = state.lock().await;
            let agents: Vec<packet::UserInfo> = state
                .list_agents()
                .iter()
                .map(|a| packet::UserInfo {
                    username: a.username.clone(),
                    role: a.role.clone(),
                    is_orchestrator: a.is_orchestrator,
                })
                .collect();
            send_response_to(
                crypto,
                tx,
                &ResponsePacket::UserListResult {
                    requester: payload.requester.clone(),
                    agents,
                },
            );
        }
    }
}

/// Try forwarding to target; fall back to local handling if target is unreachable
/// (e.g., target is the server itself or disconnected).
async fn forward_or_handle_locally(
    state: &Arc<Mutex<SwarmState>>,
    crypto: &Crypto,
    packet: &Packet,
    target: &str,
    requester: &str,
    local_handler: impl FnOnce() -> ResponsePacket,
) {
    let state = state.lock().await;
    let payload = packet.encode();
    let encrypted = match crypto.encrypt(&payload) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[SERVER] Encrypt error forwarding to {}: {}", target, e);
            return;
        }
    };

    if state.send_to_agent(target, encrypted) {
        println!("[SERVER] Forwarded {} to '{}'", packet.describe(), target);
    } else {
        println!("[SERVER] Target '{}' unreachable, handling {} locally", target, packet.describe());
        let response = local_handler();
        let payload = response.encode();
        if let Ok(encrypted) = crypto.encrypt(&payload) {
            let _ = state.send_to_agent(requester, encrypted);
        }
    }
}

fn get_requester_from_response(resp: &ResponsePacket) -> String {
    match resp {
        ResponsePacket::ListDrivesResult { requester, .. }
        | ResponsePacket::ListDirResult { requester, .. }
        | ResponsePacket::HttpRequestResult { requester, .. }
        | ResponsePacket::ToolCallResult { requester, .. }
        | ResponsePacket::ChannelListResult { requester, .. }
        | ResponsePacket::SendFileResult { requester, .. }
        | ResponsePacket::ReceiveFileResult { requester, .. }
        | ResponsePacket::DeleteFileResult { requester, .. }
        | ResponsePacket::MakeDirResult { requester, .. }
        | ResponsePacket::Error { requester, .. } => requester.clone(),
        ResponsePacket::UserListResult { requester, .. } => requester.clone(),
    }
}

fn send_response_to(crypto: &Crypto, tx: &mpsc::UnboundedSender<Vec<u8>>, resp: &ResponsePacket) {
    let payload = resp.encode();
    if let Ok(encrypted) = crypto.encrypt(&payload) {
        let _ = tx.send(encrypted);
    }
}

async fn send_frame(writer: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

// ── Local system helpers (used when server handles P2P requests locally) ──

fn write_file_local(path: &str, data: &[u8], overwrite: bool) -> Result<u64, String> {
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

fn read_file_local(path: &str, max_bytes: u64) -> Result<(Vec<u8>, u64), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Read failed: {}", e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("File too large: {} bytes (max: {})", bytes.len(), max_bytes));
    }
    let size = bytes.len() as u64;
    Ok((bytes, size))
}

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
                Err(_) => {}
            }
        }
    }
    Ok(result)
}
