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
            if let Ok(payload) = serde_json::to_vec(&packet) {
                if let Ok(encrypted) = notify_crypto.encrypt(&payload) {
                    let mut w = notify_writer.lock().await;
                    let _ = send_frame(&mut *w, &encrypted).await;
                }
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

        // ── Try ResponsePacket first (P2P replies from target agents) ──
        if let Ok(response) = serde_json::from_slice::<ResponsePacket>(&decrypted) {
            let requester = get_requester_from_response(&response);
            println!(
                "[SERVER] Response from {:?} → forwarding to '{}'",
                username, requester
            );
            // Re-encrypt and forward to the requester
            let state = state.lock().await;
            if let Ok(encrypted) = crypto.encrypt(&decrypted) {
                if !state.send_to_agent(&requester, encrypted) {
                    eprintln!(
                        "[SERVER] Cannot forward response: requester '{}' not found",
                        requester
                    );
                }
            }
            continue;
        }

        // ── Try Packet (normal swarm traffic) ──
        let packet: Packet = match serde_json::from_slice(&decrypted) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[SERVER] Deserialize error: {}", e);
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
            state.route_message(&payload.from, &payload.to, &payload.body);
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
            forward_or_handle_locally(
                state, crypto, packet, &payload.target, &requester,
                || ResponsePacket::ToolCallResult {
                    requester: requester.clone(),
                    tool_name: tool_name.clone(),
                    success: false,
                    output: format!("Tool '{}' not recognized on server.", tool_name),
                },
            )
            .await;
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
    let payload = serde_json::to_vec(packet).unwrap();
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
        // Target unreachable — handle locally
        println!(
            "[SERVER] Target '{}' unreachable, handling {} locally",
            target,
            packet.describe()
        );
        let response = local_handler();
        if let Ok(payload) = serde_json::to_vec(&response) {
            if let Ok(encrypted) = crypto.encrypt(&payload) {
                // Send back to requester
                let _ = state.send_to_agent(requester, encrypted);
            }
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
        | ResponsePacket::Error { requester, .. } => requester.clone(),
    }
}

fn send_response_to(crypto: &Crypto, tx: &mpsc::UnboundedSender<Vec<u8>>, resp: &ResponsePacket) {
    if let Ok(payload) = serde_json::to_vec(resp) {
        if let Ok(encrypted) = crypto.encrypt(&payload) {
            let _ = tx.send(encrypted);
        }
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
