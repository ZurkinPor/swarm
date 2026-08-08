# Swarm Protocol Specification

## Overview

**Swarm** is a self-contained, peer-to-peer (P2P) TCP-based protocol written in Rust that enables AI agents to orchestrate, cooperate, and work together as a swarm across multiple computers. It provides messaging channels, role-based usernames, task assignment, distributed tool execution, and encrypted file transfer — all through its own packet types over a single encrypted TCP connection. No external protocols or services are used.

Swarm is designed as an **all-in-one replacement** for the fragmented ecosystem of collaboration tools. Where you would normally need separate tools for chat (IRC, Discord, Slack), file transfer (FTP/FTPS, SCP, shared drives), remote command execution (SSH), and task management (Jira, Trello), Swarm provides all of these capabilities through one unified, encrypted protocol. It does **not** wrap, proxy, or depend on any of those protocols — it replaces them entirely with its own packet types (#1–#23). Every message, every file listing, every tool call, every HTTP request, and every byte of data transferred between agents is encrypted with AES-256-GCM by default, with no plaintext ever touching the wire.

## Technical Details

| Property | Value |
|---|---|
| **Language** | Rust |
| **Transport** | TCP (server/client model) |
| **Default Port** | `6996` |
| **Topology** | P2P (one node acts as server, others connect as clients) |
| **Encryption** | AES-256 with a 64-character hex key stored in `filename.key` |
| **Identity** | Username-based agents with roles |

## Encryption

All traffic is encrypted. A 64-character hexadecimal key is read from `filename.key` at startup. All nodes must share the same key to join the swarm.

## Architecture

### Launch Modes

A node can be launched in one of two modes, determined by the user's prompt:

- **Server mode** — Listens on `0.0.0.0:6996` (or a user-specified port). Other agents connect to it.
- **Client mode** — Connects to a server at a user-specified IP (and optional port, if not the default).

### Identity & Roles

Each agent has:
- A **username** that uniquely identifies it within the swarm.
- An optional **role** (e.g., `developer`, `researcher`, `documenter`, `reviewer`) that hints at its capabilities and preferred task types.
- The ability to self-assign or be assigned a role by the user.

### Connection Lifecycle

- **Multi-client** — The server handles any number of concurrent client connections using async tasks.
- **Heartbeat / Dead Client Detection** — The server enforces a **60-second read timeout**. If a client sends no data for 60 seconds, it is considered dead and automatically removed from the swarm with all agents notified. Clients naturally stay alive by sending any packet (messages, status updates, task operations).

### Key Management

- **Key file** — A 64-char hex key stored in `swarm.key` (or any path via `-k`).
- **Direct hex key** — Pass the key directly via `-K <hex>` to avoid needing a file.
- **Generate** — `gen-key` creates a random key; `gen-key -K <hex> -o file.key` saves a specific key.
- **Auto-generation warning** — If no key file exists at startup, the server generates one and prints a prominent warning.

### Offline Message Queue

Messages sent to an agent that is currently disconnected are **queued** in the server's mailbox. When the agent reconnects, all queued messages are delivered automatically. Messages sent to connected agents are delivered in real-time via the notification broadcast.

### Pipe Mode (AI Harness Integration)

Clients can run in `--pipe` mode for programmatic control by AI agent harnesses:

- **Input** — JSON commands on stdin, one per line (`{"cmd":"msg","target":"buffy","body":"hello"}`)
- **Output** — JSON events on stdout (`{"type":"event","data":{...}}`)
- **Stderr** — Connection logs and errors (keeps stdout pure JSON)
- **Ready signal** — `{"type":"ready","username":"..."}` sent on connect

### Tool Execution System

Swarm includes a **37-tool registry** covering file operations, shell commands, HTTP, system introspection, and AI orchestration:

| Range | Count | Category |
|---|---|---|
| `0x01`–`0x07` | 7 | Core file ops (write, read, run_command, list_dir, create_dir, delete_file, file_exists) |
| `0x08`–`0x0F` | 8 | Extended (list_drives, http_get, copy_file, move_file, file_size, env_var, sleep, whoami) |
| `0x80`–`0x93` | 20 | AI assistant (spawn_agents, read_files, str_replace, browser_use, code_reviewer, thinker, glob, etc.) |
| `0x83` | 1 | write_todos (structured TODO.md generation) |

Tools can be invoked via JSON `TOOL_CALL` packets or compact binary format (magic byte `0x01`). The `run_command` tool enforces a real timeout (polls child process, kills on expiry). The `env_var` tool caps output at 200 entries to prevent explosion.

### Shared Workspace

Swarm supports two workspace modes:

1. **Git mode (default)** — Each agent has the same GitHub project cloned locally on its own machine. All agents work independently on their local copies, communicating changes and coordinating via the swarm. This is the recommended setup for most development workflows.

2. **Single-host mode (non-Git)** — The project lives as a plain folder on one agent's computer — no Git required. Other agents issue tool calls, Swarm file transfers, file listings, and HTTP requests over TCP against that host agent's machine. Useful for quick collaboration, legacy projects, or any folder-based work where setting up Git isn't desired.

In either mode, agents can also create local files unrelated to the project (notes, documentation, drafts, etc.) and hand them off to other agents as needed.

---

## Packet Types

All communication uses structured packets. Each packet has a **type** field and a **payload**.

| # | Packet Type | Direction | Description |
|---|---|---|---|
| 1 | `JOIN` | Client → Server | Agent announces itself to the swarm with username, role, and capabilities. |
| 2 | `LEAVE` | Client → Server / Broadcast | Agent disconnects from the swarm gracefully. Server broadcasts departure to remaining agents. |
| 3 | `NOTIFY` | Server → Clients | Server notifies all agents of swarm events (join, leave, task updates, etc.). |
| 4 | `CREATE_TASK` | Any → Server | Propose a new task with a description, priority, and optional assigned role. Server broadcasts to relevant agents. |
| 5 | `TAKE_TASK` | Client → Server | Agent claims one or more pending tasks. Server acknowledges and broadcasts the assignment. |
| 6 | `STATUS` | Client → Server | Agent reports its current status (idle, working on task X, progress percentage, etc.). |
| 7 | `MESSAGE` | Any ↔ Any | Direct or channel-based text message between agents. |
| 8 | `CREATE_CHANNEL` | Any → Server | Create a named communication channel. Agents can join/leave channels. |
| 14 | `LIST_CHANNELS` | Client → Server | Request a list of all visible (non-hidden) channels in the swarm. |
| 15 | `JOIN_CHANNEL` | Client → Server | Agent requests to join a channel by name. Server adds them to the member list. |
| 16 | `LEAVE_CHANNEL` | Client → Server | Agent leaves a channel they are a member of. |
| 17 | `DELETE_CHANNEL` | Client → Server | Delete a channel. Only the channel creator (or server) can delete. |
| 18 | `HIDE_CHANNEL` | Client → Server | Hide a channel from the agent's visible channel list. Does not leave the channel — just hides it from view. |
| 9 | `LIST_DRIVES` | Client → Target Agent | Request a list of mounted drives/volumes on the target agent's machine. |
| 10 | `LIST_DIR` | Client → Target Agent | List directories and files at a given path, with optional recursive flag. |
| 11 | `HTTP_REQUEST` | Client → Target Agent | Ask an agent to perform an HTTP request (GET/POST/PUT/DELETE/OPTIONS/etc.) to a URL, with optional payload and query string. Results are returned to the requester. |
| 12 | `TOOL_CALL` | Client → Target Agent | Invoke a named tool on the target agent's machine with supplied arguments. Results are returned. |
| 13 | `TASK_COMPLETE` | Client → Server | Agent notifies the swarm that a task is finished, optionally including results or artifacts. |
| 19 | `ASSIGN_TASK` | Client → Server | Orchestrator assigns a pending task to a specific agent. Only orchestrators can send this. Non-orchestrator agents cannot `take` tasks when an orchestrator is present. |
| 20 | `SEND_FILE` | Client → Target Agent | Upload a file to a remote agent via Swarm's encrypted file transfer (base64-encoded payload, max 10MB). Content is encrypted along with the outer frame. |
| 21 | `RECEIVE_FILE` | Client → Target Agent | Request a file from a remote agent. The target reads the file and returns it base64-encoded in the response. |
| 22 | `DELETE_FILE` | Client → Target Agent | Delete a file on a remote agent. First-class Swarm packet (not a tool call) — fast, encrypted file deletion. |
| 23 | `MAKE_DIR` | Client → Target Agent | Create a directory recursively on a remote agent. First-class Swarm packet for encrypted directory creation. |

### Orchestrator Mode

When `--orchestrator` is set on any agent (server or client), the swarm enters **managed task mode**:

- Non-orchestrator agents **cannot `take` tasks** — they receive an error: *"An orchestrator is present — you cannot take tasks."*
- The orchestrator can **`assign` tasks** to specific agents via `ASSIGN_TASK` (#19).
- The orchestrator can still **self-claim** tasks via `take`.
- When all orchestrators leave, the swarm reverts to free-for-all mode.

When no orchestrator is present, task claiming has a **2-second grace period** after task creation. The `take` command silently skips tasks younger than 2 seconds, ensuring all agents see the `TaskCreated` broadcast before anyone claims the task — preventing accidental double-takes.

### Binary Tool Call Protocol

Tool calls can be sent in a compact binary format instead of JSON for reduced overhead:

```
Byte 0:    0x01      (magic byte — marks this as binary, not JSON)
Byte 1:    tool_id   (u8 — 0x01–0x93, see tool registry)
Bytes 2-3: target_len (u16, big-endian)
Bytes 4..:  target    (UTF-8)
Next 2:    requester_len (u16, big-endian)
Next ..:   requester   (UTF-8)
Next 4:    args_len    (u32, big-endian)
Next ..:   args_json   (UTF-8 JSON)
```

Total overhead: **12 bytes + target + requester** — substantially smaller than JSON for large tool calls. 37 tools are registered with IDs from `0x01` to `0x93`. Server detects the `0x01` magic byte after decryption and forwards to the target agent. The target executes the tool and returns a JSON response as usual.

### Swarm File Transfer

Swarm has its own encrypted file transfer protocol built directly into the packet layer (#20–#23). There is no separate FTP/FTPS/SFTP sub-protocol — file operations are first-class Swarm packets, encrypted with the same AES-256-GCM key as everything else:

- **SEND_FILE** — Upload a file to a remote agent. Content is base64-encoded. Max 10MB per transfer. Server forwards to target; target writes the file and returns bytes written.
- **RECEIVE_FILE** — Request a file from a remote agent. Server forwards to target; target reads and base64-encodes, returns content.
- **DELETE_FILE** — Delete a file on a remote agent. First-class packet with no tool call overhead.
- **MAKE_DIR** — Create a directory recursively on a remote agent. First-class packet.

Unlike tool calls (which serialize through JSON and a generic executor), these packets are routed directly by the server with minimal overhead. All transfers are encrypted with AES-256-GCM along with the outer frame — there is no separate encryption layer or protocol negotiation.

### Packet Lifecycle Example

1. **Client** sends `JOIN` → **Server** acknowledges and broadcasts `NOTIFY` to all others.
2. **Agent A** sends `CREATE_TASK` → **Server** broadcasts to agents whose role matches (or to all).
3. **Agent B** sends `TAKE_TASK` → **Server** confirms and broadcasts assignment.
4. **Agent B** sends periodic `STATUS` updates while working.
5. **Agent B** sends `TASK_COMPLETE` → **Server** broadcasts completion.

### Channel Lifecycle Example

1. **Agent A** sends `CREATE_CHANNEL` → **Server** creates the channel and adds Agent A as a member. Broadcasts `ChannelCreated`.
2. **Agent B** sends `LIST_CHANNELS` → **Server** returns visible channels. Agent B sees the new channel.
3. **Agent B** sends `JOIN_CHANNEL` → **Server** adds Agent B to the member list. Broadcasts `ChannelJoined`.
4. **Agent B** sends `MESSAGE` to the channel → **Server** routes to all channel members except sender.
5. **Agent B** sends `HIDE_CHANNEL` → **Server** hides the channel from Agent B's list. Agent B is still a member.
6. **Agent A** sends `DELETE_CHANNEL` → **Server** removes the channel entirely. Broadcasts `ChannelDeleted`.

### File Transfer Lifecycle Example

1. **Agent A** sends `SEND_FILE` → **Server** forwards to **Agent B**. Agent B writes the file to disk and responds with bytes written.
2. **Agent A** sends `RECEIVE_FILE` → **Server** forwards to **Agent B**. Agent B reads the file, base64-encodes it, and returns the content.
3. **Agent A** sends `DELETE_FILE` → **Server** forwards to **Agent B**. Agent B deletes the file and responds with success/failure.
4. **Agent A** sends `MAKE_DIR` → **Server** forwards to **Agent B**. Agent B creates the directory recursively and responds.

---

## Feature Summary

### Core Swarm Features
- **Join / Leave** — Agents connect to and disconnect from the swarm.
- **Notifications** — Server pushes swarm events (joins, leaves, task changes, channel events) to all connected agents.
- **Messaging** — Direct (1-to-1) and channel-based (many-to-many) text communication.

### Swarm Channels (Encrypted, Self-Contained)
- **Create Channels** — Any agent can create a named channel with an optional description. No external chat service is used — channels are Swarm's own packet-driven communication groups.
- **Join / Leave Channels** — Agents can join open channels or leave channels they're in.
- **List Channels** — View all channels visible to the agent (hides channels the agent has hidden).
- **Delete Channels** — The channel creator can delete their channel, removing it from the swarm.
- **Hide Channels** — Hide a channel from your view without leaving it. Useful for muting noisy channels.
- **Channel Messaging** — Send messages to a channel via Swarm's `MESSAGE` packet; all members receive them. This replaces the need for separate chat tools like Discord, Slack, or IRC — Swarm handles it all natively.

### Task Management
- **Create Tasks** — Any agent can propose a task with description, priority, and target role.
- **Take Tasks** — Agents claim available tasks. A task can be taken by one or multiple agents.
- **Status Reporting** — Agents periodically report progress (idle, busy, % complete).
- **Completion Notification** — Agents signal when a task is done, with optional deliverable.

### Swarm File Transfer
- **Send / Receive Files** — Upload and download files between agents via dedicated Swarm packets (#20–#21). No external FTP/FTPS/SFTP protocol — Swarm has its own encrypted file transfer built into the packet layer.
- **Delete Files / Make Directories** — Remote file deletion and directory creation via Swarm packets (#22–#23).
- **List Drives** — Enumerate mounted volumes on a remote agent's machine (#9).
- **List Directories** — Browse directory trees on a remote agent (#10).

### Remote Execution
- **Tool Calls** — Invoke any of 37 tools on a remote agent's machine via Swarm packets (#12), enabling distributed computing. No SSH or remote shell — Swarm's own `run_command` tool executes commands and returns output.
- **HTTP Requests** — Ask a remote agent to issue HTTP calls (REST, scraping, API interaction) from its machine (#11).

### Collaborative Development
- Agents work on the same GitHub project cloned across all machines.
- One agent can act as the "build host" while others issue tool calls to it over TCP.
- Agents can create local scratch files (notes, docs, drafts) and share them with the swarm.

---

## Security Model

1. **Encryption** — All TCP traffic is encrypted using the shared 64-char hex key from `filename.key`.
2. **Private by default** — The swarm is not discoverable; only agents with the key and IP/port can connect.
3. **No built-in authentication beyond the shared key** — Trust is based on possession of the key file.
4. **Remote execution is powerful and dangerous** — `TOOL_CALL` and `HTTP_REQUEST` allow arbitrary code/network access on a remote machine. Only trusted agents should be in the swarm.

---

### Messaging
- **Offline Queue** — Messages to disconnected agents are stored and delivered on reconnect.
- **Heartbeat** — 60-second read timeout detects and removes dead clients automatically.
- **Pipe Mode** — JSON stdin/stdout for programmatic AI harness control (`--pipe` flag).

---

## Future Considerations

- **Streaming** — Persistent TCP stream for real-time log tailing or long-running command output.
- **Agent discovery** — UDP broadcast or mDNS for LAN-based auto-discovery.
- **Key rotation** — In-band key rotation protocol for long-running swarms.
- **Compression** — Optional gzip/zstd compression for large payloads.
- **Chunked file transfer** — Split large files into multiple frames for transfers exceeding the 10MB limit.
- **Directory transfer** — Recursive send/recv for entire directory trees as a single operation.
