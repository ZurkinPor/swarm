# Swarm Protocol Specification

## Overview

**Swarm** is a self-contained, peer-to-peer TCP protocol written in Rust. It enables AI agents to orchestrate, cooperate, and work together as a swarm across multiple computers. Every capability — messaging, channels, task management, file transfer, remote command execution, directory browsing — is provided through Swarm's own binary packet types over a single AES-256-GCM encrypted TCP connection. No other protocols or services are used, wrapped, or proxied.

The Swarm wire format is a purpose-built binary protocol. Packet types are identified by a single byte; payloads use length-prefixed fields with raw bytes for binary data (no base64 encoding). Text fields are UTF-8. Structured data (tool arguments, notification events) is embedded as JSON within binary packets.

## Technical Details

| Property | Value |
|---|---|
| **Language** | Rust |
| **Transport** | TCP |
| **Default Port** | `6996` |
| **Topology** | Hub-and-spoke (one node acts as routing server, others connect as clients) |
| **Encryption** | AES-256-GCM, 64-character hex key |
| **Identity** | Username-based agents with optional roles |
| **Wire Format** | Binary: `[type: u8][compression: u8][uncompressed_len: u32 BE][payload]` |
| **Max Frame** | 16 MiB |

## Encryption

All traffic is encrypted with AES-256-GCM. A 64-character hexadecimal key is read from `swarm.key` at startup. Every node must share the same key. There is no plaintext on the wire — even the first byte of every frame is encrypted.

**Processing order (send):** Payload → zstd:11 compress (if >256B and compressible) → binary encode → AES-256-GCM encrypt → length-prefixed frame → TCP

**Processing order (receive):** TCP → length-prefixed frame → AES-256-GCM decrypt → binary decode → zstd decompress → payload

## Architecture

### Launch Modes

- **Server mode** (`serve`) — Listens on `0.0.0.0:6996`. Routes packets between connected agents, broadcasts notifications, enforces orchestrator rules, queues offline messages.
- **Client mode** (`connect`) — Connects to a server. Provides an interactive prompt (`swarm>`) or pipe mode (`--pipe`) for JSON stdin/stdout control by AI harnesses.

### Identity & Roles

Each agent has a username (unique within the swarm) and an optional role (`developer`, `researcher`, `documenter`, `reviewer`) that hints at its capabilities and preferred task types.

### Connection Lifecycle

- **Multi-client** — The server handles any number of concurrent connections via async tasks.
- **Heartbeat** — 60-second read timeout. A client that sends nothing for 60 seconds is removed and all agents are notified. Clients stay alive naturally by sending any packet (messages, status updates, task operations).
- **Offline queue** — Messages to disconnected agents are stored and delivered on reconnect.

### Key Management

- `-k <file>` — Read key from file (default: `swarm.key`)
- `-K <hex>` — Pass 64-char hex key directly
- `gen-key` — Generate a random key and save to file
- Auto-generation warning if no key file exists at startup

### Pipe Mode (`--pipe`)

For programmatic control by AI harnesses:

- **Input** — JSON commands on stdin, one per line
- **Output** — JSON events on stdout (`{"type":"event","data":{...}}`)
- **Stderr** — Connection logs and errors
- **Ready signal** — `{"type":"ready","username":"...","orchestrator":false}` on connect

---

## Binary Wire Format

Every packet (after AES-256-GCM decryption):

```
Byte 0:       packet_type (u8)
Byte 1:       compression (u8) — 0x00 = none, 0x1B = zstd:11
              Encoded as (algorithm << 4) | level: 0=none, 1=zstd
Bytes 2-5:    uncompressed_payload_length (u32, big-endian)
Bytes 6..:    payload (possibly zstd-compressed; type-specific binary fields)
```

### Compression

Payloads larger than 256 bytes are automatically compressed with zstd level 11 before encryption. The compression byte `0x1B` means "zstd algorithm, level 11" — `(1 << 4) | 11`.

- **Threshold**: 256 bytes — smaller payloads are sent uncompressed (overhead not worth it)
- **Fallback**: If zstd cannot shrink the data (already compressed payload), it falls back to uncompressed
- **File transfer**: SendFile skips wire compression for video, audio, image, and archive formats that are already compressed

### Payload primitives

| Primitive | Encoding | Used for |
|---|---|---|
| `flag` | u8, 0 or 1 | Booleans |
| `u8` | 1 byte | Short lengths, enum values |
| `u16` | 2 bytes BE | Medium lengths |
| `u32` | 4 bytes BE | Long lengths, raw data sizes |
| `u64` | 8 bytes BE | File size limits |
| `str8` | u8 len + UTF-8 bytes | Short strings (< 256 bytes) |
| `str16` | u16 len + UTF-8 bytes | Medium strings (paths, messages) |
| `opt_str16` | flag + str16 | Optional strings |
| `bytes` | u32 len + raw bytes | File content, binary blobs |
| `json` | u32 len + UTF-8 JSON | Tool arguments, notification events |
| `uuid` | 16 raw bytes | Task IDs, channel IDs |

### Design principles

- **Binary-first** — Every packet on the wire is binary. No text-based protocol layer.
- **Raw bytes for data** — File content is transmitted as raw bytes with a u32 length prefix. No base64, no hex encoding, no escaping.
- **JSON where needed** — Complex nested structures (tool call arguments, notification events) embed a JSON string within the binary packet. The envelope is binary; the structured data is JSON-accessible.
- **No magic numbers** — The first byte of every Swarm packet identifies its type. There is no separate framing magic — the outer TCP frame (4-byte BE length prefix, handled by the transport layer) provides framing.

---

## Packet Types

24 packet types, each identified by a u8 type ID on the wire.

### Connection (1–3)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 1 | `JOIN` | Client → Server | `flag(orchestrator) str8(username) opt_str16(role) u8(cap_count) [str16(cap)...] opt_str16(workspace) opt_str16(project_root)` |
| 2 | `LEAVE` | Client → Server | `str8(username) opt_str16(reason)` |
| 3 | `NOTIFY` | Server → Clients | `u8(event: 0–10)` + event-specific fields |

Notification events (type 3):

| ID | Event | Extra fields |
|---|---|---|
| 0 | AgentJoined | `flag(orchestrator) str8(name) opt_str16(role) opt_str16(workspace) opt_str16(root)` |
| 1 | AgentLeft | `str8(name) opt_str16(reason)` |
| 2 | TaskCreated | `uuid(id) str16(title) opt_str16(role)` |
| 3 | TaskAssigned | `uuid(id) str8(username)` |
| 4 | TaskCompleted | `uuid(id) str8(user) opt_str16(result) u8(n) [str16(artifact)...]` |
| 5 | ChannelCreated | `uuid(id) str8(name) str8(creator) str8(visibility)` |
| 6 | ChannelJoined | `str8(channel) str8(user)` |
| 7 | ChannelLeft | `str8(channel) str8(user)` |
| 8 | ChannelDeleted | `str8(channel) str8(deleted_by)` |
| 9 | StatusUpdate | `str8(user) str8(status) flag+uuid?(task) flag+u8?(pct)` |
| 10 | MessageReceived | `u64(timestamp) str8(datetime_utc) str8(time_region) str8(from) str8(to) str16(body)` |

### Tasks (4–6, 13, 19)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 4 | `CREATE_TASK` | Any → Server | `str16(title) str16(desc) u8(priority: 0–3) opt_str16(role) opt_str16(assign_to)` |
| 5 | `TAKE_TASK` | Client → Server | `str8(username) u8(count) [uuid(id)...]` |
| 6 | `STATUS` | Client → Server | `str8(user) u8(status: 0–3) flag+uuid?(task) flag+u8?(pct) opt_str16(msg)` |
| 13 | `TASK_COMPLETE` | Client → Server | `uuid(id) str8(user) opt_str16(result) u8(n) [str16(artifact)...]` |
| 19 | `ASSIGN_TASK` | Client → Server | `str8(assigned_by) uuid(id) str8(assign_to)` |

### Messaging (7)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 7 | `MESSAGE` | Any ↔ Any | `u64(timestamp) str8(datetime_utc) str8(time_region) str8(from) u8(target_type: 0=direct 1=channel) str8(target) str16(body)` |

### Channels (8, 14–18)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 8 | `CREATE_CHANNEL` | Any → Server | `str8(name) str8(created_by) opt_str16(desc) str8(visibility)` |
| 14 | `LIST_CHANNELS` | Client → Server | `str8(requester)` |
| 15 | `JOIN_CHANNEL` | Client → Server | `str8(channel) str8(username)` |
| 16 | `LEAVE_CHANNEL` | Client → Server | `str8(channel) str8(username)` |
| 17 | `DELETE_CHANNEL` | Client → Server | `str8(channel) str8(requested_by)` |
| 18 | `HIDE_CHANNEL` | Client → Server | `str8(channel) str8(username)` |

### Remote file system (9–10, 20–23)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 9 | `LIST_DRIVES` | Client → Target | `str8(requester) str8(target)` |
| 10 | `LIST_DIR` | Client → Target | `str8(requester) str8(target) str16(path) flag(recursive)` |
| 20 | `SEND_FILE` | Client → Target | `str8(requester) str8(target) str16(path) flag(overwrite) bytes(content)` |
| 21 | `RECEIVE_FILE` | Client → Target | `str8(requester) str8(target) str16(path) flag+u64?(max_bytes)` |
| 22 | `DELETE_FILE` | Client → Target | `str8(requester) str8(target) str16(path)` |
| 23 | `MAKE_DIR` | Client → Target | `str8(requester) str8(target) str16(path)` |

### Remote execution (11–12)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 11 | `HTTP_REQUEST` | Client → Target | `str8(req) str8(target) u8(method: 0–6) str16(url) u8(n_headers) [(str16,str16)...] opt_str16(body) u8(n_params) [(str16,str16)...]` |
| 12 | `TOOL_CALL` | Client → Target | `str8(req) str8(target) str8(tool_name) json(arguments)` |

### Agent listing (24)

| # | Type | Direction | Binary payload |
|---|---|---|---|
| 24 | `LIST_USERS` | Client → Server | `str8(requester)` |

### Enums

| Enum | Values (wire: Rust) |
|---|---|
| TaskPriority | 0=Low, 1=Normal, 2=High, 3=Critical |
| AgentStatus | 0=Idle, 1=Working, 2=Waiting, 3=Error |
| HttpMethod | 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=OPTIONS, 5=PATCH, 6=HEAD |
| MessageTarget | 0=Direct, 1=Channel |

---

## Orchestrator Mode

When `--orchestrator` is set on any agent, the swarm enters managed task mode:

- Non-orchestrator agents **cannot claim tasks** via `TAKE_TASK`. They receive an error.
- The orchestrator can **assign tasks** to specific agents via `ASSIGN_TASK` (#19).
- The orchestrator can still self-claim tasks.
- When all orchestrators leave, the swarm reverts to free-for-all mode.

When no orchestrator is present, tasks have a **2-second grace period** after creation. `TAKE_TASK` silently skips tasks younger than 2 seconds, ensuring all agents see the `TaskCreated` notification before anyone claims it.

---

## Swarm File Transfer

File operations use dedicated packet types (#20–#23) for minimal overhead:

- **SEND_FILE** (#20) — Uploads a file as raw bytes (no encoding). Max 10 MB. The target writes the file to disk.
- **RECEIVE_FILE** (#21) — Requests a file from a target. The target reads the file and returns raw bytes.
- **DELETE_FILE** (#22) — Deletes a file on a target.
- **MAKE_DIR** (#23) — Creates a directory recursively on a target.

Wire compression is intelligently skipped for incompressible file types. The `is_compressible_file()` function checks the file extension:

| Category | Compressed? | Examples |
|---|---|---|
| Code | ✅ zstd:11 | `.rs`, `.py`, `.js`, `.ts`, `.go`, `.cpp`, `.java`, `.c`, `.rb`, `.php`, `.swift`, `.kt`, `.cs`, `.sh`, `.bat` |
| Documents / Markup | ✅ zstd:11 | `.md`, `.txt`, `.json`, `.yaml`, `.toml`, `.xml`, `.html`, `.css`, `.csv`, `.log`, `.cfg`, `.sql` |
| Executables / Libraries | ✅ zstd:11 | `.exe`, `.dll`, `.so`, `.dylib`, `.wasm`, `.obj`, `.o`, `.lib`, `.a`, `.sys` |
| Document formats | ✅ zstd:11 | `.docx`, `.xlsx`, `.pptx`, `.odt`, `.svg`, `.rtf` |
| Fonts | ✅ zstd:11 | `.ttf`, `.otf`, `.woff`, `.woff2` |
| Extensionless / Dotfiles | ✅ zstd:11 | `Dockerfile`, `Makefile`, `LICENSE`, `.gitignore`, `.env` |
| Video | ❌ skip | `.mp4`, `.avi`, `.mkv`, `.mov`, `.webm`, `.flv` |
| Audio | ❌ skip | `.mp3`, `.wav`, `.flac`, `.ogg`, `.aac`, `.opus` |
| Images | ❌ skip | `.jpg`, `.png`, `.gif`, `.webp`, `.bmp`, `.svgz`, `.ico` |
| Archives | ❌ skip | `.zip`, `.gz`, `.xz`, `.7z`, `.rar`, `.tar`, `.bz2`, `.zst` |

Files are encrypted with AES-256-GCM along with the outer frame. There is no separate encryption negotiation or key exchange — the same 64-char hex key protects all traffic.

---

## Tool Execution System

37 tools are registered in Swarm's tool registry, invoked via the `TOOL_CALL` packet (#12):

| Range | Count | Category |
|---|---|---|
| `0x01`–`0x07` | 7 | Core: write_file, read_file, run_command, list_dir, create_dir, delete_file, file_exists |
| `0x08`–`0x0F` | 8 | Extended: list_drives, http_get, copy_file, move_file, file_size, env_var, sleep, whoami |
| `0x83` | 1 | write_todos |
| `0x80`–`0x93` | 20 | AI assistant: spawn_agents, read_files, str_replace, browser_use, code_reviewer, thinker, glob, etc. |

The `run_command` tool enforces a real timeout (polls child process, kills on expiry). The `env_var` tool caps output at 200 entries.

### Message Timestamps

Messages carry three timestamp-related fields:

- `timestamp` — Unix epoch seconds (u64). Machine-readable, compact on wire.
- `datetime_utc` — ISO 8601 UTC string (e.g. `"2026-08-08T14:05:30Z"`). Human-readable, zero-config.
- `time_region` — Sender's timezone label (e.g. `"UTC-5"`, `"EST"`, `"Europe/London"`). Set via `--time-region` flag, defaults to `"UTC"`.

The server broadcasts `MessageReceived` notifications carrying all three fields so every agent sees the sender's local time context. Pipe mode JSON output includes `datetime_utc` and `time_region`.

### Server as Client

The server acts as both a router and a peer. When a P2P packet targets the server's own username, the server handles it locally:

- `TOOL_CALL` → executes the tool on the server machine (all 37 tools)
- `SEND_FILE` → writes file to server disk
- `RECEIVE_FILE` → reads file from server disk
- `DELETE_FILE` → deletes file on server
- `MAKE_DIR` → creates directory on server
- `LIST_DRIVES` / `LIST_DIR` → enumerates server filesystem

No separate client instance is needed — the server is a first-class swarm member.

---

## System Tools

| ID | Name | Args | Description |
|---|---|---|---|
| `0x01` | `write_file` | `path`, `content` | Create or overwrite a file |
| `0x02` | `read_file` | `path`, `max_bytes?` | Read a file (capped at 1 MB) |
| `0x03` | `run_command` | `command`, `cwd?`, `timeout?` | Execute a shell command |
| `0x04` | `list_dir` | `path`, `recursive?` | List directory contents |
| `0x05` | `create_dir` | `path` | Create directories recursively |
| `0x06` | `delete_file` | `path` | Delete a file |
| `0x07` | `file_exists` | `path` | Check if a path exists |
| `0x08` | `list_drives` | — | List mounted drives/volumes |
| `0x09` | `http_get` | `url`, `timeout?` | HTTP GET request |
| `0x0A` | `copy_file` | `src`, `dst` | Copy a file |
| `0x0B` | `move_file` | `src`, `dst` | Move or rename a file |
| `0x0C` | `file_size` | `path` | Get file size |
| `0x0D` | `env_var` | `name?` | Get env variable (or list all) |
| `0x0E` | `sleep` | `ms` (max 60000) | Pause for N milliseconds |
| `0x0F` | `whoami` | — | Return hostname and username |

---

## Security Model

1. AES-256-GCM on every frame — no plaintext ever touches the wire.
2. Private by default — not discoverable without the key and server IP/port.
3. Trust is based on possession of the shared key file.
4. Remote execution is powerful — `TOOL_CALL` and `run_command` can execute arbitrary code on a remote machine. Only trusted agents should join the swarm.

---

## Future Considerations

- Streaming — persistent stream for real-time log tailing or long-running command output
- Agent discovery — UDP broadcast for LAN-based auto-discovery
- Key rotation — in-band key rotation protocol
- Chunked transfer — split files exceeding 10 MB across multiple frames
- Directory transfer — recursive send/recv for entire trees
