# Swarm Manual

A self-contained peer-to-peer TCP protocol for AI agent orchestration. Swarm provides messaging, channels, task management, file transfer, remote command execution, and directory browsing — all through its own binary packet types over a single AES-256-GCM encrypted TCP connection.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Launch Modes](#launch-modes)
3. [Key Management](#key-management)
4. [Interactive Commands](#interactive-commands)
5. [Pipe Mode (AI Harness)](#pipe-mode-ai-harness)
6. [Binary Tool Calls](#binary-tool-calls)
7. [Orchestrator Mode](#orchestrator-mode)
8. [Task Workflows](#task-workflows)
9. [Channel System](#channel-system)
10. [Remote Operations](#remote-operations)
11. [Tool Registry](#tool-registry)
12. [Architecture](#architecture)
13. [Examples](#examples)

---

## Quick Start

### 1. Download or Build

```bash
# Download the pre-built binary from the repo root (Windows, ~2.8 MB)
# Or build from source:
cargo build --release
```

### 2. Generate a Key

```bash
./swarm gen-key                    # creates swarm.key
./swarm gen-key -o my.key          # custom filename
```

Share `swarm.key` with every agent that joins. All traffic is encrypted with this key.

### 3. Start the Server

```bash
./swarm serve                      # listens on 0.0.0.0:6996
./swarm serve -p 9000              # custom port
./swarm serve -u main-hub          # custom server name
./swarm serve --orchestrator       # run as task orchestrator
```

### 4. Connect Clients

```bash
./swarm connect -s 192.168.1.10 -u alice
./swarm connect -s 192.168.1.10 -u bob -r developer
./swarm connect -s 192.168.1.10 -u leader --orchestrator
./swarm connect -s 192.168.1.10 -u agent --pipe   # AI harness mode
```

---

## Launch Modes

### `serve` — Start a Swarm Server

```
./swarm serve [OPTIONS]

Options:
  -u, --username <NAME>         Server node name [default: swarm-server]
  -r, --role <ROLE>             Server role
  -p, --port <PORT>             Custom port [default: 6996]
  -k, --key-file <PATH>         Path to key file [default: swarm.key]
  -K <HEX>                      64-char hex key directly
      --workspace-mode <MODE>   "git" or "single-host" [default: git]
      --orchestrator            Run as task orchestrator
```

The server registers itself as an agent, handles routing, broadcasts notifications, and enforces orchestrator rules.

### `connect` — Join a Swarm as a Client

```
./swarm connect [OPTIONS]

Options:
  -s, --server <IP>             Server IP address (required)
      --server-port <PORT>      Server port [default: 6996]
  -u, --username <NAME>         Your agent name (required)
  -r, --role <ROLE>             Your role (developer, researcher, etc.)
  -k, --key-file <PATH>         Path to key file [default: swarm.key]
  -K <HEX>                      64-char hex key directly
      --capabilities <LIST>     Comma-separated capabilities [default: general]
      --workspace-mode <MODE>   "git" or "single-host" [default: git]
      --project-root <PATH>     Project root for single-host mode
      --orchestrator            Run as task orchestrator
      --pipe                    JSON stdin/stdout mode for AI harnesses
```

### `gen-key` — Generate Encryption Key

```
./swarm gen-key [OPTIONS]

Options:
  -o, --output <PATH>           Output file [default: swarm.key]
  -k, --key <HEX>               Save a specific hex key (don't generate)
```

**Examples:**
```bash
./swarm gen-key                              # random key → swarm.key
./swarm gen-key -k e114e62f... -o my.key     # save specific key
```

---

## Key Management

Swarm uses AES-256-GCM encryption. All nodes must share the same key.

| Method | Flag | Example |
|---|---|---|
| Key file | `-k swarm.key` | `./swarm serve -k my.key` |
| Hex string | `-K <64-char-hex>` | `./swarm serve -K e114e62f...` |
| Auto-generate | *(no flag, no file)* | Creates `swarm.key` with warning |

**Note:** The `-K` flag must come **before** the subcommand:
```bash
./swarm -K e114e62f8df59ba2e5ea6b093e0f60e6b67dde3f036530b6312fb6d977f8b37a serve -u hub
```

---

## Interactive Commands

Once connected, type at the `swarm>` prompt. Type `help` to see this list.

### Messaging

| Command | Description |
|---|---|
| `msg <user> <body>` | Direct message to an agent |
| `msg #<channel> <body>` | Message to a channel |

**Examples:**
```
swarm> msg alice Hey, how's the login task going?
swarm> msg #general Build failed — can anyone take a look?
```

### Swarm Channels

Named, encrypted communication groups. Channels are created, joined, and managed through Swarm's own packet types — a first-class part of the protocol, not an external service.

| Command | Description |
|---|---|
| `channel <name> [desc] [--private]` | Create a channel |
| `channels` | List all visible channels |
| `join <name>` | Join a channel |
| `leave <name>` | Leave a channel |
| `delete-channel <name>` | Delete a channel (creator only) |
| `hide <name>` | Hide a channel from your list |

**Channel Lifecycle:**
```
swarm> channel general main chat room
swarm> channel secrets --private confidential channel
swarm> channels
  #general (1 members, public by alice)
    main chat room
  #secrets (1 members, private by alice)
swarm> join general
swarm> msg #general hello everyone!
swarm> hide secrets
swarm> delete-channel general
```

### Tasks

| Command | Description |
|---|---|
| `task <title> [role:<r>]` | Create a new task |
| `take <task_id>` | Claim a pending task |
| `assign <task_id> <user>` | Assign task to user (orchestrator only) |
| `done <task_id>` | Mark a task as complete |
| `status <msg>` | Update your status |

**Examples:**
```
swarm> task Fix login timeout bug role:developer
swarm> task Write API docs role:documenter
swarm> take a1b2c3d4-...
swarm> assign e5f6a7b8-... bob
swarm> done a1b2c3d4-...
swarm> status Working on login bug, 60% done
```

### Remote File System

| Command | Description |
|---|---|
| `drives <target>` | List drives on a remote agent |
| `ls <target>:<path>` | List directory on a remote agent |

**Examples:**
```
swarm> drives alice
  C:\, D:\, E:\
swarm> ls bob:C:/projects
  d src (0b)
  f README.md (1024b)
  f Cargo.toml (512b)
```

### Swarm File Transfer

First-class packet types (#20–#23) for encrypted file operations. Files are transmitted as raw bytes — no encoding overhead.

| Command | Description |
|---|---|
| `send <t> <local> <remote>` | Upload a file (raw bytes, max 10MB) |
| `recv <t> <remote_path>` | Download a file (raw bytes) |
| `rm <t> <path>` | Delete a file on a remote agent |
| `mkdir <t> <path>` | Create a directory on a remote agent (recursive) |

**Examples:**
```
swarm> send alice ./report.pdf /home/alice/reports/report.pdf
swarm> recv bob /var/log/app.log
swarm> rm alice /tmp/junk.txt
swarm> mkdir bob /home/bob/new-feature
```

Received files are auto-saved to the current directory (stripped of their remote path).

### Remote Tools

Invoke tools on remote agents through the `TOOL_CALL` packet (#12).

| Command | Description |
|---|---|
| `cp <t> <src> <dst>` | Copy a file on a remote agent |
| `mv <t> <src> <dst>` | Move/rename a file on a remote agent |
| `size <t> <path>` | Get file size on a remote agent |
| `env <t> [name]` | Get env var on a remote agent |
| `whoami <t>` | Get hostname/username of a remote agent |
| `sleep <t> <ms>` | Pause a remote agent (max 60s) |
| `http-get <t> <url>` | HTTP GET from a remote agent |
| `list-drives <t>` | List drives on a remote agent |
| `todos <t> [json]` | Write a TODO.md on a remote agent |
| `tool <t> <name> [args]` | Invoke any tool by name |
| `btc <t> <id> [args]` | Binary tool call by byte ID |
| `tools-list` | List all 37 binary tool IDs |

**Examples:**
```
swarm> cp alice C:/project/main.rs C:/backup/main.rs.bak
swarm> mv bob /tmp/draft.md /docs/final.md
swarm> size alice C:/project/large-file.bin
swarm> env alice HOME
swarm> whoami bob
swarm> sleep bob 2000
swarm> http-get alice https://api.github.com/repos/torvalds/linux
swarm> list-drives alice
swarm> todos bob [{"task":"fix bug","completed":false},{"task":"write test","completed":true}]
swarm> tool bob write_file {"path":"hello.txt","content":"world"}
swarm> btc bob 1 {"path":"test.txt","content":"binary tool call works!"}
```

### Other

| Command | Description |
|---|---|
| `help` | Show command list |
| `quit` or `exit` | Leave the swarm |

---

## Pipe Mode (AI Harness)

Pipe mode enables AI agent harnesses to control Swarm programmatically via stdin/stdout.

### Starting

```bash
./swarm connect -s 127.0.0.1 -u ai-assistant --pipe
```

On connect, the client emits a ready signal:
```json
{"type":"ready","username":"ai-assistant","orchestrator":false}
```

### Input — JSON commands on stdin (one per line)

```json
{"cmd":"msg","target":"alice","body":"Hello from AI!"}
{"cmd":"msg","target":"#general","body":"Build complete"}
{"cmd":"channel","name":"ai-chat","description":"AI agents discussion"}
{"cmd":"channels"}
{"cmd":"join","name":"ai-chat"}
{"cmd":"leave","name":"ai-chat"}
{"cmd":"delete-channel","name":"ai-chat"}
{"cmd":"hide","name":"noisy-channel"}
{"cmd":"task","title":"Fix bug #42","description":"Null pointer in auth","priority":"high","role":"developer"}
{"cmd":"take","task_id":"a1b2c3d4-..."}
{"cmd":"assign","task_id":"e5f6a7b8-...","assign_to":"bob"}
{"cmd":"done","task_id":"a1b2c3d4-...","result":"Fixed: added null check"}
{"cmd":"status","message":"Working on it, 50% done"}
{"cmd":"drives","target":"alice"}
{"cmd":"ls","target":"alice","path":"C:/projects"}
{"cmd":"cp","target":"alice","src":"/tmp/a.txt","dst":"/tmp/b.txt"}
{"cmd":"mv","target":"bob","src":"/old","dst":"/new"}
{"cmd":"send","target":"alice","local":"./report.pdf","remote":"/home/alice/report.pdf"}
{"cmd":"recv","target":"bob","path":"/var/log/app.log"}
{"cmd":"rm","target":"alice","path":"/tmp/junk.txt"}
{"cmd":"mkdir","target":"bob","path":"/home/bob/new-dir"}
{"cmd":"size","target":"alice","path":"/large-file.bin"}
{"cmd":"env","target":"alice","name":"HOME"}
{"cmd":"whoami","target":"bob"}
{"cmd":"sleep","target":"bob","ms":5000}
{"cmd":"http-get","target":"alice","url":"https://api.example.com/data"}
{"cmd":"list-drives","target":"alice"}
{"cmd":"todos","target":"alice","path":"TODO.md","title":"# Sprint 3","todos":[{"task":"Fix auth","completed":false}]}
{"cmd":"tool","target":"alice","tool_name":"write_file","args":{"path":"hello.txt","content":"world"}}
{"cmd":"btc","target":"alice","tool_id":1,"args":{"path":"test.txt","content":"binary"}}
{"cmd":"btc","target":"alice","tool_id":"0x0F","args":{}}
{"cmd":"tools-list"}
{"cmd":"quit"}
```

### Output — JSON events on stdout

**Responses (tool results, channel lists):**
```json
{"type":"response","data":{"type":"ToolCallResult","payload":{"requester":"ai","tool_name":"write_file","success":true,"output":"Wrote 5 bytes to hello.txt"}}}
```

**Events (notifications):**
```json
{"type":"event","data":{"type":"Notify","payload":{"event":"AgentJoined","username":"alice","role":"developer","workspace_mode":"git","project_root":null,"is_orchestrator":false}}}
```

**Binary tool calls received:**
```json
{"type":"binary_tool_call","data":{"tool_id":"0x01","tool_name":"write_file","target":"ai-assistant","requester":"buffy","arguments":{"path":"test.txt","content":"hello"}}}
```

**Errors:**
```json
{"type":"error","message":"'target' required"}
```

**Tool list:**
```json
{"type":"tool_list","tools":[{"id":"0x01","name":"write_file","description":"Create or overwrite a file"},...]}
```

---

## Binary Wire Format

All Swarm packets use a unified binary format on the wire:

```
Byte 0:       packet_type (u8 — see packet type table)
Bytes 1-4:    payload_len (u32, big-endian)
Bytes 5..:    payload (type-specific binary fields)
```

Payload fields use length-prefixed encoding: `str8` (u8 + UTF-8), `str16` (u16 + UTF-8), `bytes` (u32 + raw bytes for file content), `json` (u32 + UTF-8 JSON for complex structures like tool arguments).

### Tool call by ID

```
swarm> btc bob 1 {"path":"test.txt","content":"hello"}   # decimal ID
swarm> btc bob 0x0F {}                                    # hex ID
swarm> tools-list                                         # list all tool IDs
```

---

## Orchestrator Mode

The orchestrator is a special agent that manages task distribution.

### Enabling

```bash
./swarm serve --orchestrator
./swarm connect -s 127.0.0.1 -u leader --orchestrator
```

### Behavior

| Scenario | Agent can `take`? | Agent can `assign`? |
|---|---|---|
| No orchestrator in swarm | ✅ (after 2s grace period) | ❌ |
| Orchestrator present, agent is NOT orchestrator | ❌ (must be assigned) | ❌ |
| Orchestrator present, agent IS orchestrator | ✅ | ✅ |

### Grace Period (No Orchestrator Mode)

When no orchestrator is present, tasks have a **2-second grace period** after creation. During this window, `take` silently skips the task. This ensures all agents see the `TaskCreated` notification before anyone claims it — preventing accidental double-takes.

### Multiple Orchestrators

You can have multiple orchestrators. `has_orchestrator()` returns `true` if ANY orchestrator is connected. If the last orchestrator leaves, the swarm reverts to free-for-all mode.

### AgentJoined Notification

When an orchestrator joins, all agents see:
```
[SWARM] Agent 'leader' joined (role: Some("orchestrator"), workspace: git) [ORCHESTRATOR]
```

---

## Task Workflows

### Option A: Self-Service (No Orchestrator)

```
Agent A> task Fix login timeout role:developer
         Server broadcasts: [SWARM] Task created: 'Fix login timeout' (id: a1b2-...)
         (2 second grace period — all agents see the notification)

Agent B> take a1b2-...
         Server broadcasts: [SWARM] Task a1b2-... assigned to 'bob'

Agent B> status Working on login timeout — 50% done

Agent B> done a1b2-...
         Server broadcasts: [SWARM] Task a1b2-... completed by 'bob'
```

### Option B: Orchestrator-Managed

```
Leader>   task Fix login timeout role:developer
Leader>   task Write API docs role:documenter
           Server broadcasts both tasks

Leader>   assign a1b2-... alice    ← orchestrator assigns
           Server broadcasts: Task a1b2-... assigned to 'alice'

Leader>   assign c3d4-... bob
           Server broadcasts: Task c3d4-... assigned to 'bob'

Alice>    status Working on login timeout
Bob>      status Documenting API endpoints

Alice>    done a1b2-...
Bob>      done c3d4-...
```

### Option C: Hybrid

The orchestrator can take tasks themselves if they want to work on them:

```
Leader>   task Critical security patch role:developer
Leader>   take e5f6-...                    ← orchestrator self-claims
Leader>   assign a1b2-... alice            ← delegates other tasks
```

---

## Channel System

Named, encrypted communication groups. Channels are created, joined, hidden, and deleted through Swarm's own packet types. All channel messages are encrypted with the shared AES-256-GCM key.

### Visibility

| Type | Who can see it | Who can join |
|---|---|---|
| **Public** | Everyone in the swarm | Anyone can join |
| **Private** | Only members | Must be invited (future) |

### Commands

```
swarm> channel general main discussion     # public channel
swarm> channel secrets --private            # private channel
swarm> channels                             # list visible
swarm> join general                         # become a member
swarm> msg #general hello world!            # send to channel
swarm> hide noisy-channel                   # hide from your list
swarm> leave secrets                        # leave channel
swarm> delete-channel general               # delete (creator only)
```

### Channel Notifications

All channel events are broadcast to every agent:
- `ChannelCreated` — when someone creates a channel
- `ChannelJoined` — when someone joins
- `ChannelLeft` — when someone leaves
- `ChannelDeleted` — when deleted by creator

---

## Remote Operations

Swarm supports three types of remote operations on other agents:

### 1. Swarm File Transfer Packets

| Packet | Description |
|---|---|
| `SEND_FILE` (#20) | Upload raw bytes to target (max 10MB) |
| `RECEIVE_FILE` (#21) | Request raw bytes from target |
| `DELETE_FILE` (#22) | Delete a file on target |
| `MAKE_DIR` (#23) | Create a directory on target |

### 2. P2P Query Packets (server-routed)

| Packet | Description |
|---|---|
| `LIST_DRIVES` (#9) | Enumerate drives on target |
| `LIST_DIR` (#10) | List directory contents on target |
| `HTTP_REQUEST` (#11) | HTTP call from target's machine |

These go through the server which forwards them to the target agent. Responses come back the same way.

### 3. Tool Calls

```
swarm> tool bob write_file {"path":"hello.txt","content":"world"}
swarm> btc bob 1 {"path":"test.txt","content":"binary!"}  # by tool ID
```

The `TOOL_CALL` packet (#12) invokes a named tool on the target. Any tool in the registry (37 total) is available. The `btc` command is shorthand for tool calls by numeric ID.

---

## Tool Registry

### Built-in Tools (0x01–0x0F)

| ID | Name | Args | Description |
|---|---|---|---|
| `0x01` | `write_file` | `path`, `content` | Create or overwrite a file |
| `0x02` | `read_file` | `path`, `max_bytes?` | Read a file (capped at 1MB) |
| `0x03` | `run_command` | `command`, `cwd?`, `timeout?` | Execute a shell command |
| `0x04` | `list_dir` | `path`, `recursive?` | List directory contents |
| `0x05` | `create_dir` | `path` | Create directories recursively |
| `0x06` | `delete_file` | `path` | Delete a file |
| `0x07` | `file_exists` | `path` | Check if a path exists |
| `0x08` | `list_drives` | — | List mounted drives/volumes |
| `0x09` | `http_get` | `url`, `timeout?` | HTTP GET request |
| `0x0A` | `copy_file` | `src`, `dst` | Copy a file |
| `0x0B` | `move_file` | `src`, `dst` | Move or rename a file |
| `0x0C` | `file_size` | `path` | Get file size (human-readable) |
| `0x0D` | `env_var` | `name?` | Get env var (or list all) |
| `0x0E` | `sleep` | `ms` (max 60000) | Pause for N milliseconds |
| `0x0F` | `whoami` | — | Return hostname@username (OS) |

### AI Assistant Tools (0x80–0x93)

| ID | Name | Description |
|---|---|---|
| `0x80` | `spawn_agents` | Spawn specialized sub-agents |
| `0x81` | `read_files` | Read files with parsed metadata |
| `0x82` | `read_subtree` | Read a directory tree blob |
| `0x83` | `write_todos` | Write a structured TODO.md file |
| `0x84` | `suggest_followups` | Suggest next-step followup actions |
| `0x85` | `str_replace` | Edit files with exact-string replacement |
| `0x86` | `ask_user` | Ask the user multiple-choice questions |
| `0x87` | `read_url` | Fetch a URL and extract readable text |
| `0x88` | `render_ui` | Render interactive UI widgets |
| `0x89` | `gravity_index` | Discover and compare 3rd-party services |
| `0x8A` | `file_picker` | Fuzzy-search for relevant files |
| `0x8B` | `code_searcher` | Run ripgrep queries over the codebase |
| `0x8C` | `researcher_web` | Browse the web for information |
| `0x8D` | `researcher_docs` | Read technical library documentation |
| `0x8E` | `basher` | Run a single terminal command |
| `0x8F` | `tmux_cli` | Interact with CLI apps via tmux |
| `0x90` | `browser_use` | Automate Chrome via DevTools |
| `0x91` | `code_reviewer` | Review code changes for bugs |
| `0x92` | `thinker` | Deep reasoning with Gemini |
| `0x93` | `glob` | Find files by glob pattern |

Use `tools-list` at the interactive prompt to see the full registry, or `{"cmd":"tools-list"}` in pipe mode.

---

## Architecture

```
                     TCP :6996 (AES-256-GCM encrypted)
 ┌─────────┐     ┌──────────┐     ┌─────────┐
 │ Agent A │────▶│  SERVER  │◀────│ Agent B │
 │ (client)│◀────│  (hub)   │────▶│ (client)│
 └─────────┘     └──────────┘     └─────────┘
                       │
                       │ Broadcast notifications (joins, leaves, tasks, channels, messages)
                       │ P2P routing (ListDrives, ListDir, HttpRequest, ToolCall)
                       │ Offline message queuing
                       │ Heartbeat monitoring (60s timeout)
                       ▼
                 ┌─────────┐
                 │ Agent C │
                 │ (client)│
                 └─────────┘
```

### Key Properties

| Property | Value |
|---|---|
| Transport | TCP, length-prefixed frames (4-byte BE + payload) |
| Encryption | AES-256-GCM on every frame |
| Default Port | 6996 |
| Max Frame | 16 MiB |
| Heartbeat | 60-second read timeout |
| Offline Messages | Queued, delivered on reconnect |
| Multi-client | Async tasks, one per connection |
| File Transfer Max | 10 MB per file (raw bytes) |

### Packet Types (23 total)

| # | Type | Direction |
|---|---|---|
| 1 | `JOIN` | Client → Server |
| 2 | `LEAVE` | Client → Server |
| 3 | `NOTIFY` | Server → Clients |
| 4 | `CREATE_TASK` | Any → Server |
| 5 | `TAKE_TASK` | Client → Server |
| 6 | `STATUS` | Client → Server |
| 7 | `MESSAGE` | Any ↔ Any |
| 8 | `CREATE_CHANNEL` | Any → Server |
| 9 | `LIST_DRIVES` | Client → Target Agent |
| 10 | `LIST_DIR` | Client → Target Agent |
| 11 | `HTTP_REQUEST` | Client → Target Agent |
| 12 | `TOOL_CALL` | Client → Target Agent |
| 13 | `TASK_COMPLETE` | Client → Server |
| 14 | `LIST_CHANNELS` | Client → Server |
| 15 | `JOIN_CHANNEL` | Client → Server |
| 16 | `LEAVE_CHANNEL` | Client → Server |
| 17 | `DELETE_CHANNEL` | Client → Server |
| 18 | `HIDE_CHANNEL` | Client → Server |
| 19 | `ASSIGN_TASK` | Client → Server |
| 20 | `SEND_FILE` | Client → Target Agent |
| 21 | `RECEIVE_FILE` | Client → Target Agent |
| 22 | `DELETE_FILE` | Client → Target Agent |
| 23 | `MAKE_DIR` | Client → Target Agent |

---

## Examples

### Example 1: Basic Chat Swarm

```bash
# Terminal 1 — Start server
./swarm serve -u hub

# Terminal 2 — Alice joins
./swarm connect -s 127.0.0.1 -u alice -r developer
swarm> msg hub hello!

# Terminal 3 — Bob joins
./swarm connect -s 127.0.0.1 -u bob -r developer
swarm> msg alice hey alice!
```

### Example 2: Task Management with Orchestrator

```bash
# Terminal 1 — Orchestrator server
./swarm serve -u hub --orchestrator

# Terminal 2 — Alice (developer)
./swarm connect -s 127.0.0.1 -u alice -r developer
swarm> task Fix login timeout role:developer
# Error: don't need to create tasks, orchestrator will manage

# Terminal 3 — Leader (orchestrator)
./swarm connect -s 127.0.0.1 -u leader --orchestrator -r orchestrator
swarm> task Fix login timeout role:developer
swarm> task Write API docs role:documenter
swarm> assign a1b2c3d4-... alice
swarm> assign e5f6a7b8-... bob

# Alice's terminal now shows:
# [SWARM] Task a1b2c3d4-... assigned to 'alice'
swarm> status Working on login timeout
swarm> done a1b2c3d4-...
```

### Example 3: Remote Tool Execution + Swarm File Transfer

```bash
# Alice runs tools and Swarm file transfers on Bob's machine
swarm> whoami bob
  [TOOL:whoami] OK: bob@bob-pc (windows)

swarm> drives bob
  [DRIVES] C:\, D:\, E:\

swarm> ls bob:D:/projects
  [DIR] D:/projects:
    d src (0 bytes)
    f README.md (2048 bytes)

swarm> cp bob D:/projects/main.rs D:/backup/main.rs.bak
  [TOOL:copy_file] OK: Copied 4096 bytes

# Swarm file transfer (first-class packets, not tool calls — no FTP needed)
swarm> send bob ./build.exe D:/deploy/build.exe
  [SWARM] Sending './build.exe' (2600000 bytes) → bob:D:/deploy/build.exe
  [SWARM] Sent 'D:/deploy/build.exe' — 2600000 bytes written

swarm> recv bob D:/projects/notes.md
  [SWARM] Received 'notes.md' — 1024 bytes (b64: 1368 chars)
  [SWARM] Decoded and saved as './notes.md' (1024 bytes)

swarm> rm bob /tmp/old-log.txt
  [SWARM] Delete '/tmp/old-log.txt': OK

swarm> mkdir bob D:/new-project/src
  [SWARM] Mkdir 'D:/new-project/src': OK
```

### Example 4: AI Harness via Pipe Mode

```bash
# Start the harness client
./swarm connect -s 127.0.0.1 -u ai-assistant --pipe

# Send commands via stdin:
echo '{"cmd":"channel","name":"ai-tasks","description":"AI agent task coordination"}' | ./swarm connect -s 127.0.0.1 -u ai --pipe
echo '{"cmd":"task","title":"Scan codebase for security issues","priority":"high","role":"reviewer"}' | ./swarm connect -s 127.0.0.1 -u ai --pipe
echo '{"cmd":"btc","target":"alice","tool_id":"0x02","args":{"path":"C:/projects/main.rs"}}' | ./swarm connect -s 127.0.0.1 -u ai --pipe
```

### Example 5: No-Orchestrator Self-Service

```bash
# No --orchestrator flag on any node

# Alice creates a task
swarm> task Add dark mode support role:developer

# (2 second grace period — everyone sees the notification)

# Bob claims it
swarm> take c3d4e5f6-...

# Carol tries to claim it too — gets error
swarm> take c3d4e5f6-...
# [ERROR] Tasks not found: [c3d4e5f6-...]
# (task was already assigned to Bob)
```

---

## Security

- **AES-256-GCM** on every packet — no plaintext ever
- 64-character hex key — possession of key = access
- Private by default — not discoverable without key and IP
- No built-in auth beyond the shared key
- **Remote execution is powerful** — `TOOL_CALL` and `run_command` can execute arbitrary code on remote machines via Swarm packets. Only trusted agents should join the swarm.

---

## License

MIT
