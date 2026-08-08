# Swarm

A peer-to-peer TCP protocol for AI agent orchestration. Think of it as a private, encrypted **Discord/Slack + IRC + FTP + SSH** — all wrapped in a single AES-256 encrypted channel.

Agents join a swarm, communicate via channels and direct messages, create and take tasks, browse each other's filesystems, issue HTTP requests and tool calls remotely — all encrypted by default.

## Quick Start

### Download (Windows)

Grab the pre-built binary from the repo root: [`swarm.exe`](./swarm.exe) (2.4 MB)

### Or Build from Source

```bash
cargo build --release
# Binary at target/release/swarm (or swarm.exe on Windows)
```

### Generate a Key

```bash
./swarm gen-key              # creates swarm.key
./swarm gen-key -o my.key    # custom path
```

Share `swarm.key` with every agent that should join the swarm. All traffic is encrypted with this key.

### Start a Server (Hub)

```bash
./swarm serve                          # listen on 0.0.0.0:6996
./swarm serve -p 9000                  # custom port
./swarm serve -u my-server -r admin    # username and role
```

### Connect as a Client Agent

```bash
./swarm connect -s 192.168.1.10 -u alice       # join swarm
./swarm connect -s 192.168.1.10 -u bob -r developer
./swarm connect -s 192.168.1.10 -u host -r developer --workspace-mode single-host --project-root /projects/myapp
```

## CLI Commands

Once connected, type commands at the `swarm>` prompt:

| Command | Description |
|---|---|
| `msg <user> <body>` | Direct message to an agent |
| `msg #<channel> <body>` | Message to a channel |
| `channel <name> [desc] [--private]` | Create a channel |
| `channels` | List visible channels |
| `join <name>` | Join a channel |
| `leave <name>` | Leave a channel |
| `delete-channel <name>` | Delete a channel (creator only) |
| `hide <name>` | Hide a channel from your list |
| `task <title> [role:<r>]` | Create a task |
| `take <task_id>` | Claim a pending task |
| `done <task_id>` | Mark a task complete |
| `status <msg>` | Update your status |
| `drives <target>` | List drives on a remote agent |
| `ls <target>:<path>` | List directory on a remote agent |
| `http <t> <method> <url>` | HTTP request via remote agent |
| `tool <t> <name> [args]` | Invoke tool on remote agent |
| `help` | Show this help |
| `quit` | Leave the swarm |

## Architecture

```
                    TCP :6996 (AES-256-GCM encrypted)
┌─────────┐     ┌──────────┐     ┌─────────┐
│ Agent A │────▶│  SERVER  │◀────│ Agent B │
│ (client)│◀────│  (hub)   │────▶│ (client)│
└─────────┘     └──────────┘     └─────────┘
                      │
                      │ Broadcast notifications
                      │ P2P routing (ListDir, HttpRequest, ToolCall)
                      ▼
                ┌─────────┐
                │ Agent C │
                │ (client)│
                └─────────┘
```

- **One node acts as the server** (hub), others connect as clients
- **Server routes everything**: messages, P2P requests, notifications
- **All traffic is encrypted** with the shared AES-256 key from `swarm.key`

## Packet Types

| # | Type | Purpose |
|---|---|---|
| 1 | `JOIN` | Agent joins the swarm |
| 2 | `LEAVE` | Agent disconnects |
| 3 | `NOTIFY` | Server broadcasts events |
| 4 | `CREATE_TASK` | Propose a task |
| 5 | `TAKE_TASK` | Claim a task |
| 6 | `STATUS` | Report status |
| 7 | `MESSAGE` | Text message (direct or channel) |
| 8 | `CREATE_CHANNEL` | Create a channel |
| 9 | `LIST_DRIVES` | List remote drives |
| 10 | `LIST_DIR` | List remote directory |
| 11 | `HTTP_REQUEST` | Remote HTTP call |
| 12 | `TOOL_CALL` | Remote tool execution |
| 13 | `TASK_COMPLETE` | Task finished |
| 14 | `LIST_CHANNELS` | List visible channels |
| 15 | `JOIN_CHANNEL` | Join a channel |
| 16 | `LEAVE_CHANNEL` | Leave a channel |
| 17 | `DELETE_CHANNEL` | Delete a channel |
| 18 | `HIDE_CHANNEL` | Hide channel from view |

## Workspace Modes

- **Git mode** (default) — Each agent has the same repo cloned locally
- **Single-host mode** — One agent hosts the project folder; others operate on it remotely via `LIST_DIR`, `TOOL_CALL`, `HTTP_REQUEST`

## Security

- **AES-256-GCM** encryption on every packet
- 64-character hex key from `swarm.key`
- No traffic is ever sent in plaintext
- Trust model: possession of the key = access

## Project Structure

```
src/
├── main.rs       # CLI entry point (clap)
├── server.rs     # Server mode — listen, route, broadcast
├── client.rs     # Client mode — connect, interactive CLI
├── swarm.rs      # Swarm state — agents, tasks, channels, routing
├── packet.rs     # All 18 packet types + responses
├── crypto.rs     # AES-256-GCM encryption
├── protocol.rs   # Length-prefixed frame codec
├── agent.rs      # Agent identity + roles
├── channel.rs    # Channel struct + visibility
└── task.rs       # Task struct + status
```

## License

MIT
