use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// All packet types in the Swarm protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum Packet {
    // --- Connection lifecycle ---
    /// Client announces itself to the swarm.
    Join(JoinPayload),
    /// Agent disconnects gracefully.
    Leave(LeavePayload),
    /// Server notifies all agents of swarm events.
    Notify(NotifyPayload),

    // --- Task management ---
    /// Propose a new task.
    CreateTask(CreateTaskPayload),
    /// Agent claims one or more pending tasks.
    TakeTask(TakeTaskPayload),
    /// Agent reports its current status.
    Status(StatusPayload),
    /// Agent notifies the swarm a task is finished.
    TaskComplete(TaskCompletePayload),

    // --- Messaging ---
    /// Direct or channel-based text message.
    Message(MessagePayload),

    // --- Channel management ---
    /// Create a named communication channel.
    CreateChannel(CreateChannelPayload),
    /// List all visible (non-hidden) channels.
    ListChannels(ListChannelsPayload),
    /// Join a channel by name.
    JoinChannel(JoinChannelPayload),
    /// Leave a channel by name.
    LeaveChannel(LeaveChannelPayload),
    /// Delete a channel (creator only).
    DeleteChannel(DeleteChannelPayload),
    /// Hide a channel from view without leaving.
    HideChannel(HideChannelPayload),

    // --- Remote file system ---
    /// Request list of mounted drives/volumes.
    ListDrives(ListDrivesPayload),
    /// List directories and files at a given path.
    ListDir(ListDirPayload),

    // --- Remote execution ---
    /// Ask an agent to perform an HTTP request.
    HttpRequest(HttpRequestPayload),
    /// Invoke a named tool on the target agent's machine.
    ToolCall(ToolCallPayload),

    // --- Task assignment ---
    /// Orchestrator assigns a task directly to an agent.
    AssignTask(AssignTaskPayload),
}

// ── Payloads ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JoinPayload {
    pub username: String,
    pub role: Option<String>,
    pub capabilities: Vec<String>,
    /// "git" or "single-host" — how the agent's workspace is set up.
    pub workspace_mode: Option<String>,
    /// Root directory of the project (meaningful in single-host mode).
    pub project_root: Option<String>,
    /// Whether this agent is an orchestrator
    #[serde(default)]
    pub is_orchestrator: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeavePayload {
    pub username: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event")]
pub enum NotifyPayload {
    AgentJoined {
        username: String,
        role: Option<String>,
        workspace_mode: Option<String>,
        project_root: Option<String>,
        #[serde(default)]
        is_orchestrator: bool,
    },
    AgentLeft {
        username: String,
        reason: Option<String>,
    },
    TaskCreated {
        task_id: Uuid,
        title: String,
        assigned_role: Option<String>,
    },
    TaskAssigned {
        task_id: Uuid,
        username: String,
    },
    TaskCompleted {
        task_id: Uuid,
        username: String,
        result: Option<String>,
        artifacts: Vec<String>,
    },
    ChannelCreated {
        channel_id: Uuid,
        name: String,
        created_by: String,
        visibility: String,
    },
    ChannelJoined {
        channel_name: String,
        username: String,
    },
    ChannelLeft {
        channel_name: String,
        username: String,
    },
    ChannelDeleted {
        channel_name: String,
        deleted_by: String,
    },
    StatusUpdate {
        username: String,
        status: String,
        task_id: Option<Uuid>,
        progress_pct: Option<u8>,
    },
    MessageReceived {
        from: String,
        to: String,
        body: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateTaskPayload {
    pub title: String,
    pub description: String,
    pub priority: TaskPriority,
    pub assigned_role: Option<String>,
    pub assign_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TakeTaskPayload {
    pub task_ids: Vec<Uuid>,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusPayload {
    pub username: String,
    pub status: AgentStatus,
    pub task_id: Option<Uuid>,
    pub progress_pct: Option<u8>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Idle,
    Working,
    Waiting,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskCompletePayload {
    pub task_id: Uuid,
    pub username: String,
    pub result: Option<String>,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessagePayload {
    pub from: String,
    pub to: MessageTarget,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "tag")]
pub enum MessageTarget {
    #[serde(rename = "direct")]
    Direct { username: String },
    #[serde(rename = "channel")]
    Channel { channel: String },
}

// ── Channel payloads ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateChannelPayload {
    pub name: String,
    pub created_by: String,
    pub description: Option<String>,
    /// "public" or "private"
    pub visibility: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListChannelsPayload {
    pub requester: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JoinChannelPayload {
    pub channel_name: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeaveChannelPayload {
    pub channel_name: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeleteChannelPayload {
    pub channel_name: String,
    pub requested_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HideChannelPayload {
    pub channel_name: String,
    pub username: String,
}

// ── P2P payloads ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListDrivesPayload {
    pub requester: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListDirPayload {
    pub requester: String,
    pub target: String,
    pub path: String,
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpRequestPayload {
    pub requester: String,
    pub target: String,
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub query_params: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    PATCH,
    HEAD,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallPayload {
    pub requester: String,
    pub target: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

// ── Task assignment ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssignTaskPayload {
    /// Who is doing the assigning (must be orchestrator).
    pub assigned_by: String,
    /// Which task to assign.
    pub task_id: Uuid,
    /// Who gets the task.
    pub assign_to: String,
}

// ── Response packets ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ResponsePacket {
    ListDrivesResult {
        requester: String,
        drives: Vec<String>,
    },
    ListDirResult {
        requester: String,
        path: String,
        entries: Vec<DirEntry>,
    },
    HttpRequestResult {
        requester: String,
        status_code: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    ToolCallResult {
        requester: String,
        tool_name: String,
        success: bool,
        output: String,
    },
    ChannelListResult {
        requester: String,
        channels: Vec<ChannelInfo>,
    },
    Error {
        requester: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelInfo {
    pub name: String,
    pub created_by: String,
    pub description: Option<String>,
    pub visibility: String,
    pub member_count: usize,
}

impl Packet {
    /// Returns a short description for logging.
    pub fn describe(&self) -> &'static str {
        match self {
            Packet::Join(_) => "JOIN",
            Packet::Leave(_) => "LEAVE",
            Packet::Notify(_) => "NOTIFY",
            Packet::CreateTask(_) => "CREATE_TASK",
            Packet::TakeTask(_) => "TAKE_TASK",
            Packet::Status(_) => "STATUS",
            Packet::Message(_) => "MESSAGE",
            Packet::CreateChannel(_) => "CREATE_CHANNEL",
            Packet::ListChannels(_) => "LIST_CHANNELS",
            Packet::JoinChannel(_) => "JOIN_CHANNEL",
            Packet::LeaveChannel(_) => "LEAVE_CHANNEL",
            Packet::DeleteChannel(_) => "DELETE_CHANNEL",
            Packet::HideChannel(_) => "HIDE_CHANNEL",
            Packet::ListDrives(_) => "LIST_DRIVES",
            Packet::ListDir(_) => "LIST_DIR",
            Packet::HttpRequest(_) => "HTTP_REQUEST",
            Packet::ToolCall(_) => "TOOL_CALL",
            Packet::TaskComplete(_) => "TASK_COMPLETE",
            Packet::AssignTask(_) => "ASSIGN_TASK",
        }
    }
}
