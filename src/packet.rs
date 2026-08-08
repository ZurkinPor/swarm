use uuid::Uuid;

// ── Binary wire format ──────────────────────────────────────
//
// Every packet (after AES-256-GCM decryption):
//   Byte 0:       packet_type (u8)
//   Bytes 1-4:    payload_length (u32 BE)
//   Bytes 5..:    payload (type-specific binary fields)
//
// Primitives used within payloads:
//   u8, u16 BE, u32 BE, u64 BE  — integers
//   str8  = u8 len + UTF-8 bytes (short strings < 256)
//   str16 = u16 len + UTF-8 bytes (strings up to 65535)
//   bytes = u32 len + raw bytes (file content, binary blobs)
//   json  = u32 len + UTF-8 JSON string (tool args, notify events)
//   uuid  = 16 raw bytes
//   flag  = u8 (0 or 1)
//   opt_str16 = flag + str16 if flag==1

// ── Binary reader/writer helpers ─────────────────────────────

struct BinWriter(Vec<u8>);
impl BinWriter {
    fn new() -> Self { Self(Vec::new()) }
    fn u8(&mut self, v: u8) { self.0.push(v); }
    fn u16(&mut self, v: u16) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn flag(&mut self, v: bool) { self.u8(if v { 1 } else { 0 }); }
    fn str8(&mut self, s: &str) { let b = s.as_bytes(); assert!(b.len() <= 255); self.u8(b.len() as u8); self.0.extend_from_slice(b); }
    fn str16(&mut self, s: &str) { let b = s.as_bytes(); assert!(b.len() <= 65535); self.u16(b.len() as u16); self.0.extend_from_slice(b); }
    fn opt_str16(&mut self, s: &Option<String>) { match s { Some(v) => { self.flag(true); self.str16(v); } None => { self.flag(false); } } }
    fn bytes(&mut self, data: &[u8]) { self.u32(data.len() as u32); self.0.extend_from_slice(data); }
    fn json(&mut self, v: &serde_json::Value) { let s = serde_json::to_string(v).unwrap_or_default(); let b = s.as_bytes(); self.u32(b.len() as u32); self.0.extend_from_slice(b); }
    fn uuid(&mut self, id: &Uuid) { self.0.extend_from_slice(id.as_bytes()); }
    fn finish(self) -> Vec<u8> { self.0 }
}

struct BinReader<'a> { data: &'a [u8], pos: usize }
impl<'a> BinReader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    fn u8(&mut self) -> Result<u8, &'static str> { self.ensure(1)?; let v = self.data[self.pos]; self.pos += 1; Ok(v) }
    fn u16(&mut self) -> Result<u16, &'static str> { self.ensure(2)?; let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos+1]]); self.pos += 2; Ok(v) }
    fn u32(&mut self) -> Result<u32, &'static str> { self.ensure(4)?; let v = u32::from_be_bytes([self.data[self.pos], self.data[self.pos+1], self.data[self.pos+2], self.data[self.pos+3]]); self.pos += 4; Ok(v) }
    fn u64(&mut self) -> Result<u64, &'static str> { self.ensure(8)?; let v = u64::from_be_bytes([self.data[self.pos], self.data[self.pos+1], self.data[self.pos+2], self.data[self.pos+3], self.data[self.pos+4], self.data[self.pos+5], self.data[self.pos+6], self.data[self.pos+7]]); self.pos += 8; Ok(v) }
    fn flag(&mut self) -> Result<bool, &'static str> { self.u8().map(|v| v != 0) }
    fn str8(&mut self) -> Result<String, &'static str> { let len = self.u8()? as usize; self.ensure(len)?; let s = String::from_utf8_lossy(&self.data[self.pos..self.pos+len]).into_owned(); self.pos += len; Ok(s) }
    fn str16(&mut self) -> Result<String, &'static str> { let len = self.u16()? as usize; self.ensure(len)?; let s = String::from_utf8_lossy(&self.data[self.pos..self.pos+len]).into_owned(); self.pos += len; Ok(s) }
    fn opt_str16(&mut self) -> Result<Option<String>, &'static str> { if self.flag()? { Ok(Some(self.str16()?)) } else { Ok(None) } }
    fn bytes(&mut self) -> Result<&'a [u8], &'static str> { let len = self.u32()? as usize; self.ensure(len)?; let slice = &self.data[self.pos..self.pos+len]; self.pos += len; Ok(slice) }
    fn json(&mut self) -> Result<serde_json::Value, &'static str> { let len = self.u32()? as usize; self.ensure(len)?; let s = std::str::from_utf8(&self.data[self.pos..self.pos+len]).map_err(|_| "invalid UTF-8 in JSON")?; self.pos += len; serde_json::from_str(s).map_err(|_| "invalid JSON") }
    fn uuid(&mut self) -> Result<Uuid, &'static str> { self.ensure(16)?; let bytes: [u8; 16] = self.data[self.pos..self.pos+16].try_into().unwrap(); self.pos += 16; Ok(Uuid::from_bytes(bytes)) }
    fn ensure(&self, n: usize) -> Result<(), &'static str> { if self.pos + n > self.data.len() { Err("unexpected end of binary packet") } else { Ok(()) } }
}

// ── Packet type IDs ───────────────────────────────────────────

impl Packet {
    fn type_id(&self) -> u8 {
        match self {
            Packet::Join(_) => 1,
            Packet::Leave(_) => 2,
            Packet::Notify(_) => 3,
            Packet::CreateTask(_) => 4,
            Packet::TakeTask(_) => 5,
            Packet::Status(_) => 6,
            Packet::Message(_) => 7,
            Packet::CreateChannel(_) => 8,
            Packet::ListDrives(_) => 9,
            Packet::ListDir(_) => 10,
            Packet::HttpRequest(_) => 11,
            Packet::ToolCall(_) => 12,
            Packet::TaskComplete(_) => 13,
            Packet::ListChannels(_) => 14,
            Packet::JoinChannel(_) => 15,
            Packet::LeaveChannel(_) => 16,
            Packet::DeleteChannel(_) => 17,
            Packet::HideChannel(_) => 18,
            Packet::AssignTask(_) => 19,
            Packet::SendFile(_) => 20,
            Packet::ReceiveFile(_) => 21,
            Packet::DeleteFile(_) => 22,
            Packet::MakeDir(_) => 23,
        }
    }

    fn from_type_id(id: u8, r: &mut BinReader) -> Result<Packet, &'static str> {
        match id {
            1 => Ok(Packet::Join(JoinPayload::decode(r)?)),
            2 => Ok(Packet::Leave(LeavePayload::decode(r)?)),
            3 => Ok(Packet::Notify(NotifyPayload::decode(r)?)),
            4 => Ok(Packet::CreateTask(CreateTaskPayload::decode(r)?)),
            5 => Ok(Packet::TakeTask(TakeTaskPayload::decode(r)?)),
            6 => Ok(Packet::Status(StatusPayload::decode(r)?)),
            7 => Ok(Packet::Message(MessagePayload::decode(r)?)),
            8 => Ok(Packet::CreateChannel(CreateChannelPayload::decode(r)?)),
            9 => Ok(Packet::ListDrives(ListDrivesPayload::decode(r)?)),
            10 => Ok(Packet::ListDir(ListDirPayload::decode(r)?)),
            11 => Ok(Packet::HttpRequest(HttpRequestPayload::decode(r)?)),
            12 => Ok(Packet::ToolCall(ToolCallPayload::decode(r)?)),
            13 => Ok(Packet::TaskComplete(TaskCompletePayload::decode(r)?)),
            14 => Ok(Packet::ListChannels(ListChannelsPayload::decode(r)?)),
            15 => Ok(Packet::JoinChannel(JoinChannelPayload::decode(r)?)),
            16 => Ok(Packet::LeaveChannel(LeaveChannelPayload::decode(r)?)),
            17 => Ok(Packet::DeleteChannel(DeleteChannelPayload::decode(r)?)),
            18 => Ok(Packet::HideChannel(HideChannelPayload::decode(r)?)),
            19 => Ok(Packet::AssignTask(AssignTaskPayload::decode(r)?)),
            20 => Ok(Packet::SendFile(SendFilePayload::decode(r)?)),
            21 => Ok(Packet::ReceiveFile(ReceiveFilePayload::decode(r)?)),
            22 => Ok(Packet::DeleteFile(DeleteFilePayload::decode(r)?)),
            23 => Ok(Packet::MakeDir(MakeDirPayload::decode(r)?)),
            _ => Err("unknown packet type"),
        }
    }

    /// Full binary encode: [type: u8][payload_len: u32 BE][payload bytes]
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.encode_payload();
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(self.type_id());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Decode from binary bytes. Returns None if the data doesn't look like a binary packet.
    pub fn decode(data: &[u8]) -> Result<Packet, &'static str> {
        if data.is_empty() { return Err("empty packet"); }
        let id = data[0];
        if data.len() < 5 { return Err("packet too short for header"); }
        let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + payload_len { return Err("payload truncated"); }
        let mut r = BinReader::new(&data[5..5 + payload_len]);
        Self::from_type_id(id, &mut r)
    }

    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Packet::Join(p) => p.encode(),
            Packet::Leave(p) => p.encode(),
            Packet::Notify(p) => p.encode(),
            Packet::CreateTask(p) => p.encode(),
            Packet::TakeTask(p) => p.encode(),
            Packet::Status(p) => p.encode(),
            Packet::Message(p) => p.encode(),
            Packet::CreateChannel(p) => p.encode(),
            Packet::ListChannels(p) => p.encode(),
            Packet::JoinChannel(p) => p.encode(),
            Packet::LeaveChannel(p) => p.encode(),
            Packet::DeleteChannel(p) => p.encode(),
            Packet::HideChannel(p) => p.encode(),
            Packet::ListDrives(p) => p.encode(),
            Packet::ListDir(p) => p.encode(),
            Packet::HttpRequest(p) => p.encode(),
            Packet::ToolCall(p) => p.encode(),
            Packet::TaskComplete(p) => p.encode(),
            Packet::AssignTask(p) => p.encode(),
            Packet::SendFile(p) => p.encode(),
            Packet::ReceiveFile(p) => p.encode(),
            Packet::DeleteFile(p) => p.encode(),
            Packet::MakeDir(p) => p.encode(),
        }
    }
}

// ── All packet types ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Join(JoinPayload),
    Leave(LeavePayload),
    Notify(NotifyPayload),
    CreateTask(CreateTaskPayload),
    TakeTask(TakeTaskPayload),
    Status(StatusPayload),
    Message(MessagePayload),
    CreateChannel(CreateChannelPayload),
    ListChannels(ListChannelsPayload),
    JoinChannel(JoinChannelPayload),
    LeaveChannel(LeaveChannelPayload),
    DeleteChannel(DeleteChannelPayload),
    HideChannel(HideChannelPayload),
    ListDrives(ListDrivesPayload),
    ListDir(ListDirPayload),
    HttpRequest(HttpRequestPayload),
    ToolCall(ToolCallPayload),
    TaskComplete(TaskCompletePayload),
    AssignTask(AssignTaskPayload),
    SendFile(SendFilePayload),
    ReceiveFile(ReceiveFilePayload),
    DeleteFile(DeleteFilePayload),
    MakeDir(MakeDirPayload),
}

// ── Payload structs with encode/decode ───────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct JoinPayload {
    pub username: String,
    pub role: Option<String>,
    pub capabilities: Vec<String>,
    pub workspace_mode: Option<String>,
    pub project_root: Option<String>,
    pub is_orchestrator: bool,
}
impl JoinPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.flag(self.is_orchestrator); w.str8(&self.username); w.opt_str16(&self.role); w.u8(self.capabilities.len() as u8); for c in &self.capabilities { w.str16(c); } w.opt_str16(&self.workspace_mode); w.opt_str16(&self.project_root); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let is_orchestrator = r.flag()?; let username = r.str8()?; let role = r.opt_str16()?; let ncap = r.u8()? as usize; let mut capabilities = Vec::with_capacity(ncap); for _ in 0..ncap { capabilities.push(r.str16()?); } let workspace_mode = r.opt_str16()?; let project_root = r.opt_str16()?; Ok(Self { username, role, capabilities, workspace_mode, project_root, is_orchestrator }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeavePayload { pub username: String, pub reason: Option<String> }
impl LeavePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.username); w.opt_str16(&self.reason); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { username: r.str8()?, reason: r.opt_str16()? }) }
}

// Notify payloads embed their event data as JSON (complex nested structure)
#[derive(Debug, Clone, PartialEq)]
pub enum NotifyPayload {
    AgentJoined { username: String, role: Option<String>, workspace_mode: Option<String>, project_root: Option<String>, is_orchestrator: bool },
    AgentLeft { username: String, reason: Option<String> },
    TaskCreated { task_id: Uuid, title: String, assigned_role: Option<String> },
    TaskAssigned { task_id: Uuid, username: String },
    TaskCompleted { task_id: Uuid, username: String, result: Option<String>, artifacts: Vec<String> },
    ChannelCreated { channel_id: Uuid, name: String, created_by: String, visibility: String },
    ChannelJoined { channel_name: String, username: String },
    ChannelLeft { channel_name: String, username: String },
    ChannelDeleted { channel_name: String, deleted_by: String },
    StatusUpdate { username: String, status: String, task_id: Option<Uuid>, progress_pct: Option<u8> },
    MessageReceived { from: String, to: String, body: String },
}
impl NotifyPayload {
    fn event_id(&self) -> u8 {
        match self {
            NotifyPayload::AgentJoined { .. } => 0,
            NotifyPayload::AgentLeft { .. } => 1,
            NotifyPayload::TaskCreated { .. } => 2,
            NotifyPayload::TaskAssigned { .. } => 3,
            NotifyPayload::TaskCompleted { .. } => 4,
            NotifyPayload::ChannelCreated { .. } => 5,
            NotifyPayload::ChannelJoined { .. } => 6,
            NotifyPayload::ChannelLeft { .. } => 7,
            NotifyPayload::ChannelDeleted { .. } => 8,
            NotifyPayload::StatusUpdate { .. } => 9,
            NotifyPayload::MessageReceived { .. } => 10,
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut w = BinWriter::new();
        w.u8(self.event_id());
        match self {
            NotifyPayload::AgentJoined { username, role, workspace_mode, project_root, is_orchestrator } => {
                w.flag(*is_orchestrator); w.str8(username); w.opt_str16(role); w.opt_str16(workspace_mode); w.opt_str16(project_root);
            }
            NotifyPayload::AgentLeft { username, reason } => { w.str8(username); w.opt_str16(reason); }
            NotifyPayload::TaskCreated { task_id, title, assigned_role } => { w.uuid(task_id); w.str16(title); w.opt_str16(assigned_role); }
            NotifyPayload::TaskAssigned { task_id, username } => { w.uuid(task_id); w.str8(username); }
            NotifyPayload::TaskCompleted { task_id, username, result, artifacts } => {
                w.uuid(task_id); w.str8(username); w.opt_str16(result);
                w.u8(artifacts.len() as u8); for a in artifacts { w.str16(a); }
            }
            NotifyPayload::ChannelCreated { channel_id, name, created_by, visibility } => { w.uuid(channel_id); w.str8(name); w.str8(created_by); w.str8(visibility); }
            NotifyPayload::ChannelJoined { channel_name, username } => { w.str8(channel_name); w.str8(username); }
            NotifyPayload::ChannelLeft { channel_name, username } => { w.str8(channel_name); w.str8(username); }
            NotifyPayload::ChannelDeleted { channel_name, deleted_by } => { w.str8(channel_name); w.str8(deleted_by); }
            NotifyPayload::StatusUpdate { username, status, task_id, progress_pct } => {
                w.str8(username); w.str8(status);
                w.flag(task_id.is_some()); if let Some(tid) = task_id { w.uuid(tid); }
                w.flag(progress_pct.is_some()); if let Some(pct) = progress_pct { w.u8(*pct); }
            }
            NotifyPayload::MessageReceived { from, to, body } => { w.str8(from); w.str8(to); w.str16(body); }
        }
        w.finish()
    }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> {
        let event = r.u8()?;
        match event {
            0 => Ok(NotifyPayload::AgentJoined { is_orchestrator: r.flag()?, username: r.str8()?, role: r.opt_str16()?, workspace_mode: r.opt_str16()?, project_root: r.opt_str16()? }),
            1 => Ok(NotifyPayload::AgentLeft { username: r.str8()?, reason: r.opt_str16()? }),
            2 => Ok(NotifyPayload::TaskCreated { task_id: r.uuid()?, title: r.str16()?, assigned_role: r.opt_str16()? }),
            3 => Ok(NotifyPayload::TaskAssigned { task_id: r.uuid()?, username: r.str8()? }),
            4 => { let task_id = r.uuid()?; let username = r.str8()?; let result = r.opt_str16()?; let n = r.u8()? as usize; let mut artifacts = Vec::with_capacity(n); for _ in 0..n { artifacts.push(r.str16()?); } Ok(NotifyPayload::TaskCompleted { task_id, username, result, artifacts }) }
            5 => Ok(NotifyPayload::ChannelCreated { channel_id: r.uuid()?, name: r.str8()?, created_by: r.str8()?, visibility: r.str8()? }),
            6 => Ok(NotifyPayload::ChannelJoined { channel_name: r.str8()?, username: r.str8()? }),
            7 => Ok(NotifyPayload::ChannelLeft { channel_name: r.str8()?, username: r.str8()? }),
            8 => Ok(NotifyPayload::ChannelDeleted { channel_name: r.str8()?, deleted_by: r.str8()? }),
            9 => { let username = r.str8()?; let status = r.str8()?; let task_id = if r.flag()? { Some(r.uuid()?) } else { None }; let progress_pct = if r.flag()? { Some(r.u8()?) } else { None }; Ok(NotifyPayload::StatusUpdate { username, status, task_id, progress_pct }) }
            10 => Ok(NotifyPayload::MessageReceived { from: r.str8()?, to: r.str8()?, body: r.str16()? }),
            _ => Err("unknown notify event"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateTaskPayload { pub title: String, pub description: String, pub priority: TaskPriority, pub assigned_role: Option<String>, pub assign_to: Option<String> }
impl CreateTaskPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str16(&self.title); w.str16(&self.description); w.u8(self.priority.to_u8()); w.opt_str16(&self.assigned_role); w.opt_str16(&self.assign_to); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { title: r.str16()?, description: r.str16()?, priority: TaskPriority::from_u8(r.u8()?)?, assigned_role: r.opt_str16()?, assign_to: r.opt_str16()? }) }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TaskPriority { Low, Normal, High, Critical }
impl TaskPriority {
    fn to_u8(&self) -> u8 { match self { TaskPriority::Low => 0, TaskPriority::Normal => 1, TaskPriority::High => 2, TaskPriority::Critical => 3 } }
    fn from_u8(v: u8) -> Result<Self, &'static str> { match v { 0 => Ok(TaskPriority::Low), 1 => Ok(TaskPriority::Normal), 2 => Ok(TaskPriority::High), 3 => Ok(TaskPriority::Critical), _ => Err("invalid priority") } }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TakeTaskPayload { pub task_ids: Vec<Uuid>, pub username: String }
impl TakeTaskPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.username); w.u8(self.task_ids.len() as u8); for id in &self.task_ids { w.uuid(id); } w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let username = r.str8()?; let n = r.u8()? as usize; let mut task_ids = Vec::with_capacity(n); for _ in 0..n { task_ids.push(r.uuid()?); } Ok(Self { task_ids, username }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusPayload { pub username: String, pub status: AgentStatus, pub task_id: Option<Uuid>, pub progress_pct: Option<u8>, pub message: Option<String> }
impl StatusPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.username); w.u8(self.status.to_u8()); w.flag(self.task_id.is_some()); if let Some(t) = &self.task_id { w.uuid(t); } w.flag(self.progress_pct.is_some()); if let Some(p) = self.progress_pct { w.u8(p); } w.opt_str16(&self.message); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let username = r.str8()?; let status = AgentStatus::from_u8(r.u8()?)?; let task_id = if r.flag()? { Some(r.uuid()?) } else { None }; let progress_pct = if r.flag()? { Some(r.u8()?) } else { None }; let message = r.opt_str16()?; Ok(Self { username, status, task_id, progress_pct, message }) }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AgentStatus { Idle, Working, Waiting, Error }
impl AgentStatus {
    fn to_u8(&self) -> u8 { match self { AgentStatus::Idle => 0, AgentStatus::Working => 1, AgentStatus::Waiting => 2, AgentStatus::Error => 3 } }
    fn from_u8(v: u8) -> Result<Self, &'static str> { match v { 0 => Ok(AgentStatus::Idle), 1 => Ok(AgentStatus::Working), 2 => Ok(AgentStatus::Waiting), 3 => Ok(AgentStatus::Error), _ => Err("invalid status") } }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskCompletePayload { pub task_id: Uuid, pub username: String, pub result: Option<String>, pub artifacts: Vec<String> }
impl TaskCompletePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.uuid(&self.task_id); w.str8(&self.username); w.opt_str16(&self.result); w.u8(self.artifacts.len() as u8); for a in &self.artifacts { w.str16(a); } w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let task_id = r.uuid()?; let username = r.str8()?; let result = r.opt_str16()?; let n = r.u8()? as usize; let mut artifacts = Vec::with_capacity(n); for _ in 0..n { artifacts.push(r.str16()?); } Ok(Self { task_id, username, result, artifacts }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessagePayload { pub from: String, pub to: MessageTarget, pub body: String }
impl MessagePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.from); match &self.to { MessageTarget::Direct { username } => { w.u8(0); w.str8(username); } MessageTarget::Channel { channel } => { w.u8(1); w.str8(channel); } } w.str16(&self.body); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let from = r.str8()?; let target_type = r.u8()?; let to = if target_type == 0 { MessageTarget::Direct { username: r.str8()? } } else { MessageTarget::Channel { channel: r.str8()? } }; let body = r.str16()?; Ok(Self { from, to, body }) }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MessageTarget { Direct { username: String }, Channel { channel: String } }

#[derive(Debug, Clone, PartialEq)]
pub struct CreateChannelPayload { pub name: String, pub created_by: String, pub description: Option<String>, pub visibility: Option<String> }
impl CreateChannelPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.name); w.str8(&self.created_by); w.opt_str16(&self.description); w.str8(self.visibility.as_deref().unwrap_or("public")); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { name: r.str8()?, created_by: r.str8()?, description: r.opt_str16()?, visibility: Some(r.str8()?) }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListChannelsPayload { pub requester: String }
impl ListChannelsPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JoinChannelPayload { pub channel_name: String, pub username: String }
impl JoinChannelPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.channel_name); w.str8(&self.username); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { channel_name: r.str8()?, username: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeaveChannelPayload { pub channel_name: String, pub username: String }
impl LeaveChannelPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.channel_name); w.str8(&self.username); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { channel_name: r.str8()?, username: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteChannelPayload { pub channel_name: String, pub requested_by: String }
impl DeleteChannelPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.channel_name); w.str8(&self.requested_by); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { channel_name: r.str8()?, requested_by: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HideChannelPayload { pub channel_name: String, pub username: String }
impl HideChannelPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.channel_name); w.str8(&self.username); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { channel_name: r.str8()?, username: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListDrivesPayload { pub requester: String, pub target: String }
impl ListDrivesPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListDirPayload { pub requester: String, pub target: String, pub path: String, pub recursive: bool }
impl ListDirPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str16(&self.path); w.flag(self.recursive); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()?, path: r.str16()?, recursive: r.flag()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequestPayload { pub requester: String, pub target: String, pub method: HttpMethod, pub url: String, pub headers: Vec<(String, String)>, pub body: Option<String>, pub query_params: Vec<(String, String)> }
impl HttpRequestPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.u8(self.method.to_u8()); w.str16(&self.url); w.u8(self.headers.len() as u8); for (k, v) in &self.headers { w.str16(k); w.str16(v); } w.opt_str16(&self.body); w.u8(self.query_params.len() as u8); for (k, v) in &self.query_params { w.str16(k); w.str16(v); } w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let requester = r.str8()?; let target = r.str8()?; let method = HttpMethod::from_u8(r.u8()?)?; let url = r.str16()?; let nh = r.u8()? as usize; let mut headers = Vec::with_capacity(nh); for _ in 0..nh { headers.push((r.str16()?, r.str16()?)); } let body = r.opt_str16()?; let nq = r.u8()? as usize; let mut query_params = Vec::with_capacity(nq); for _ in 0..nq { query_params.push((r.str16()?, r.str16()?)); } Ok(Self { requester, target, method, url, headers, body, query_params }) }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod { GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD }
impl HttpMethod {
    fn to_u8(&self) -> u8 { match self { HttpMethod::GET => 0, HttpMethod::POST => 1, HttpMethod::PUT => 2, HttpMethod::DELETE => 3, HttpMethod::OPTIONS => 4, HttpMethod::PATCH => 5, HttpMethod::HEAD => 6 } }
    fn from_u8(v: u8) -> Result<Self, &'static str> { match v { 0 => Ok(HttpMethod::GET), 1 => Ok(HttpMethod::POST), 2 => Ok(HttpMethod::PUT), 3 => Ok(HttpMethod::DELETE), 4 => Ok(HttpMethod::OPTIONS), 5 => Ok(HttpMethod::PATCH), 6 => Ok(HttpMethod::HEAD), _ => Err("invalid HTTP method") } }
}

// ToolCall embeds arguments as JSON (complex nested structure)
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallPayload { pub requester: String, pub target: String, pub tool_name: String, pub arguments: serde_json::Value }
impl ToolCallPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str8(&self.tool_name); w.json(&self.arguments); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()?, tool_name: r.str8()?, arguments: r.json()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssignTaskPayload { pub assigned_by: String, pub task_id: Uuid, pub assign_to: String }
impl AssignTaskPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.assigned_by); w.uuid(&self.task_id); w.str8(&self.assign_to); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { assigned_by: r.str8()?, task_id: r.uuid()?, assign_to: r.str8()? }) }
}

// ── Swarm File Transfer payloads (raw bytes, NOT base64) ─────

#[derive(Debug, Clone, PartialEq)]
pub struct SendFilePayload {
    pub requester: String,
    pub target: String,
    pub path: String,
    /// Raw file content (no base64 encoding — just the bytes)
    pub content: Vec<u8>,
    pub overwrite: bool,
}
impl SendFilePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str16(&self.path); w.flag(self.overwrite); w.bytes(&self.content); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()?, path: r.str16()?, overwrite: r.flag()?, content: r.bytes()?.to_vec() }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceiveFilePayload { pub requester: String, pub target: String, pub path: String, pub max_bytes: Option<u64> }
impl ReceiveFilePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str16(&self.path); w.flag(self.max_bytes.is_some()); if let Some(mb) = self.max_bytes { w.u64(mb); } w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { let requester = r.str8()?; let target = r.str8()?; let path = r.str16()?; let max_bytes = if r.flag()? { Some(r.u64()?) } else { None }; Ok(Self { requester, target, path, max_bytes }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteFilePayload { pub requester: String, pub target: String, pub path: String }
impl DeleteFilePayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str16(&self.path); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()?, path: r.str16()? }) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MakeDirPayload { pub requester: String, pub target: String, pub path: String }
impl MakeDirPayload {
    fn encode(&self) -> Vec<u8> { let mut w = BinWriter::new(); w.str8(&self.requester); w.str8(&self.target); w.str16(&self.path); w.finish() }
    fn decode(r: &mut BinReader) -> Result<Self, &'static str> { Ok(Self { requester: r.str8()?, target: r.str8()?, path: r.str16()? }) }
}

// ── Response packets (still use serde for internal routing, but now with binary wire format too) ──

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ResponsePacket {
    ListDrivesResult { requester: String, drives: Vec<String> },
    ListDirResult { requester: String, path: String, entries: Vec<DirEntry> },
    HttpRequestResult { requester: String, status_code: u16, headers: Vec<(String, String)>, body: String },
    ToolCallResult { requester: String, tool_name: String, success: bool, output: String },
    ChannelListResult { requester: String, channels: Vec<ChannelInfo> },
    Error { requester: String, message: String },
    SendFileResult { requester: String, path: String, bytes_written: u64 },
    ReceiveFileResult { requester: String, path: String, content: Vec<u8>, size_bytes: u64 },
    DeleteFileResult { requester: String, path: String, deleted: bool },
    MakeDirResult { requester: String, path: String, created: bool },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DirEntry { pub name: String, pub is_dir: bool, pub size_bytes: u64 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ChannelInfo { pub name: String, pub created_by: String, pub description: Option<String>, pub visibility: String, pub member_count: usize }

impl ResponsePacket {
    /// Binary encode for responses (kept JSON for now since responses are internal server↔client routing).
    /// The main Packet type uses binary; ResponsePacket can migrate later.
    pub fn encode(&self) -> Vec<u8> { serde_json::to_vec(self).unwrap_or_default() }
    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> { serde_json::from_slice(data) }
}

impl Packet {
    pub fn describe(&self) -> &'static str {
        match self {
            Packet::Join(_) => "JOIN", Packet::Leave(_) => "LEAVE", Packet::Notify(_) => "NOTIFY",
            Packet::CreateTask(_) => "CREATE_TASK", Packet::TakeTask(_) => "TAKE_TASK", Packet::Status(_) => "STATUS",
            Packet::Message(_) => "MESSAGE", Packet::CreateChannel(_) => "CREATE_CHANNEL", Packet::ListChannels(_) => "LIST_CHANNELS",
            Packet::JoinChannel(_) => "JOIN_CHANNEL", Packet::LeaveChannel(_) => "LEAVE_CHANNEL",
            Packet::DeleteChannel(_) => "DELETE_CHANNEL", Packet::HideChannel(_) => "HIDE_CHANNEL",
            Packet::ListDrives(_) => "LIST_DRIVES", Packet::ListDir(_) => "LIST_DIR", Packet::HttpRequest(_) => "HTTP_REQUEST",
            Packet::ToolCall(_) => "TOOL_CALL", Packet::TaskComplete(_) => "TASK_COMPLETE", Packet::AssignTask(_) => "ASSIGN_TASK",
            Packet::SendFile(_) => "SEND_FILE", Packet::ReceiveFile(_) => "RECEIVE_FILE",
            Packet::DeleteFile(_) => "DELETE_FILE", Packet::MakeDir(_) => "MAKE_DIR",
        }
    }
}
