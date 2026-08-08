use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::agent::Agent;
use crate::channel::{Channel, ChannelVisibility};
use crate::packet::{AgentStatus, ChannelInfo, NotifyPayload, StatusPayload, TaskPriority};
use crate::task::{Task, TaskStatus};

/// Handle for sending encrypted frames to a specific client.
#[derive(Clone)]
pub struct ConnectionHandle {
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// A message queued for offline delivery.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub from: String,
    pub body: String,
}

/// Central swarm state shared by the server.
pub struct SwarmState {
    /// Connected agents by username.
    pub agents: HashMap<String, Agent>,
    /// All tasks by ID.
    pub tasks: HashMap<Uuid, Task>,
    /// All channels by name.
    pub channels: HashMap<String, Channel>,
    /// Agent statuses by username.
    pub statuses: HashMap<String, StatusPayload>,
    /// Broadcast channel for notifying all connected clients.
    pub broadcast_tx: broadcast::Sender<NotifyPayload>,
    /// Per-client connection handles for P2P routing.
    pub connections: HashMap<String, ConnectionHandle>,
    /// Offline message queue: username → list of queued messages.
    pub mailbox: HashMap<String, Vec<QueuedMessage>>,
    /// Task creation timestamps for collision-avoidance grace period.
    task_creation_times: HashMap<Uuid, Instant>,
    /// Seconds to wait after task creation before anyone can take it
    /// (lets all agents see the notification first).
    pub task_grace_secs: u64,
    /// All known project names collected from agent JOINs.
    pub known_projects: HashSet<String>,
}

impl SwarmState {
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(256);
        Self {
            agents: HashMap::new(),
            tasks: HashMap::new(),
            channels: HashMap::new(),
            statuses: HashMap::new(),
            broadcast_tx,
            connections: HashMap::new(),
            mailbox: HashMap::new(),
            task_creation_times: HashMap::new(),
            task_grace_secs: 2,
            known_projects: HashSet::new(),
        }
    }

    // ── Agent management ──

    pub fn add_agent(&mut self, agent: Agent, conn: ConnectionHandle) {
        self.broadcast_tx
            .send(NotifyPayload::AgentJoined {
                username: agent.username.clone(),
                role: agent.role.clone(),
                workspace_mode: agent.workspace_mode.clone(),
                project_root: agent.project_root.clone(),
                project: agent.project.clone(),
                is_orchestrator: agent.is_orchestrator,
            })
            .ok();
        self.statuses.insert(
            agent.username.clone(),
            StatusPayload {
                username: agent.username.clone(),
                status: AgentStatus::Idle,
                task_id: None,
                progress_pct: None,
                message: None,
            },
        );
        // Deliver any queued offline messages
        if let Some(queued) = self.mailbox.remove(&agent.username) {
            for msg in queued {
                self.broadcast_tx
                    .send(NotifyPayload::MessageReceived {
                        from: msg.from,
                        to: agent.username.clone(),
                        body: msg.body,
                        timestamp: 0,
                        datetime_utc: String::new(),
                        time_region: String::new(),
                        project: None,
                    })
                    .ok();
            }
        }
        self.connections.insert(agent.username.clone(), conn);
        // Track project
        if let Some(ref proj) = agent.project {
            self.known_projects.insert(proj.clone());
        }
        self.agents.insert(agent.username.clone(), agent);
    }

    pub fn remove_agent(&mut self, username: &str, reason: Option<String>) {
        // Remove agent from all channel memberships
        for channel in self.channels.values_mut() {
            channel.members.retain(|m| m != username);
        }
        self.agents.remove(username);
        self.connections.remove(username);
        self.statuses.remove(username);
        self.broadcast_tx
            .send(NotifyPayload::AgentLeft {
                username: username.to_string(),
                reason,
            })
            .ok();
    }

    /// Send encrypted data to a specific agent.
    pub fn send_to_agent(&self, target: &str, data: Vec<u8>) -> bool {
        if let Some(conn) = self.connections.get(target) {
            conn.tx.send(data).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a notification to all connected agents.
    #[allow(dead_code)]
    pub fn notify_all(&self, notification: NotifyPayload) {
        self.broadcast_tx.send(notification).ok();
    }

    // ── Task management ──

    pub fn create_task(
        &mut self,
        title: String,
        description: String,
        priority: TaskPriority,
        assigned_role: Option<String>,
        assign_to: Option<String>,
        created_by: String,
    ) -> Task {
        let task = Task::new(title, description, priority, assigned_role, assign_to, created_by.clone());
        let sender_project = self.agents.get(&created_by).and_then(|a| a.project.clone());
        self.broadcast_tx
            .send(NotifyPayload::TaskCreated {
                task_id: task.id,
                title: task.title.clone(),
                assigned_role: task.assigned_role.clone(),
                project: sender_project,
            })
            .ok();
        self.task_creation_times.insert(task.id, Instant::now());
        self.tasks.insert(task.id, task.clone());
        task
    }

    /// Check whether any connected agent is an orchestrator.
    pub fn has_orchestrator(&self) -> bool {
        self.agents.values().any(|a| a.is_orchestrator)
    }

    /// Assign a task to a specific agent. Only orchestrators can call this.
    /// Returns Ok(task_title) on success, Err(message) on failure.
    pub fn assign_task(
        &mut self,
        assigned_by: &str,
        task_id: Uuid,
        assign_to: &str,
    ) -> Result<String, String> {
        // Verify assigner is an orchestrator
        let assigner = self
            .agents
            .get(assigned_by)
            .ok_or_else(|| format!("Assigner '{}' not found", assigned_by))?;
        if !assigner.is_orchestrator {
            return Err(format!(
                "'{}' is not an orchestrator — only orchestrators can assign tasks",
                assigned_by
            ));
        }

        // Verify target agent exists
        if !self.agents.contains_key(assign_to) {
            return Err(format!("Target agent '{}' not found", assign_to));
        }

        // Find and assign the task
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| format!("Task {} not found", task_id))?;

        if task.status != TaskStatus::Pending {
            return Err(format!(
                "Task {} is not pending (current status: {:?})",
                task_id, task.status
            ));
        }

        let title = task.title.clone();
        task.status = TaskStatus::InProgress;
        task.assignees.push(assign_to.to_string());
        self.broadcast_tx
            .send(NotifyPayload::TaskAssigned {
                task_id,
                username: assign_to.to_string(),
            })
            .ok();
        Ok(title)
    }

    pub fn take_task(&mut self, username: &str, task_ids: &[Uuid]) -> (Vec<Uuid>, Vec<Uuid>) {
        let mut taken = Vec::new();
        let mut not_found = Vec::new();
        // Check orchestrator status before the mutable borrow loop
        let skip_grace = self.has_orchestrator();
        let grace_secs = self.task_grace_secs;
        for &task_id in task_ids {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if task.status == TaskStatus::Pending {
                    // Grace period: if no orchestrator, wait before allowing take
                    // so all agents see the notification first
                    if !skip_grace {
                        if let Some(created) = self.task_creation_times.get(&task_id) {
                            let elapsed = created.elapsed().as_secs();
                            if elapsed < grace_secs {
                                // Still in grace period — skip this task silently
                                // (it's not an error, just not ready yet)
                                continue;
                            }
                        }
                    }
                    task.status = TaskStatus::InProgress;
                    task.assignees.push(username.to_string());
                    self.broadcast_tx
                        .send(NotifyPayload::TaskAssigned {
                            task_id,
                            username: username.to_string(),
                        })
                        .ok();
                    taken.push(task_id);
                }
            } else {
                not_found.push(task_id);
            }
        }
        (taken, not_found)
    }

    pub fn complete_task(
        &mut self,
        username: &str,
        task_id: Uuid,
        result: Option<String>,
        artifacts: Vec<String>,
    ) -> bool {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.status = TaskStatus::Completed;
            task.result = result.clone();
            task.artifacts = artifacts.clone();
            self.task_creation_times.remove(&task_id);
            self.broadcast_tx
                .send(NotifyPayload::TaskCompleted {
                    task_id,
                    username: username.to_string(),
                    result,
                    artifacts,
                })
                .ok();
            if let Some(status) = self.statuses.get_mut(username) {
                status.status = AgentStatus::Idle;
                status.task_id = None;
                status.progress_pct = None;
            }
            return true;
        }
        false
    }

    // ── Status ──

    pub fn update_status(
        &mut self,
        username: &str,
        status: AgentStatus,
        task_id: Option<Uuid>,
        progress_pct: Option<u8>,
        message: Option<String>,
    ) {
        let sp = StatusPayload {
            username: username.to_string(),
            status: status.clone(),
            task_id,
            progress_pct,
            message,
        };
        self.broadcast_tx
            .send(NotifyPayload::StatusUpdate {
                username: username.to_string(),
                status: format!("{:?}", status),
                task_id,
                progress_pct,
            })
            .ok();
        self.statuses.insert(username.to_string(), sp);
    }

    // ── Channels ──

    pub fn create_channel(
        &mut self,
        name: String,
        created_by: String,
        description: Option<String>,
        visibility: ChannelVisibility,
    ) -> Option<Channel> {
        if self.channels.contains_key(&name) {
            return None;
        }
        let channel = Channel::new(name.clone(), created_by.clone(), description, visibility);
        let channel_id = channel.id;
        let vis_str = match channel.visibility {
            ChannelVisibility::Public => "public",
            ChannelVisibility::Private => "private",
        };
        let creator_project = self.agents.get(&created_by).and_then(|a| a.project.clone());
        self.broadcast_tx
            .send(NotifyPayload::ChannelCreated {
                channel_id,
                name: name.clone(),
                created_by: created_by.clone(),
                visibility: vis_str.to_string(),
                project: creator_project,
            })
            .ok();
        self.channels.insert(name, channel.clone());
        Some(channel)
    }

    /// Join a channel. Returns Ok(()) on success, Err(message) on failure.
    pub fn join_channel(&mut self, channel_name: &str, username: &str) -> Result<(), String> {
        let channel = self
            .channels
            .get_mut(channel_name)
            .ok_or_else(|| format!("Channel '{}' not found", channel_name))?;

        if channel.is_member(username) {
            return Err(format!("Already a member of '{}'", channel_name));
        }

        if channel.visibility == ChannelVisibility::Private {
            return Err(format!(
                "Channel '{}' is private — cannot join",
                channel_name
            ));
        }

        channel.members.push(username.to_string());
        self.broadcast_tx
            .send(NotifyPayload::ChannelJoined {
                channel_name: channel_name.to_string(),
                username: username.to_string(),
            })
            .ok();
        Ok(())
    }

    /// Leave a channel. Returns Ok(()) on success.
    pub fn leave_channel(&mut self, channel_name: &str, username: &str) -> Result<(), String> {
        let channel = self
            .channels
            .get_mut(channel_name)
            .ok_or_else(|| format!("Channel '{}' not found", channel_name))?;

        if !channel.is_member(username) {
            return Err(format!("Not a member of '{}'", channel_name));
        }

        channel.members.retain(|m| m != username);
        self.broadcast_tx
            .send(NotifyPayload::ChannelLeft {
                channel_name: channel_name.to_string(),
                username: username.to_string(),
            })
            .ok();
        Ok(())
    }

    /// Delete a channel. Only the creator can delete. Returns Ok(()) on success.
    pub fn delete_channel(&mut self, channel_name: &str, requested_by: &str) -> Result<(), String> {
        let channel = self
            .channels
            .get(channel_name)
            .ok_or_else(|| format!("Channel '{}' not found", channel_name))?;

        if channel.created_by != requested_by {
            return Err(format!(
                "Only the channel creator '{}' can delete '{}'",
                channel.created_by, channel_name
            ));
        }

        self.channels.remove(channel_name);
        self.broadcast_tx
            .send(NotifyPayload::ChannelDeleted {
                channel_name: channel_name.to_string(),
                deleted_by: requested_by.to_string(),
            })
            .ok();
        Ok(())
    }

    /// Hide a channel from an agent's view.
    pub fn hide_channel(&mut self, channel_name: &str, username: &str) -> Result<(), String> {
        let channel = self
            .channels
            .get_mut(channel_name)
            .ok_or_else(|| format!("Channel '{}' not found", channel_name))?;

        channel.hidden_by.insert(username.to_string());
        Ok(())
    }

    /// List channels visible to the given agent (excludes hidden channels).
    pub fn list_visible_channels(&self, username: &str) -> Vec<ChannelInfo> {
        self.channels
            .values()
            .filter(|ch| ch.is_visible_to(username))
            .map(|ch| ChannelInfo {
                name: ch.name.clone(),
                created_by: ch.created_by.clone(),
                description: ch.description.clone(),
                visibility: match ch.visibility {
                    ChannelVisibility::Public => "public".to_string(),
                    ChannelVisibility::Private => "private".to_string(),
                },
                member_count: ch.members.len(),
            })
            .collect()
    }

    // ── Message routing ──

    /// Route a message to its target(s) and broadcast a notification.
    pub fn route_message(
        &mut self,
        from: &str,
        to: &crate::packet::MessageTarget,
        body: &str,
        timestamp: u64,
        datetime_utc: &str,
        time_region: &str,
        project: &Option<String>,
    ) -> Vec<String> {
        match to {
            crate::packet::MessageTarget::Direct { username } => {
                if self.connections.contains_key(username) {
                    self.broadcast_tx
                        .send(NotifyPayload::MessageReceived {
                            from: from.to_string(),
                            to: username.clone(),
                            body: body.to_string(),
                            timestamp,
                            datetime_utc: datetime_utc.to_string(),
                            time_region: time_region.to_string(),
                            project: project.clone(),
                        })
                        .ok();
                } else {
                    // Queue for offline delivery
                    self.mailbox
                        .entry(username.clone())
                        .or_default()
                        .push(QueuedMessage {
                            from: from.to_string(),
                            body: body.to_string(),
                        });
                }
                vec![username.clone()]
            }
            crate::packet::MessageTarget::Channel { channel } => {
                let recipients: Vec<String> = self
                    .channels
                    .get(channel)
                    .map(|ch| ch.members.iter().filter(|m| *m != from).cloned().collect())
                    .unwrap_or_default();
                for recipient in &recipients {
                    if self.connections.contains_key(recipient) {
                        self.broadcast_tx
                            .send(NotifyPayload::MessageReceived {
                                from: from.to_string(),
                                to: recipient.clone(),
                                body: body.to_string(),
                                timestamp,
                                datetime_utc: datetime_utc.to_string(),
                                time_region: time_region.to_string(),
                                project: project.clone(),
                            })
                            .ok();
                    } else {
                        self.mailbox
                            .entry(recipient.clone())
                            .or_default()
                            .push(QueuedMessage {
                                from: from.to_string(),
                                body: body.to_string(),
                            });
                    }
                }
                recipients
            }
        }
    }

    // ── Queries ──

    #[allow(dead_code)]
    pub fn list_agents(&self) -> Vec<&Agent> {
        self.agents.values().collect()
    }

    #[allow(dead_code)]
    pub fn get_agent(&self, username: &str) -> Option<&Agent> {
        self.agents.get(username)
    }

    #[allow(dead_code)]
    pub fn list_pending_tasks(&self) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|t| t.status == TaskStatus::Pending)
            .collect()
    }

    #[allow(dead_code)]
    pub fn list_all_tasks(&self) -> Vec<&Task> {
        self.tasks.values().collect()
    }

    #[allow(dead_code)]
    pub fn list_all_channels(&self) -> Vec<&Channel> {
        self.channels.values().collect()
    }

    pub fn subscribe_notifications(&self) -> broadcast::Receiver<NotifyPayload> {
        self.broadcast_tx.subscribe()
    }

    // ── Project management ──

    /// List all known project names.
    pub fn list_projects(&self) -> Vec<String> {
        let mut projects: Vec<String> = self.known_projects.iter().cloned().collect();
        projects.sort();
        projects
    }

    /// Select/change an agent's project scope.
    /// If an orchestrator is present and the requester is not an orchestrator,
    /// the request is denied and a ProjectRequested notification is broadcast.
    /// Returns Ok(new_project) on success, Err(message) on failure.
    pub fn select_project(&mut self, username: &str, project: &str) -> Result<Option<String>, String> {
        let project_opt: Option<String> = if project.is_empty() || project == "*" {
            None
        } else {
            Some(project.to_string())
        };

        // Orchestrator enforcement
        if self.has_orchestrator() {
            let is_orch = self.agents.get(username).map(|a| a.is_orchestrator).unwrap_or(false);
            if !is_orch {
                // Notify orchestrators that this agent needs a project
                self.broadcast_tx
                    .send(NotifyPayload::ProjectRequested {
                        username: username.to_string(),
                        requested_project: project_opt.clone(),
                    })
                    .ok();
                return Err(format!(
                    "An orchestrator is present — your project request has been sent. Wait for the orchestrator to assign you a project."
                ));
            }
        }

        // Register the project if it's new
        if let Some(ref proj) = project_opt {
            self.known_projects.insert(proj.clone());
        }

        // Update the agent's project
        if let Some(agent) = self.agents.get_mut(username) {
            agent.project = project_opt.clone();
        }

        // Broadcast the change
        self.broadcast_tx
            .send(NotifyPayload::ProjectChanged {
                username: username.to_string(),
                project: project_opt.clone(),
            })
            .ok();

        Ok(project_opt)
    }
}
