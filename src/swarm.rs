use std::collections::HashMap;
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
                    })
                    .ok();
            }
        }
        self.connections.insert(agent.username.clone(), conn);
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
        let task = Task::new(title, description, priority, assigned_role, assign_to, created_by);
        self.broadcast_tx
            .send(NotifyPayload::TaskCreated {
                task_id: task.id,
                title: task.title.clone(),
                assigned_role: task.assigned_role.clone(),
            })
            .ok();
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
        for &task_id in task_ids {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if task.status == TaskStatus::Pending {
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
        self.broadcast_tx
            .send(NotifyPayload::ChannelCreated {
                channel_id,
                name: name.clone(),
                created_by,
                visibility: vis_str.to_string(),
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
    ) -> Vec<String> {
        match to {
            crate::packet::MessageTarget::Direct { username } => {
                if self.connections.contains_key(username) {
                    self.broadcast_tx
                        .send(NotifyPayload::MessageReceived {
                            from: from.to_string(),
                            to: username.clone(),
                            body: body.to_string(),
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
}
