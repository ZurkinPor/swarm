use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::packet::TaskPriority;

/// Represents a task in the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub priority: TaskPriority,
    pub assigned_role: Option<String>,
    pub assign_to: Option<String>,
    pub created_by: String,
    pub status: TaskStatus,
    pub assignees: Vec<String>,
    /// Result output when the task is completed.
    pub result: Option<String>,
    /// Deliverable artifacts from task completion.
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
}

impl Task {
    pub fn new(
        title: String,
        description: String,
        priority: TaskPriority,
        assigned_role: Option<String>,
        assign_to: Option<String>,
        created_by: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            title,
            description,
            priority,
            assigned_role,
            assign_to,
            created_by,
            status: TaskStatus::Pending,
            assignees: Vec::new(),
            result: None,
            artifacts: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn matches_agent(&self, agent_role: &Option<String>) -> bool {
        match (&self.assigned_role, agent_role) {
            (Some(task_role), Some(agent_role)) => {
                task_role.to_lowercase() == agent_role.to_lowercase()
            }
            _ => true,
        }
    }
}
