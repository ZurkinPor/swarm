use serde::{Deserialize, Serialize};

/// Represents an agent connected to the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub username: String,
    pub role: Option<String>,
    pub capabilities: Vec<String>,
    /// "git" or "single-host"
    pub workspace_mode: Option<String>,
    /// Root directory if single-host mode
    pub project_root: Option<String>,
    /// Project scope for context isolation
    pub project: Option<String>,
    /// Whether this agent can assign tasks to others
    pub is_orchestrator: bool,
}

impl Agent {
    pub fn new(
        username: String,
        role: Option<String>,
        capabilities: Vec<String>,
        workspace_mode: Option<String>,
        project_root: Option<String>,
        project: Option<String>,
        is_orchestrator: bool,
    ) -> Self {
        Self {
            username,
            role,
            capabilities,
            workspace_mode,
            project_root,
            project,
            is_orchestrator,
        }
    }

    /// Whether this agent is the workspace host in single-host mode.
    #[allow(dead_code)]
    pub fn is_host(&self) -> bool {
        self.workspace_mode.as_deref() == Some("single-host")
    }
}

/// Well-known role names.
#[allow(dead_code)]
pub mod roles {
    pub const DEVELOPER: &str = "developer";
    pub const RESEARCHER: &str = "researcher";
    pub const DOCUMENTER: &str = "documenter";
    pub const REVIEWER: &str = "reviewer";
    pub const TESTER: &str = "tester";
    pub const ORCHESTRATOR: &str = "orchestrator";
}
