use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Represents a named communication channel (like a Discord/Slack channel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub created_by: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    /// Who can see/join this channel.
    pub visibility: ChannelVisibility,
    /// Usernames who have hidden this channel from their view.
    pub hidden_by: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelVisibility {
    /// Anyone in the swarm can see and join.
    Public,
    /// Only members can see it; others must be invited.
    Private,
}

impl Channel {
    pub fn new(
        name: String,
        created_by: String,
        description: Option<String>,
        visibility: ChannelVisibility,
    ) -> Self {
        let mut members = Vec::new();
        members.push(created_by.clone()); // creator auto-joins
        Self {
            id: Uuid::new_v4(),
            name,
            created_by,
            description,
            members,
            visibility,
            hidden_by: HashSet::new(),
        }
    }

    pub fn is_member(&self, username: &str) -> bool {
        self.members.iter().any(|m| m == username)
    }

    pub fn is_visible_to(&self, username: &str) -> bool {
        if self.hidden_by.contains(username) {
            return false;
        }
        match self.visibility {
            ChannelVisibility::Public => true,
            ChannelVisibility::Private => self.is_member(username),
        }
    }
}
