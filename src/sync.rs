#![allow(dead_code)] // Sync functions used by client P2P handlers (wiring in progress)
use std::collections::HashMap;
use crate::packet;

/// Walk a directory and build a Hashmap of (relative_path → SyncFileInfo) with SHA-1 hashes.
pub fn walk_project_dir(root: &str) -> std::io::Result<HashMap<String, packet::SyncFileInfo>> {
    let mut files = HashMap::new();
    walk_dir(root, root, &mut files)?;
    Ok(files)
}

fn walk_dir(base: &str, dir: &str, files: &mut HashMap<String, packet::SyncFileInfo>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy().replace('\\', "/");

        if path.is_dir() {
            // Skip .git, target, node_modules
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" || name == "target" || name == "node_modules" || name == ".swarm" {
                continue;
            }
            walk_dir(base, &path.to_string_lossy(), files)?;
        } else if path.is_file() {
            let metadata = entry.metadata()?;
            let content = std::fs::read(&path)?;
            let sha1 = packet::Sha1Hash(sha1_digest(&content));
            files.insert(rel.clone(), packet::SyncFileInfo {
                path: rel,
                size: metadata.len(),
                sha1,
                mtime_secs: metadata.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }
    }
    Ok(())
}

/// Compute SHA-1 digest of data.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Format SHA-1 hash as hex string.
#[allow(dead_code)]
pub fn sha1_hex(hash: &[u8; 20]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compare local and remote manifests, return files to pull / push.
/// Strategy:
/// - Newest (0): keep whichever file has the newest mtime
/// - NewestServer (1): server (remote/target) version always wins
/// - Interactive (2): prompt — for now, defaults to newest
pub struct SyncDiff {
    /// Files we need to pull from remote (remote has newer/different content)
    pub pull: Vec<String>,
    /// Files we should push to remote (our version is newer)
    pub push: Vec<String>,
    /// Files that match (skip)
    pub skipped: usize,
    /// Files that conflict (both modified, strategy decides)
    pub conflicts: Vec<String>,
}

pub fn diff_manifests(
    local: &HashMap<String, packet::SyncFileInfo>,
    remote: &HashMap<String, packet::SyncFileInfo>,
    strategy: packet::SyncStrategy,
) -> SyncDiff {
    let mut pull = Vec::new();
    let mut push = Vec::new();
    let mut skipped = 0usize;
    let mut conflicts = Vec::new();

    let all_paths: std::collections::HashSet<&String> =
        local.keys().chain(remote.keys()).collect();

    for path in all_paths {
        match (local.get(path), remote.get(path)) {
            (Some(l), Some(r)) => {
                if l.sha1.0 == r.sha1.0 {
                    skipped += 1;
                } else {
                    // Both have the file but content differs — conflict
                    match strategy {
                        packet::SyncStrategy::Newest => {
                            if l.mtime_secs >= r.mtime_secs {
                                push.push(path.clone());
                            } else {
                                pull.push(path.clone());
                            }
                        }
                        packet::SyncStrategy::NewestServer => {
                            // Server = remote, always pull
                            pull.push(path.clone());
                        }
                        packet::SyncStrategy::Interactive => {
                            // Default to newest for non-interactive
                            if l.mtime_secs >= r.mtime_secs {
                                push.push(path.clone());
                            } else {
                                pull.push(path.clone());
                            }
                            conflicts.push(path.clone());
                        }
                    }
                }
            }
            (Some(_), None) => {
                // Only local has it — push to remote
                push.push(path.clone());
            }
            (None, Some(_)) => {
                // Only remote has it — pull from remote
                pull.push(path.clone());
            }
            (None, None) => unreachable!(),
        }
    }

    SyncDiff { pull, push, skipped, conflicts }
}
