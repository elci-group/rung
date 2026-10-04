use crate::{digest, RungError};
use git2::{ObjectType, Repository, Tree};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tracing::instrument;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub revision: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

impl Snapshot {
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        for (path, bytes) in &self.files {
            if path.starts_with(".rung/authorizations/") {
                continue;
            }
            hasher.update(path.as_bytes());
            hasher.update([0]);
            hasher.update(digest(bytes).as_bytes());
            hasher.update([0]);
        }
        hex::encode(hasher.finalize())
    }
}

pub fn open_repository(path: &Path) -> Result<Repository, RungError> {
    Repository::discover(path).map_err(Into::into)
}

#[instrument(skip(repository))]
pub fn revision_snapshot(repository: &Repository, revision: &str) -> Result<Snapshot, RungError> {
    let object = repository.revparse_single(revision)?;
    let commit = object.peel_to_commit()?;
    let tree = commit.tree()?;
    let mut files = BTreeMap::new();
    collect_tree(repository, &tree, "", &mut files)?;
    Ok(Snapshot {
        revision: commit.id().to_string(),
        files,
    })
}

fn collect_tree(
    repository: &Repository,
    tree: &Tree<'_>,
    prefix: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), RungError> {
    for entry in tree {
        let name = entry
            .name()
            .map_err(|e| RungError::Analysis(format!("invalid Git path: {e}")))?;
        let path = format!("{prefix}{name}");
        match entry.kind() {
            Some(ObjectType::Tree) => {
                let child = repository.find_tree(entry.id())?;
                collect_tree(repository, &child, &format!("{path}/"), files)?;
            }
            Some(ObjectType::Blob) => {
                if entry.filemode() == 0o120000 {
                    return Err(RungError::Analysis(format!(
                        "symlink in repository: {path}"
                    )));
                }
                let blob = repository.find_blob(entry.id())?;
                files.insert(path, blob.content().to_vec());
            }
            _ => {
                return Err(RungError::Analysis(format!(
                    "unsupported Git object: {path}"
                )))
            }
        }
    }
    Ok(())
}

#[instrument(skip(repository))]
pub fn candidate_snapshot(repository: &Repository) -> Result<Snapshot, RungError> {
    let root = repository
        .workdir()
        .ok_or_else(|| RungError::Analysis("bare repository has no worktree".into()))?;
    let mut files = BTreeMap::new();
    collect_worktree(root, root, &mut files)?;
    let revision = repository
        .head()
        .ok()
        .and_then(|head| head.target())
        .map_or_else(|| "worktree".to_string(), |oid| oid.to_string());
    Ok(Snapshot { revision, files })
}

fn collect_worktree(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), RungError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|e| RungError::Analysis(e.to_string()))?;
        let name = relative
            .to_str()
            .ok_or_else(|| RungError::Analysis("non-UTF-8 path".into()))?
            .replace('\\', "/");
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(RungError::Analysis(format!("symlink in candidate: {name}")));
        }
        if kind.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some(".git" | "target" | "__pycache__" | ".pytest_cache")
            ) {
                continue;
            }
            collect_worktree(root, &path, files)?;
        } else if kind.is_file() {
            files.insert(name, fs::read(path)?);
        }
    }
    Ok(())
}
