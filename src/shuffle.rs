//! Where orphan detection exchanges its partitions: objects in a RADOS pool
//! when clients share the work, or files in a directory for a standalone scan.

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;

#[async_trait]
pub trait Shuffle: Send + Sync {
    /// Append to a named object, creating it; appends are atomic.
    async fn append(&self, name: &str, data: Vec<u8>) -> Result<()>;
    /// The whole object, or None if it does not exist.
    async fn read(&self, name: &str) -> Result<Option<Vec<u8>>>;
    async fn remove(&self, name: &str) -> Result<()>;
}

/// Files in a directory, for a scan from one host.
pub struct LocalShuffle {
    pub dir: PathBuf,
}

impl LocalShuffle {
    pub fn new(dir: PathBuf) -> Result<LocalShuffle> {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(LocalShuffle { dir })
    }
}

#[async_trait]
impl Shuffle for LocalShuffle {
    async fn append(&self, name: &str, data: Vec<u8>) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let path = self.dir.join(name);
        let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&path).await.with_context(|| format!("opening {}", path.display()))?;
        f.write_all(&data).await?;
        f.flush().await?;
        Ok(())
    }

    async fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.dir.join(name)).await {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn remove(&self, name: &str) -> Result<()> {
        match tokio::fs::remove_file(self.dir.join(name)).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}
