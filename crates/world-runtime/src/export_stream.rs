//! Decode the guest snapshot into private staging before an exclusive rename.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::CString,
    os::{fd::AsRawFd, unix::ffi::OsStrExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};

use tokio_util::sync::CancellationToken;

const MAX_RECORD: u64 = 70_000;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_DIRECTORY_METADATA: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Begin { protocol: u32 },
    Directory { path: String, mode: u32 },
    File { path: String, mode: u32, size: u64 },
    Symlink { path: String, target: String },
    Data { data: String },
    EndFile,
    Finish { entries: u64 },
}

pub(crate) struct Staging {
    dir: tempfile::TempDir,
    parent: std::fs::File,
    staging: std::fs::File,
    destination: CString,
    modes: Vec<(PathBuf, u32)>,
}

impl Staging {
    pub(crate) fn new(destination: &Path) -> Result<Self> {
        let leaf = destination
            .file_name()
            .context("export requires a destination directory name")?;
        // Reject dot and trailing parent components that Path normalizes away.
        ensure!(
            destination
                .components()
                .next_back()
                .is_some_and(|c| c.as_os_str() == leaf)
                && destination
                    .as_os_str()
                    .as_bytes()
                    .rsplit(|b| *b == b'/')
                    .find(|part| !part.is_empty())
                    == Some(leaf.as_bytes()),
            "invalid export destination"
        );
        let parent_path = destination.parent().context("missing destination parent")?;
        let parent_path = if parent_path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent_path
        }
        .canonicalize()
        .context("export destination parent does not exist")?;
        let parent = std::fs::File::open(&parent_path)?;
        ensure!(
            parent.metadata()?.is_dir(),
            "destination parent is not a directory"
        );
        match std::fs::symlink_metadata(parent_path.join(leaf)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => bail!("export destination already exists"),
        }
        let dir = tempfile::Builder::new()
            .prefix(".world-export-")
            .tempdir_in(parent_path)?;
        std::fs::create_dir(dir.path().join("tree"))?;
        let staging = std::fs::File::open(dir.path())?;
        Ok(Self {
            dir,
            parent,
            staging,
            destination: CString::new(leaf.as_bytes())?,
            modes: Vec::new(),
        })
    }

    pub(crate) async fn receive(&mut self, reader: impl AsyncRead + Unpin) -> Result<u64> {
        let root = self.dir.path().join("tree");
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        ensure!(
            matches!(
                read_record(&mut reader, &mut line).await?,
                Some(Record::Begin { protocol: 1 })
            ),
            "missing or invalid export stream header"
        );
        let mut directories = HashSet::new();
        let mut directory_metadata = 0;
        let mut entries = 0;
        let mut file = None;
        while let Some(record) = read_record(&mut reader, &mut line).await? {
            match record {
                Record::Directory { path, mode } => {
                    ensure!(file.is_none(), "unfinished export file");
                    validate_path(&path, &directories)?;
                    ensure!(mode <= 0o777, "invalid directory mode");
                    directory_metadata += path.len() + 64;
                    ensure!(
                        directory_metadata <= MAX_DIRECTORY_METADATA,
                        "export directory metadata limit exceeded"
                    );
                    let destination = root.join(&path);
                    tokio::fs::create_dir(&destination).await?;
                    self.modes.push((destination, mode));
                    directories.insert(path);
                    entries += 1;
                }
                Record::File { path, mode, size } => {
                    ensure!(file.is_none(), "unfinished export file");
                    validate_path(&path, &directories)?;
                    ensure!(mode <= 0o777, "invalid file mode");
                    let output = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(root.join(path))
                        .await?;
                    file = Some((output, mode, size));
                    entries += 1;
                }
                Record::Symlink { path, target } => {
                    ensure!(file.is_none(), "unfinished export file");
                    validate_path(&path, &directories)?;
                    ensure!(
                        !target.is_empty() && target.len() <= 4096 && !target.contains('\0'),
                        "invalid export link target"
                    );
                    tokio::fs::symlink(target, root.join(path)).await?;
                    entries += 1;
                }
                Record::Data { data } => {
                    let (output, _, remaining) =
                        file.as_mut().context("export data without a file")?;
                    let data = STANDARD.decode(data)?;
                    ensure!(
                        !data.is_empty()
                            && data.len() <= 48 * 1024
                            && data.len() as u64 <= *remaining,
                        "invalid export data chunk"
                    );
                    output.write_all(&data).await?;
                    *remaining -= data.len() as u64;
                }
                Record::EndFile => {
                    let (mut output, mode, remaining) =
                        file.take().context("unexpected end of export file")?;
                    ensure!(remaining == 0, "truncated export file");
                    output.flush().await?;
                    output
                        .set_permissions(std::fs::Permissions::from_mode(mode))
                        .await?;
                    output.sync_all().await?;
                }
                Record::Finish { entries: expected } => {
                    ensure!(
                        file.is_none() && expected == entries,
                        "incomplete export stream"
                    );
                    ensure!(
                        read_record(&mut reader, &mut line).await?.is_none(),
                        "data after export finish"
                    );
                    return Ok(entries);
                }
                Record::Begin { .. } => bail!("duplicate export stream header"),
            }
            ensure!(entries <= MAX_ENTRIES, "export entry limit exceeded");
        }
        bail!("export stream ended before finish")
    }

    pub(crate) fn publish(mut self, cancel: &CancellationToken) -> Result<()> {
        for (path, mode) in self.modes.iter().rev() {
            ensure!(!cancel.is_cancelled(), "export cancelled");
            let directory = std::fs::File::open(path)?;
            directory.set_permissions(std::fs::Permissions::from_mode(*mode))?;
            directory.sync_all()?;
        }
        std::fs::File::open(self.dir.path().join("tree"))?.sync_all()?;
        ensure!(!cancel.is_cancelled(), "export cancelled");
        let source = c"tree";
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                self.staging.as_raw_fd(),
                source.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                self.staging.as_raw_fd(),
                source.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        ensure!(
            result == 0,
            "cannot publish export without overwriting: {}",
            std::io::Error::last_os_error()
        );
        self.modes.clear();
        self.parent
            .sync_all()
            .context("export published, but destination parent sync failed")?;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        // If publication failed after applying modes, make the staging tree
        // traversable again before TempDir removes it.
        for (path, _) in &self.modes {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        }
    }
}

fn validate_path(path: &str, directories: &HashSet<String>) -> Result<()> {
    ensure!(
        path.len() <= 4096 && !path.contains('\0'),
        "invalid export path"
    );
    let mut components = path.split('/');
    ensure!(
        components
            .clone()
            .all(|part| !matches!(part, "" | "." | ".."))
            && components.by_ref().count() <= 128,
        "unsafe export path"
    );
    if let Some((parent, _)) = path.rsplit_once('/') {
        ensure!(
            directories.contains(parent),
            "export parent is missing or a symlink"
        );
    }
    Ok(())
}

async fn read_record<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    line: &mut Vec<u8>,
) -> Result<Option<Record>> {
    line.clear();
    let length = reader.take(MAX_RECORD + 1).read_until(b'\n', line).await?;
    if length == 0 {
        return Ok(None);
    }
    ensure!(
        length as u64 <= MAX_RECORD && line.ends_with(b"\n"),
        "oversized or truncated export record"
    );
    Ok(Some(
        serde_json::from_slice(line).context("invalid export record")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: &str = "{\"type\":\"begin\",\"protocol\":1}\n";

    #[tokio::test]
    async fn invalid_stream_removes_staging_without_publishing() {
        for records in [
            "{\"type\":\"directory\",\"path\":\"../escape\",\"mode\":493}\n",
            concat!(
                "{\"type\":\"symlink\",\"path\":\"link\",\"target\":\"..\"}\n",
                "{\"type\":\"file\",\"path\":\"link/escape\",\"size\":0,\"mode\":420}\n",
            ),
            "{\"type\":\"file\",\"path\":\"partial\",\"size\":10,\"mode\":420}\n",
            "{\"type\":\"finish\",\"entries\":0}\n{\"type\":\"finish\",\"entries\":0}\n",
        ] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("result");
            {
                let mut staging = Staging::new(&destination).unwrap();
                let stream = format!("{START}{records}");
                assert!(staging.receive(stream.as_bytes()).await.is_err());
            }
            assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn destination_created_during_transfer_is_never_replaced() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("result");
        let mut staging = Staging::new(&destination).unwrap();
        let stream = format!("{START}{{\"type\":\"finish\",\"entries\":0}}\n");
        assert_eq!(staging.receive(stream.as_bytes()).await.unwrap(), 0);
        std::fs::create_dir(&destination).unwrap();
        assert!(staging.publish(&CancellationToken::new()).is_err());
        assert!(destination.is_dir());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn cancellation_before_publication_removes_staging() {
        let parent = tempfile::tempdir().unwrap();
        let mut staging = Staging::new(&parent.path().join("result")).unwrap();
        let stream = format!("{START}{{\"type\":\"finish\",\"entries\":0}}\n");
        staging.receive(stream.as_bytes()).await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(staging.publish(&cancel).is_err());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}
