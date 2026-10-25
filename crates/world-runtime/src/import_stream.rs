//! Bounded JSON-lines snapshot stream. All traversal is relative to pinned
//! directory descriptors; symlinks are copied as links and never followed.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

fn entry(output: &mut File, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn names(directory: &File) -> Result<Vec<String>> {
    // fdopendir takes ownership of its descriptor, so give it a duplicate.
    let fd = unsafe { libc::dup(directory.as_raw_fd()) };
    ensure!(
        fd >= 0,
        "dup directory: {}",
        std::io::Error::last_os_error()
    );
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let dir = Directory(dir);
    let mut names = Vec::new();
    loop {
        // POSIX readdir signals EOF via null and unchanged errno.
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let item = unsafe { libc::readdir(dir.0) };
        if item.is_null() {
            let error = std::io::Error::last_os_error();
            ensure!(error.raw_os_error() == Some(0), "read directory: {error}");
            break;
        }
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }
            .to_str()
            .context("import requires UTF-8 filenames")?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn open_at(directory: &File, name: &CString) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn walk(
    directory: &File,
    prefix: &str,
    depth: usize,
    output: &mut File,
    count: &mut u64,
) -> Result<()> {
    ensure!(depth <= 128, "import directory nesting exceeds 128");
    let before = directory.metadata()?;
    for name in names(directory)? {
        *count += 1;
        ensure!(*count <= 1_000_000, "import exceeds one million entries");
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        ensure!(path.len() <= 4096, "import path exceeds 4096 bytes");
        let c_name = CString::new(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        ensure!(
            unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0,
            "stat import entry {path}: {}",
            std::io::Error::last_os_error()
        );
        let stat = unsafe { stat.assume_init() };
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            let mut buffer = vec![0u8; 4097];
            let len = unsafe {
                libc::readlinkat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            ensure!(
                len >= 0 && (len as usize) < buffer.len(),
                "invalid or changed symlink {path}"
            );
            let target = std::str::from_utf8(&buffer[..len as usize])
                .context("import requires UTF-8 symlink targets")?;
            entry(
                output,
                serde_json::json!({"type":"symlink","path":path,"target":target}),
            )?;
            continue;
        }
        ensure!(
            kind == libc::S_IFREG || kind == libc::S_IFDIR,
            "unsupported special file: {path}"
        );
        let mut file =
            open_at(directory, &c_name).with_context(|| format!("open import entry {path}"))?;
        let metadata = file.metadata()?;
        ensure!(
            i128::from(metadata.dev()) == i128::from(stat.st_dev) && metadata.ino() == stat.st_ino,
            "import entry changed while opening: {path}"
        );
        let mode = metadata.mode() & 0o777; // Never carry setuid/setgid/sticky privileges.
        if metadata.is_dir() {
            entry(
                output,
                serde_json::json!({"type":"directory","path":path,"mode":mode}),
            )?;
            walk(&file, &path, depth + 1, output, count)?;
        } else if metadata.is_file() {
            entry(
                output,
                serde_json::json!({"type":"file","path":path,"mode":mode,"size":metadata.len()}),
            )?;
            let mut remaining = metadata.len();
            let mut buffer = [0u8; 48 * 1024];
            while remaining > 0 {
                let size = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..size])
                    .context("source file changed/truncated during import")?;
                entry(
                    output,
                    serde_json::json!({"type":"data","data":STANDARD.encode(&buffer[..size])}),
                )?;
                remaining -= size as u64;
            }
            ensure!(
                unchanged(&metadata, &file.metadata()?),
                "source file changed during import: {path}"
            );
            entry(output, serde_json::json!({"type":"end_file"}))?;
        } else {
            bail!("source changed to a special file: {path}");
        }
    }
    ensure!(
        unchanged(&before, &directory.metadata()?),
        "source directory changed during import: {prefix}"
    );
    Ok(())
}

pub(crate) fn snapshot(source: &Path) -> Result<tempfile::NamedTempFile> {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .context("import source must be a real directory, not a symlink")?;
    let mut output = tempfile::NamedTempFile::new()?;
    entry(
        output.as_file_mut(),
        serde_json::json!({"protocol":1,"type":"begin"}),
    )?;
    let mut count = 0;
    walk(&directory, "", 0, output.as_file_mut(), &mut count)?;
    entry(
        output.as_file_mut(),
        serde_json::json!({"type":"finish","entries":count}),
    )?;
    output.as_file().sync_all()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn copies_links_without_reading_targets_and_rejects_special_files() {
        let root = tempfile::tempdir().unwrap();
        symlink("/unavailable/host/secret", root.path().join("link")).unwrap();
        std::fs::write(root.path().join("file"), b"hello\0world").unwrap();
        let data = std::fs::read_to_string(snapshot(root.path()).unwrap().path()).unwrap();
        assert!(data.contains("/unavailable/host/secret"));
        assert!(data.contains(&STANDARD.encode(b"hello\0world")));
        let fifo = CString::new(root.path().join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(snapshot(root.path()).is_err());
    }
}
