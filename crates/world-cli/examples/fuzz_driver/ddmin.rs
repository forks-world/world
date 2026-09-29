//! `minimize`: delta-debugging (ddmin) shrink of a `.ops` file that still
//! reproduces a divergence, by repeatedly re-`exec`ing this same binary's
//! `replay` subcommand (a fresh `--run-id` every time, so no two attempts --
//! including ones running concurrently on a shared build machine -- can ever
//! collide on the same sandbox root) on smaller and smaller subsets of the
//! op lines, each with its own bounded wait.
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{fresh_run_id, parse_ops_file};

/// The shape of a divergence, used so minimization keeps reproducing the
/// *same* kind of failure instead of drifting to some unrelated one (e.g.
/// "the sandbox root doesn't exist any more"): the diverging op's command
/// word plus the first words of its detail message, or "tree" for a final
/// tree mismatch.
fn signature(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout.lines().next()?).ok()?;
    let d = v.get("first_divergence")?;
    if d.is_null() {
        return None;
    }
    let op = d
        .get("op")
        .and_then(|o| o.as_str())
        .and_then(|o| o.split(' ').next())
        .unwrap_or("tree");
    let detail = d.get("detail").and_then(|x| x.as_str()).unwrap_or("");
    let head: Vec<&str> = detail.split(' ').take(2).collect();
    Some(format!("{op}|{}", head.join(" ")))
}

/// Run `current_exe() replay <candidate> --run-id <fresh>` (stdout to a file,
/// so a large tree dump can never block the child), waited on with a bounded
/// timeout (never backgrounded, never awaited unboundedly). Returns the
/// divergence signature if it diverged (exit 1), `None` for a pass, a harness
/// error (exit 2) or a timeout.
fn reproduces(exe: &Path, candidate_file: &Path, timeout: Duration) -> Option<String> {
    let run_id = fresh_run_id();
    let out_path = candidate_file.with_extension("out");
    let out = std::fs::File::create(&out_path).ok()?;
    let mut child = Command::new(exe)
        .arg("replay")
        .arg(candidate_file)
        .arg("--run-id")
        .arg(&run_id)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            if status.code() != Some(1) {
                return None;
            }
            let text = std::fs::read_to_string(&out_path).ok()?;
            return signature(&text);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Render already-`Op::to_line`d text lines back into a full `.ops` file
/// (headers + lines): used both for throwaway candidates during the search
/// and for the final minimized output.
fn render_lines(header: (&str, u64, &str, bool), lines: &[String]) -> String {
    let (profile, seed, run_id, allow_escaping_links) = header;
    let mut text = String::new();
    text.push_str(&format!("# profile {profile}\n"));
    text.push_str(&format!("# seed {seed}\n"));
    text.push_str(&format!("# run-id {run_id}\n"));
    text.push_str(&format!(
        "# allow-escaping-links {}\n",
        if allow_escaping_links { 1 } else { 0 }
    ));
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    text
}

fn write_candidate(
    dir: &Path,
    tag: &str,
    header: (&str, u64, &str, bool),
    lines: &[String],
) -> std::path::PathBuf {
    let path = dir.join(format!("candidate-{tag}.ops"));
    let _ = std::fs::write(&path, render_lines(header, lines));
    path
}

pub fn minimize(input: &Path, output: &Path, timeout_secs: u64) -> i32 {
    let text = match std::fs::read_to_string(input) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fuzz_driver: could not read {}: {e}", input.display());
            return 2;
        }
    };
    let parsed = match parse_ops_file(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("fuzz_driver: could not parse {}: {e}", input.display());
            return 2;
        }
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("fuzz_driver: could not resolve current_exe: {e}");
            return 2;
        }
    };
    let scratch = match tempdir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fuzz_driver: could not create a scratch dir for minimize: {e}");
            return 2;
        }
    };
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut lines: Vec<String> = parsed.ops.iter().map(|op| op.to_line()).collect();
    let header = (
        parsed.profile.as_str(),
        parsed.seed,
        parsed.run_id.as_str(),
        parsed.allow_escaping_links,
    );

    let attempt = |lines: &[String]| -> Option<String> {
        let candidate = write_candidate(&scratch, "try", header, lines);
        reproduces(&exe, &candidate, timeout)
    };

    let Some(target) = (if lines.is_empty() {
        None
    } else {
        attempt(&lines)
    }) else {
        eprintln!(
            "fuzz_driver: {} does not reproduce a divergence; nothing to minimize",
            input.display()
        );
        let _ = std::fs::remove_dir_all(&scratch);
        return 1;
    };
    let repro = |lines: &[String]| -> bool { attempt(lines).as_deref() == Some(target.as_str()) };

    // Coarse ddmin: shrink by removing ever-smaller contiguous chunks.
    let mut chunk_divisor = 2usize;
    while lines.len() > 1 {
        let chunk_size = lines.len().div_ceil(chunk_divisor);
        if chunk_size == 0 {
            break;
        }
        let mut shrank = false;
        let mut start = 0;
        while start < lines.len() {
            let end = (start + chunk_size).min(lines.len());
            let mut candidate = lines.clone();
            candidate.drain(start..end);
            if !candidate.is_empty() && repro(&candidate) {
                lines = candidate;
                shrank = true;
                chunk_divisor = chunk_divisor.saturating_sub(1).max(2);
                break;
            }
            start = end;
        }
        if !shrank {
            if chunk_divisor >= lines.len() {
                break;
            }
            chunk_divisor = (chunk_divisor * 2).min(lines.len());
        }
    }

    // Fine pass: try dropping single lines outright.
    let mut i = 0;
    while i < lines.len() {
        let mut candidate = lines.clone();
        candidate.remove(i);
        if !candidate.is_empty() && repro(&candidate) {
            lines = candidate;
        } else {
            i += 1;
        }
    }

    if let Err(e) = std::fs::write(output, render_lines(header, &lines)) {
        eprintln!("fuzz_driver: could not write {}: {e}", output.display());
        let _ = std::fs::remove_dir_all(&scratch);
        return 2;
    }
    let _ = std::fs::remove_dir_all(&scratch);
    eprintln!(
        "fuzz_driver: minimized {} ops down to {} ops -> {}",
        parsed.ops.len(),
        lines.len(),
        output.display()
    );
    0
}

/// A short-lived scratch directory under the system temp dir for candidate
/// `.ops` files only (never a sandbox root itself: `replay` makes its own
/// under `/tmp/<fresh-run-id>`).
fn tempdir() -> std::io::Result<std::path::PathBuf> {
    let base = std::env::temp_dir().join(format!("fuzz-driver-ddmin-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}
