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
/// *same* failure instead of drifting to some unrelated one (e.g. "the
/// sandbox root doesn't exist any more", or the same op now failing with a
/// different errno): the diverging op's command word ("tree" for a final
/// tree mismatch), the detail's category (the text before its first `:`,
/// with the replay's own run id normalized away, since every attempt uses a
/// fresh one), and the concrete model/real errno and return-sign pairs.
/// Data payloads (read bytes, paths, tree dumps) are left out: removing
/// unrelated ops may legitimately change them.
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
    let mut category = detail.split(':').next().unwrap_or("").to_string();
    if let Some(run_id) = v.get("run_id").and_then(|r| r.as_str())
        && !run_id.is_empty()
    {
        category = category.replace(run_id, "<run>");
    }
    let field = |k: &str| d.get(k).and_then(|x| x.as_i64());
    let sign = |r: Option<i64>| r.map(|r| if r < 0 { "-" } else { "+" }).unwrap_or("?");
    let errno = |e: Option<i64>| e.map(|e| e.to_string()).unwrap_or_else(|| "?".to_string());
    Some(format!(
        "{op}|{category}|model={}{} real={}{}",
        sign(field("model_ret")),
        errno(field("model_errno")),
        sign(field("real_ret")),
        errno(field("real_errno")),
    ))
}

/// Best-effort removal of a (killed) replay's sandbox roots, through the same
/// guarded, `O_NOFOLLOW`-only walk the driver uses for its own cleanup. A
/// missing root is not an error; any other failure is ignored (a leftover
/// under a unique `fz-*` id is harmless to later attempts).
fn cleanup_roots(run_id: &str) {
    let phys = std::env::var_os("WORLD_TMP").map(|v| {
        use std::os::unix::ffi::OsStrExt;
        v.as_bytes().to_vec()
    });
    for root in [format!("/tmp/{run_id}"), format!("/var/tmp/{run_id}")] {
        let _ = crate::exec::remove_sandbox_tree(run_id, phys.as_deref(), root.as_bytes());
    }
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
            if !matches!(status.code(), Some(0) | Some(1)) {
                // Killed by a signal / harness abort: the replay may not
                // have reached its own cleanup.
                cleanup_roots(&run_id);
            }
            if status.code() != Some(1) {
                return None;
            }
            let text = std::fs::read_to_string(&out_path).ok()?;
            return signature(&text);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The killed replay never reached its own cleanup: remove the
            // sandbox roots it may have left behind (best effort).
            cleanup_roots(&run_id);
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

#[cfg(test)]
mod tests {
    use super::signature;

    fn out(run_id: &str, divergence: serde_json::Value) -> String {
        serde_json::json!({ "run_id": run_id, "result": "diverge", "first_divergence": divergence })
            .to_string()
    }

    fn errno_div(op: &str, model: i64, real: i64) -> serde_json::Value {
        serde_json::json!({
            "op": op,
            "detail": format!("errno mismatch: model={model} real={real}"),
            "model_ret": -1, "model_errno": model,
            "real_ret": if real == 0 { 0 } else { -1 }, "real_errno": real,
        })
    }

    #[test]
    fn errno_pairs_are_part_of_the_signature() {
        let a = signature(&out(
            "fz-00000001",
            errno_div("open /tmp/fz-00000001/x 100100", 2, 0),
        ));
        let same = signature(&out(
            "fz-00000002",
            errno_div("open /tmp/fz-00000002/y 000000", 2, 0),
        ));
        let other = signature(&out(
            "fz-00000003",
            errno_div("open /tmp/fz-00000003/x 100100", 20, 0),
        ));
        let swapped = signature(&out(
            "fz-00000004",
            errno_div("open /tmp/fz-00000004/x 100100", 2, 13),
        ));
        assert!(a.is_some());
        assert_eq!(a, same);
        assert_ne!(a, other);
        assert_ne!(a, swapped);
    }

    #[test]
    fn tree_mismatches_ignore_the_run_id_and_dump_but_keep_the_root() {
        let tree = |rid: &str, root: &str, dump: &str| {
            out(
                rid,
                serde_json::json!({
                    "detail": format!("final tree mismatch under /{root}/{rid}: model=[{dump}] real=[]"),
                }),
            )
        };
        let a = signature(&tree("fz-00000001", "tmp", "a"));
        assert_eq!(a, signature(&tree("fz-00000002", "tmp", "b, c")));
        assert_ne!(a, signature(&tree("fz-00000003", "var/tmp", "a")));
        assert!(
            a.unwrap()
                .starts_with("tree|final tree mismatch under /tmp/<run>|")
        );
    }

    #[test]
    fn data_mismatches_ignore_the_payload() {
        let data = |bytes: &str| {
            out(
                "fz-00000001",
                serde_json::json!({
                    "op": "read 3 8",
                    "detail": format!("data mismatch: real={bytes:?} model=\"\""),
                    "model_ret": 0, "model_errno": 0, "real_ret": 2, "real_errno": 0,
                }),
            )
        };
        assert_eq!(signature(&data("ab")), signature(&data("abcdef")));
        assert_eq!(
            signature(&out("fz-00000001", serde_json::Value::Null)),
            None
        );
    }
}
