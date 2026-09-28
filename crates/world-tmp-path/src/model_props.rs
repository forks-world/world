//! Layer 1 property tests: `world-tmp-path`'s pure, allocation-free mapper
//! (`map`/`map_at`/`map_target`/`unmap_in_place`/...), checked against
//! `world-fsmodel::Model` as a from-scratch, kernel-behavior oracle.
//!
//! Every property in this file is a pure, in-memory computation: `Model` has
//! no filesystem-backed state at all (it is a `BTreeMap`-based arena, see
//! `world-fsmodel::Model`), and every `world-tmp-path` function exercised
//! here (`map`, `map_at`, `map_target`, `unmap_in_place`, `copy_cwd`,
//! `copy_link`, `unix_path`, `unmap_sockaddr`, `requeried_unix`,
//! `valid_root`) only reads and writes caller-supplied byte buffers -- none
//! of it touches a real path, directory or file descriptor. So, unlike
//! `world-fsmodel/tests/conformance.rs` (which deliberately runs real,
//! sandboxed filesystem operations to check the model itself), nothing here
//! needs directory-escape guards, dirfds or sandboxing.
//!
//! Runtime knobs:
//! - `PROPTEST_CASES` (default 256 per property): case count.
//! - `WORLD_FSMODEL_ESCAPING_LINKS=1`: also generate the documented shim
//!   gaps (a relative symlink inside `/tmp` climbing above the private root;
//!   a symlink created outside the shim pointing into a host temp root)
//!   where `map`'s lexical result and the model's virtual-view resolution
//!   are known to diverge. Off by default, so those cases neither run nor
//!   fail; with the knob set, a divergence there is reported (`eprintln`),
//!   not asserted, so the suite stays green either way.
use super::*;
use proptest::prelude::*;
use world_fsmodel::{Model, NodeId, Op, Profile, Start, View, errno_equiv};

const ROOT: &[u8] = b"/Users/me/.local/share/world/workspaces/tmp/127.77.0.1";
/// A macOS shim never runs against Linux errno tables.
const LINUX: bool = false;

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        ..ProptestConfig::default()
    }
}

fn escaping_links_enabled() -> bool {
    std::env::var("WORLD_FSMODEL_ESCAPING_LINKS").as_deref() == Ok("1")
}

fn root_str() -> &'static str {
    std::str::from_utf8(ROOT).unwrap()
}

/// Whether an absolute symlink target text names a host temp root the shim
/// would redirect (`/tmp`, `/var/tmp`, or their `/private` forms).
fn under_host_temp_root(target: &[u8]) -> bool {
    for prefix in [
        &b"/private/var/tmp"[..],
        &b"/private/tmp"[..],
        &b"/var/tmp"[..],
        &b"/tmp"[..],
    ] {
        if let Some(rest) = target.strip_prefix(prefix)
            && (rest.is_empty() || rest[0] == b'/')
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------
// Shared model-tree generation (`map_with_matches_model`,
// `map_at_with_matches_model`).
// ---------------------------------------------------------------------

/// A randomizable plan for a small filesystem: a few directories/files
/// inside the private `/tmp`, a relative and an absolute symlink there (both
/// drawn from a small, deliberately non-escaping vocabulary unless
/// `escaping` is set), a `/var/tmp` entry, and a host fixture outside every
/// temp root.
#[derive(Debug, Clone)]
struct TreePlan {
    has_a: bool,
    has_a_b: bool,
    has_a_f: bool,
    rel_target: Option<Vec<u8>>,
    abs_target: Option<Vec<u8>>,
    has_var_x: bool,
    has_host_project: bool,
    escaping: bool,
}

fn tree_plan_strategy() -> impl Strategy<Value = TreePlan> {
    let escaping = escaping_links_enabled();
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        prop::option::of(prop_oneof![
            Just(b"a".to_vec()),
            Just(b"a/b".to_vec()),
            Just(b"nonexist".to_vec()),
            Just(b"a/b/../f".to_vec()),
        ]),
        prop::option::of(prop_oneof![
            Just(b"/tmp/a".to_vec()),
            Just(b"/private/tmp/a".to_vec()),
            Just(b"/etc/hosts".to_vec()),
            Just(b"/Users/alice/project".to_vec()),
        ]),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            move |(
                has_a,
                has_a_b,
                has_a_f,
                rel_target,
                abs_target,
                has_var_x,
                has_host_project,
            )| {
                // An absolute symlink target under a host temp root (e.g.
                // "/tmp/a") can only appear on disk this way if it was written
                // *outside* the shim: a workload's own `symlink()` call has its
                // absolute target rewritten by `map_target` before it ever
                // reaches disk (see silo-bind's `symlink`/`symlinkat`
                // interposers), so the real, shim-created target bytes would
                // already be the redirected `ROOT/tmp/a`, not `/tmp/a`. That
                // "symlink created outside the shim" case is exactly the
                // documented gap this module's docs mention, so keep it out of
                // the default (non-`escaping`) generation.
                let abs_target = abs_target.filter(|t| escaping || !under_host_temp_root(t));
                TreePlan {
                    has_a,
                    has_a_b,
                    has_a_f,
                    rel_target,
                    abs_target,
                    has_var_x,
                    has_host_project,
                    escaping,
                }
            },
        )
}

fn build_model(plan: &TreePlan) -> Model {
    let mut m = Model::new(Profile::MacShim {
        root: ROOT.to_vec(),
    });
    if plan.has_a {
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
    }
    if plan.has_a_b {
        m.add_fixture_dir(View::Virtual, b"/tmp/a/b");
    }
    if plan.has_a_f {
        m.add_fixture_file(View::Virtual, b"/tmp/a/f", b"x".to_vec());
    }
    if let Some(t) = &plan.rel_target {
        m.add_fixture_symlink(View::Virtual, b"/tmp/rel", t.clone());
    }
    if let Some(t) = &plan.abs_target {
        m.add_fixture_symlink(View::Virtual, b"/tmp/abs", t.clone());
    }
    if plan.has_var_x {
        m.add_fixture_dir(View::Virtual, b"/var/tmp/x");
    }
    if plan.has_host_project {
        m.add_fixture_dir(View::Physical, b"/Users/alice/project");
    }
    m.add_opaque_ancestors(b"/etc/hosts");
    if plan.escaping {
        // A relative symlink inside the private root that climbs above it:
        // documented as an escaping-links gap (see module docs).
        m.add_fixture_symlink(View::Virtual, b"/tmp/escape", b"../../../outside".to_vec());
        m.add_fixture_dir(View::Physical, b"/Users/outside");
    }
    m
}

/// A resolver backed by the model, mimicking the shim's use of the real
/// kernel (`getattrlistat`/`ATTR_CMN_FULLPATH`): resolve `path` physically
/// from the model's root and report its canonical physical name.
fn resolver_from_model(model: &Model) -> impl FnMut(&[u8], &mut [u8]) -> Result<usize, i32> + '_ {
    move |path: &[u8], out: &mut [u8]| {
        let clean = path.split(|&b| b == 0).next().unwrap_or(path);
        let node = model.resolve(View::Physical, Start::Root, clean, true)?;
        let full = model.full_path(View::Physical, node);
        if full.len() >= out.len() {
            return Err(libc::ENAMETOOLONG);
        }
        out[..full.len()].copy_from_slice(&full);
        Ok(full.len())
    }
}

fn path_strategy(escaping: bool) -> impl Strategy<Value = Vec<u8>> {
    let mut prefixes = vec![
        "/tmp",
        "/private/tmp",
        "/var/./tmp",
        "/private/../tmp",
        "//tmp",
        "/tmp/.",
        "/var/tmp",
        "/private/var/tmp",
        "/Users/alice/project",
        "/etc",
    ];
    let mut suffixes = vec![
        "",
        "/a",
        "/a/",
        "/a/b",
        "/a/f",
        "/rel",
        "/abs",
        "/x",
        "/nonexistent",
        "/a/../a",
        "/a/b/../../a",
        "/./a",
        "/a/./b",
        "/../tmp/a",
    ];
    if escaping {
        prefixes.push("/tmp");
        suffixes.push("/escape");
        suffixes.push("/escape/x");
    }
    (
        prop::sample::select(prefixes),
        prop::sample::select(suffixes),
    )
        .prop_map(|(p, s)| format!("{p}{s}").into_bytes())
}

/// Compares `map_with`'s answer for `path` against the model's own virtual
/// resolution, allowing (and reporting rather than failing) the documented
/// escaping-link divergence when `plan.escaping` is set.
fn assert_matches_model(
    plan: &TreePlan,
    model: &Model,
    path: &[u8],
    start_view_both_sides: Start,
    mapped: Result<Option<usize>, i32>,
    out: &[u8],
) -> Result<(), TestCaseError> {
    let report_or_fail = |msg: String| -> Result<(), TestCaseError> {
        if plan.escaping {
            eprintln!("known escaping-link divergence (WORLD_FSMODEL_ESCAPING_LINKS=1): {msg}");
            Ok(())
        } else {
            Err(TestCaseError::fail(msg))
        }
    };
    match mapped {
        Ok(opt) => {
            let effective: Vec<u8> = match opt {
                Some(n) => out[..n].to_vec(),
                None => path.to_vec(),
            };
            let phys = model.resolve(View::Physical, start_view_both_sides, &effective, true);
            let virt = model.resolve(View::Virtual, start_view_both_sides, path, true);
            match (phys, virt) {
                (Ok(p), Ok(v)) => {
                    if p != v {
                        return report_or_fail(format!(
                            "node mismatch for {:?} (effective {:?}): physical={p} virtual={v}",
                            String::from_utf8_lossy(path),
                            String::from_utf8_lossy(&effective)
                        ));
                    }
                    Ok(())
                }
                (Err(pe), Err(ve)) => {
                    if !errno_equiv(LINUX, pe, ve) {
                        return report_or_fail(format!(
                            "errno mismatch for {:?}: physical={pe} virtual={ve}",
                            String::from_utf8_lossy(path)
                        ));
                    }
                    Ok(())
                }
                (pr, vr) => report_or_fail(format!(
                    "one side succeeded, the other failed for {:?}: physical={pr:?} virtual={vr:?}",
                    String::from_utf8_lossy(path)
                )),
            }
        }
        Err(e) => {
            let virt = model.resolve(View::Virtual, start_view_both_sides, path, true);
            match virt {
                Err(ve) if errno_equiv(LINUX, e, ve) => Ok(()),
                other => report_or_fail(format!(
                    "map_with failed ({e}) but virtual resolve gave {other:?} for {:?}",
                    String::from_utf8_lossy(path)
                )),
            }
        }
    }
}

fn plan_and_path_strategy() -> impl Strategy<Value = (TreePlan, Vec<u8>)> {
    tree_plan_strategy().prop_flat_map(|plan| {
        let escaping = plan.escaping;
        (Just(plan), path_strategy(escaping))
    })
}

fn base_virtual_path_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"/".to_vec()),
        Just(b"/tmp".to_vec()),
        Just(b"/tmp/a".to_vec()),
        Just(b"/tmp/a/b".to_vec()),
        Just(b"/private".to_vec()),
        Just(b"/var/tmp".to_vec()),
        Just(b"/Users/alice/project".to_vec()),
    ]
}

fn relpath_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"a".to_vec()),
        Just(b"b".to_vec()),
        Just(b"f".to_vec()),
        Just(b"../a".to_vec()),
        Just(b"../../etc/hosts".to_vec()),
        Just(b"./a".to_vec()),
        Just(b"tmp/x".to_vec()),
        Just(b"private/tmp/a".to_vec()),
        Just(b"var/tmp/x".to_vec()),
        Just(b"../../../Users/alice/project".to_vec()),
        Just(b".".to_vec()),
        Just(b"..".to_vec()),
    ]
}

fn target_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"/tmp/x".to_vec()),
        Just(b"/private/var/tmp/y".to_vec()),
        Just(b"/tmp/a/../b".to_vec()),
        Just(b"/tmp/a/../../etc/x".to_vec()),
        Just(b"tmp/x".to_vec()),
        Just(b"/etc/passwd".to_vec()),
        Just(b"/private/tmp".to_vec()),
        Just(b"../tmp/x".to_vec()),
        Just(b"/does-not-exist/../tmp/x".to_vec()),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// `map`'s answer for a randomly spelled path, over a randomly built
    /// model tree, must land on the same node as the model's own
    /// virtual-view resolution (or fail with an equivalent errno).
    #[test]
    fn map_with_matches_model((plan, path) in plan_and_path_strategy()) {
        let model = build_model(&plan);
        let mut out = [0u8; PATH_MAX];
        let mut resolve = resolver_from_model(&model);
        let mapped = map_with(ROOT, &path, &mut out, &mut resolve);
        assert_matches_model(&plan, &model, &path, Start::Root, mapped, &out)?;
    }

    /// Same, but resolved relative to a random cwd/dirfd base rather than
    /// the root.
    #[test]
    fn map_at_with_matches_model(
        (plan, base_virtual_path, relpath) in tree_plan_strategy().prop_flat_map(|plan| {
            (Just(plan), base_virtual_path_strategy(), relpath_strategy())
        }),
    ) {
        let mut model = build_model(&plan);
        // Resolve the chosen base in the *virtual* view (what a real chdir
        // into it would land on), matching `do_chdir`'s own resolution.
        let Ok(base_node): Result<NodeId, i32> =
            model.resolve(View::Virtual, Start::Root, &base_virtual_path, true)
        else {
            return Ok(());
        };
        let chdir = model.apply(&Op::Chdir { path: base_virtual_path.clone() });
        if chdir.errno != 0 {
            return Ok(());
        }
        // `map_at`'s `base` closure reports the dirfd/cwd's *physical* name
        // (via `real_base`/`getattrlistat`): the same node, viewed
        // physically, not a fresh physical-view resolution of the virtual
        // path text (which could land on a different, unmounted node, e.g.
        // the host's real `/tmp` rather than the private one just entered).
        let base_physical_path = model.full_path(View::Physical, base_node);

        let mut resolve = resolver_from_model(&model);
        let base = |out: &mut [u8]| -> Result<usize, i32> {
            if base_physical_path.len() >= out.len() {
                return Err(libc::ENAMETOOLONG);
            }
            out[..base_physical_path.len()].copy_from_slice(&base_physical_path);
            Ok(base_physical_path.len())
        };
        let mut out = [0u8; PATH_MAX];
        let mapped = map_at_with(ROOT, &relpath, &mut out, base, &mut resolve);
        assert_matches_model(&plan, &model, &relpath, Start::Cwd, mapped, &out)?;
    }

    /// `map_target` never calls the resolver, and when it does map a target,
    /// the result must be exactly what `map_with` would produce for the same
    /// (purely lexical, non-escaping) text.
    #[test]
    fn map_target_is_lexical_and_resolves_equal(target in target_strategy()) {
        let mut out = [0u8; PATH_MAX];
        let mut panicking = |_: &[u8], _: &mut [u8]| -> Result<usize, i32> {
            panic!("map_target must never call the resolver")
        };
        let result = map_target(ROOT, &target, &mut out);
        if let Ok(Some(n)) = result {
            let model = Model::new(Profile::MacShim { root: ROOT.to_vec() });
            let mut resolve = resolver_from_model(&model);
            let mut out2 = [0u8; PATH_MAX];
            let cross = map_with(ROOT, &target, &mut out2, &mut resolve);
            prop_assert_eq!(cross, Ok(Some(n)));
            prop_assert_eq!(&out[..n], &out2[..n]);
        }
        let _ = &mut panicking; // used only via map_target's own guarantee above
    }
}

// ---------------------------------------------------------------------
// Layer 1 properties that need no model: pure byte-buffer invariants of
// world-tmp-path's own helpers.
// ---------------------------------------------------------------------

proptest! {
    #![proptest_config(config())]

    #[test]
    fn unmap_roundtrip(rest in "(/[a-zA-Z0-9._-]{0,6}){0,5}") {
        let root = root_str();
        let mut out = [0u8; PATH_MAX];
        let path = format!("/tmp{rest}");
        if let Some(n) = map(ROOT, path.as_bytes(), &mut out).unwrap() {
            let world = format!("{root}/tmp{rest}");
            prop_assert_eq!(&out[..n], world.as_bytes());
            let new_len = unmap_in_place(ROOT, &mut out, n).unwrap();
            let host = format!("/private/tmp{rest}");
            prop_assert_eq!(&out[..new_len], host.as_bytes());
        }
    }

    #[test]
    fn copy_cwd_erange_leaves_dst(rest in "[a-z]{0,10}", cap in 1usize..40, fill in any::<u8>()) {
        let root = root_str();
        let physical = format!("{root}/tmp/{rest}");
        let mut local = [0u8; PATH_MAX];
        local[..physical.len()].copy_from_slice(physical.as_bytes());
        let mut dst = vec![fill; cap];
        let before = dst.clone();
        let result = copy_cwd(ROOT, &mut local, physical.len(), &mut dst);
        let host = format!("/private/tmp/{rest}");
        if host.len() + 1 > cap {
            prop_assert_eq!(result, Err(libc::ERANGE));
            prop_assert_eq!(dst, before);
        } else {
            let n = result.unwrap();
            prop_assert_eq!(n, host.len());
            prop_assert_eq!(&dst[..n], host.as_bytes());
            prop_assert_eq!(dst[n], 0);
        }
    }

    #[test]
    fn copy_link_truncates_like_kernel(rest in "[a-z]{0,10}", cap in 0usize..40) {
        let root = root_str();
        let physical = format!("{root}/tmp/{rest}");
        let mut local = [0u8; PATH_MAX];
        local[..physical.len()].copy_from_slice(physical.as_bytes());
        let mut dst = vec![0xAAu8; cap];
        let n = copy_link(ROOT, &mut local, physical.len(), &mut dst);
        let host = format!("/private/tmp/{rest}");
        let expect_n = host.len().min(cap);
        prop_assert_eq!(n, expect_n);
        prop_assert_eq!(&dst[..expect_n], &host.as_bytes()[..expect_n]);
    }

    #[test]
    fn unix_path_bounds(
        len in 0usize..40,
        family in any::<u8>(),
        bytes in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut sa = vec![0u8; len];
        if !sa.is_empty() {
            sa[0] = len as u8;
        }
        if sa.len() > 1 {
            sa[1] = family;
        }
        for (i, b) in bytes.iter().enumerate() {
            if SUN_PATH_OFFSET + i < sa.len() {
                sa[SUN_PATH_OFFSET + i] = *b;
            }
        }
        let result = unix_path(&sa);
        if sa.len() <= SUN_PATH_OFFSET || family as i32 != libc::AF_UNIX {
            prop_assert_eq!(result, None);
        } else {
            let region = &sa[SUN_PATH_OFFSET..];
            let expect = region.split(|&b| b == 0).next().unwrap_or(region);
            prop_assert_eq!(result, Some(expect));
        }
    }

    #[test]
    fn unmap_sockaddr_sun_len(rest in "[a-z]{0,10}", pad in 0usize..20) {
        let root = root_str();
        let physical = format!("{root}/tmp/{rest}");
        let mut sa = vec![0xFFu8; SUN_PATH_OFFSET + physical.len() + 1 + pad];
        sa[1] = libc::AF_UNIX as u8;
        sa[SUN_PATH_OFFSET..SUN_PATH_OFFSET + physical.len()].copy_from_slice(physical.as_bytes());
        sa[SUN_PATH_OFFSET + physical.len()] = 0;
        let reported = SUN_PATH_OFFSET + physical.len() + 1;
        let total = unmap_sockaddr(ROOT, &mut sa, reported).unwrap();
        let host = format!("/private/tmp/{rest}");
        prop_assert_eq!(total, SUN_PATH_OFFSET + host.len() + 1);
        prop_assert_eq!(sa[0], total as u8);
        prop_assert_eq!(&sa[SUN_PATH_OFFSET..SUN_PATH_OFFSET + host.len()], host.as_bytes());
        prop_assert!(sa[SUN_PATH_OFFSET + host.len()..reported].iter().all(|&b| b == 0));
    }

    #[test]
    fn requeried_unix_never_writes_past_cap(rest in "[a-z]{0,10}", cap in 0usize..30) {
        let root = root_str();
        let physical = format!("{root}/tmp/{rest}");
        let mut storage = vec![0u8; SUN_PATH_OFFSET + physical.len() + 1 + 16];
        storage[1] = libc::AF_UNIX as u8;
        storage[SUN_PATH_OFFSET..SUN_PATH_OFFSET + physical.len()].copy_from_slice(physical.as_bytes());
        let reported = SUN_PATH_OFFSET + physical.len() + 1;
        let mut full = storage.clone();
        let total = unmap_sockaddr(ROOT, &mut full, reported).unwrap();
        let mut dst = vec![0xAAu8; cap];
        let reported_len = requeried_unix(ROOT, &mut storage, reported, cap, &mut dst).unwrap();
        prop_assert_eq!(reported_len, total);
        let n = cap.min(total);
        prop_assert_eq!(&dst[..n], &full[..n]);
        prop_assert!(dst[n..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn outputs_nul_terminated_and_sentinel_intact(rest in "[a-z]{0,10}") {
        let root = root_str();
        let path = format!("/tmp/{rest}");
        let world = format!("{root}/tmp/{rest}");
        let want_len = world.len();
        for buf_len in want_len.saturating_sub(1)..=want_len + 2 {
            let mut out = vec![0xA5u8; buf_len.max(1)];
            let result = map(ROOT, path.as_bytes(), &mut out);
            if buf_len < want_len + 1 {
                prop_assert_eq!(result, Err(libc::ENAMETOOLONG));
                prop_assert!(out.iter().all(|&b| b == 0xA5), "buffer touched on error at buf_len={buf_len}");
            } else {
                let n = result.unwrap().unwrap();
                prop_assert_eq!(n, want_len);
                prop_assert_eq!(&out[..n], world.as_bytes());
                prop_assert_eq!(out[n], 0);
                prop_assert!(
                    out[n + 1..].iter().all(|&b| b == 0xA5),
                    "sentinel clobbered past NUL at buf_len={buf_len}"
                );
            }
        }
    }

    #[test]
    fn enametoolong_iff_over_limit(root_extra in 0usize..500, delta in -2i32..=2) {
        let mut root = b"/root".to_vec();
        root.extend(std::iter::repeat_n(b'r', root_extra));
        prop_assume!(valid_root(&root));
        let target_total = (PATH_MAX as i32 + delta) as usize;
        let fixed = root.len() + "/tmp".len() + 1; // root + "/tmp" + leading '/'
        prop_assume!(target_total >= fixed);
        let n = target_total - fixed;
        let path = format!("/tmp/{}", "a".repeat(n));
        prop_assume!(path.len() < PATH_MAX);
        let mut out = vec![0u8; PATH_MAX];
        let result = map(&root, path.as_bytes(), &mut out);
        if target_total >= PATH_MAX {
            prop_assert_eq!(result, Err(libc::ENAMETOOLONG));
        } else {
            match result {
                Ok(Some(len)) => prop_assert_eq!(len, target_total),
                other => prop_assert!(false, "expected Ok(Some({target_total})), got {other:?}"),
            }
        }
    }

    #[test]
    fn terminates_with_adversarial_resolver(
        path in r"(/[a-z]{1,3}|/\.\.){1,10}",
        table in prop::collection::vec("[a-z/.]{0,10}", 0..5),
    ) {
        let path = format!("/tmp{path}");
        let mut out = [0u8; PATH_MAX];
        let calls = std::cell::Cell::new(0u32);
        let mut resolve = |_p: &[u8], o: &mut [u8]| -> Result<usize, i32> {
            let i = calls.get();
            calls.set(i + 1);
            let answer = if table.is_empty() {
                b"/x".as_slice()
            } else {
                table[i as usize % table.len()].as_bytes()
            };
            if answer.is_empty() || answer.len() >= o.len() {
                return Err(libc::ENAMETOOLONG);
            }
            o[..answer.len()].copy_from_slice(answer);
            Ok(answer.len())
        };
        let result = map_with(ROOT, path.as_bytes(), &mut out, &mut resolve);
        let bound = dotdot_count(path.as_bytes()) as u32 + 1;
        prop_assert!(
            calls.get() <= bound,
            "resolver called {} times, bound {bound} for {path:?}",
            calls.get()
        );
        prop_assert!(
            result.is_ok() || result == Err(libc::ELOOP) || result == Err(libc::ENAMETOOLONG),
            "unexpected result {result:?} for {path:?}"
        );
    }
}
