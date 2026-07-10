//! `.rpol` module resolution (LAN-300, ADR-0103 Decision 8.1 /
//! plan item 5).
//!
//! Modules are a **frontend feature with no IR change**: `import
//! "lib/common.rpol"` declarations are resolved here — against the
//! importing file's directory and the configured policy roots — into
//! one merged compilation unit that the typechecker and lowerer see as
//! a single [`ast::SourceFile`]. After resolution the compiled
//! artifact is indistinguishable from a concatenated single source;
//! only span attribution (each [`Span`] carries its module index)
//! remembers the file boundaries.
//!
//! Resolution rules:
//!
//! - Import paths are **relative** (absolute paths are rejected) and
//!   resolve against the importing file's directory first, then each
//!   configured root in declaration order. The first candidate that
//!   exists wins.
//! - Every resolved file is canonicalized before it is read (the
//!   LAN-218 TOCTOU discipline), and the canonical path must stay
//!   inside one of the roots (the main file's directory is always a
//!   root). Symlinks that resolve inside a root are fine; symlinks or
//!   `..` traversal escaping every root are compile errors.
//! - The import graph is a DAG walked depth-first following
//!   declaration order — resolution order never depends on filesystem
//!   iteration, so identical graphs compile identically (ADR-0103
//!   Decision 5.1). Diamond imports load once; cycles are compile
//!   errors naming the cycle (the `apply`/`fn` DAG precedent).
//! - Budgets: [`MAX_MODULE_DEPTH`] import nesting, [`MAX_FILE_BYTES`]
//!   per file, [`MAX_GRAPH_BYTES`] and [`MAX_MODULE_FILES`] for the
//!   whole graph.
//! - The merge appends definitions dependency-first (post-order), main
//!   file last; all definitions share one flat namespace and duplicate
//!   names across modules are compile errors naming both files (the
//!   typechecker's existing duplicate check over the merged unit).
//!
//! Everything here runs at load/reload time only — evaluation never
//! touches the filesystem (ADR-0103 Decision 7).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::ast;
use super::diag::{Diagnostic, Diagnostics, Span, Spanned};
use super::parser;

/// Maximum import nesting depth (ADR-0103 Decision 3): the main file
/// is depth 0; an import chain deeper than this is a compile error.
pub const MAX_MODULE_DEPTH: u32 = 8;

/// Maximum size of one `.rpol` source file (ADR-0103 Decision 3:
/// load-time reject).
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// Maximum total source size of a resolved module graph.
pub const MAX_GRAPH_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of files in a resolved module graph.
pub const MAX_MODULE_FILES: usize = 64;

/// One resolved module of a compile: its display path, source text,
/// resolved import edges, and content digest. Index in
/// [`crate::rpol::RpolFile::modules`] = the `file` index spans carry.
#[derive(Debug, Clone)]
pub struct ModuleSource {
    /// Canonical filesystem path (`"<inline>"` for source-only parses).
    pub path: String,
    /// The module's source text.
    pub text: String,
    /// Module indices this module imports, in declaration order.
    pub imports: Vec<u32>,
    /// Lowercase-hex SHA-256 of `text` — the audit-facing content
    /// hash printed by `rbgp policy check --list-deps`.
    pub digest: String,
}

impl ModuleSource {
    pub(super) fn inline(text: &str) -> Self {
        Self {
            path: "<inline>".to_string(),
            text: text.to_string(),
            imports: Vec::new(),
            digest: digest_hex(text),
        }
    }
}

/// Lowercase-hex SHA-256 of a module text.
fn digest_hex(text: &str) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(text.as_bytes()) {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Why a file-based `.rpol` load failed.
#[derive(Debug)]
pub enum LoadError {
    /// The main file (or a configured root) could not be resolved or
    /// read — there is no source to attribute diagnostics to.
    Io {
        /// The offending path, as given.
        path: String,
        /// Human-readable reason.
        reason: String,
    },
    /// Compilation failed; diagnostics span the resolved module graph.
    Compile {
        /// `(display path, text)` per module index, for rendering.
        sources: Vec<(String, String)>,
        /// Every diagnostic found, across all modules.
        diagnostics: Diagnostics,
    },
}

impl LoadError {
    /// Render the error for humans (ariadne excerpts for compile
    /// errors, a plain line for I/O errors).
    #[must_use]
    pub fn render(&self, color: bool) -> String {
        match self {
            LoadError::Io { path, reason } => format!("{path}: {reason}"),
            LoadError::Compile {
                sources,
                diagnostics,
            } => diagnostics.render_sources(sources, color),
        }
    }

    /// The diagnostics of a compile failure, if that is what this is.
    #[must_use]
    pub fn diagnostics(&self) -> Option<&Diagnostics> {
        match self {
            LoadError::Io { .. } => None,
            LoadError::Compile { diagnostics, .. } => Some(diagnostics),
        }
    }
}

/// A fully resolved (but not yet typechecked) module graph: per-module
/// sources in discovery order (index = span `file`) and the merged
/// compilation unit.
pub(super) struct ResolvedGraph {
    pub(super) modules: Vec<ModuleSource>,
    pub(super) merged: ast::SourceFile,
}

/// Resolve `main_path`'s import graph. `roots` are the configured
/// policy roots (the main file's directory is always added). Returns
/// the resolved graph, or an error for unreadable inputs / resolution
/// and parse diagnostics.
pub(super) fn resolve(main_path: &Path, roots: &[PathBuf]) -> Result<ResolvedGraph, LoadError> {
    let io = |path: &Path, reason: String| LoadError::Io {
        path: path.display().to_string(),
        reason,
    };
    let main_canon = main_path
        .canonicalize()
        .map_err(|e| io(main_path, format!("failed to read: {e}")))?;
    let main_dir = main_canon
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io(main_path, "file has no parent directory".to_string()))?;

    // Confinement roots: the main file's directory plus every
    // configured root, canonicalized. A configured root that does not
    // exist is a load error — a silently dropped root would quietly
    // change which file an import resolves to.
    let mut confine: Vec<PathBuf> = vec![main_dir];
    for root in roots {
        confine.push(
            root.canonicalize()
                .map_err(|e| io(root, format!("policy root is unusable: {e}")))?,
        );
    }

    let mut resolver = Resolver {
        confine,
        modules: Vec::new(),
        asts: Vec::new(),
        canon: Vec::new(),
        index: HashMap::new(),
        in_progress: Vec::new(),
        post_order: Vec::new(),
        total_bytes: 0,
        diags: Vec::new(),
    };
    let text = std::fs::read_to_string(&main_canon)
        .map_err(|e| io(main_path, format!("failed to read: {e}")))?;
    resolver.visit(main_canon, text, 0);

    let sources: Vec<(String, String)> = resolver
        .modules
        .iter()
        .map(|m| (m.path.clone(), m.text.clone()))
        .collect();
    if !resolver.diags.is_empty() {
        return Err(LoadError::Compile {
            sources,
            diagnostics: Diagnostics(resolver.diags),
        });
    }

    // Merge dependency-first (post-order); the main file — visited
    // first, finished last — lands at the end, so `compile_rpol`'s
    // "zero-parameter policies in source order" reads as imports
    // first, then the main file, deterministically.
    let mut merged = ast::SourceFile::default();
    let mut asts = resolver.asts;
    for &id in &resolver.post_order {
        let module = std::mem::take(&mut asts[id as usize]);
        merged.prefix_sets.extend(module.prefix_sets);
        merged.community_sets.extend(module.community_sets);
        merged.asn_sets.extend(module.asn_sets);
        merged.fns.extend(module.fns);
        merged.policies.extend(module.policies);
        merged.tests.extend(module.tests);
    }
    Ok(ResolvedGraph {
        modules: resolver.modules,
        merged,
    })
}

struct Resolver {
    /// Canonicalized confinement roots (main dir + configured roots).
    confine: Vec<PathBuf>,
    /// Per-module metadata, indexed by module (`file`) id.
    modules: Vec<ModuleSource>,
    /// Parsed ASTs, same indexing (consumed by the merge).
    asts: Vec<ast::SourceFile>,
    /// Canonical paths, same indexing.
    canon: Vec<PathBuf>,
    /// Canonical path → module id (diamond dedupe + cycle detection).
    index: HashMap<PathBuf, u32>,
    /// Whether a module is still on the DFS stack.
    in_progress: Vec<bool>,
    /// Dependency-first merge order.
    post_order: Vec<u32>,
    /// Running total of loaded source bytes.
    total_bytes: usize,
    /// Resolution + parse diagnostics, across all modules.
    diags: Vec<Diagnostic>,
}

impl Resolver {
    /// Load, parse, and recurse into one module whose canonical path
    /// and text are already in hand. Returns its module id.
    fn visit(&mut self, canon: PathBuf, text: String, depth: u32) -> u32 {
        let id = u32::try_from(self.modules.len()).expect("MAX_MODULE_FILES bounds the count");
        let display = canon.display().to_string();
        self.index.insert(canon.clone(), id);
        self.canon.push(canon);
        let text_len = text.len();
        self.total_bytes += text_len;
        let (ast, mut parse_diags) = parser::parse_module(&text, id);
        self.diags.append(&mut parse_diags);
        let digest = digest_hex(&text);
        self.modules.push(ModuleSource {
            path: display,
            text,
            imports: Vec::new(),
            digest,
        });
        self.asts.push(ast::SourceFile::default());
        self.in_progress.push(true);

        if text_len > MAX_FILE_BYTES {
            self.diags.push(Diagnostic::new(
                Span::in_file(0..0, id),
                format!("`.rpol` file is {text_len} bytes; the per-file limit is {MAX_FILE_BYTES}"),
                "this file is too large",
            ));
        }
        if self.total_bytes > MAX_GRAPH_BYTES {
            self.diags.push(Diagnostic::new(
                Span::in_file(0..0, id),
                format!(
                    "resolved module graph exceeds {MAX_GRAPH_BYTES} total source bytes \
                     at this file"
                ),
                "graph source budget exhausted here",
            ));
        }

        // Resolve this module's imports in declaration order.
        let imports = ast.imports.clone();
        let mut edges = Vec::with_capacity(imports.len());
        for import in &imports {
            if let Some(dep) = self.resolve_import(id, import, depth) {
                edges.push(dep);
            }
        }
        self.modules[id as usize].imports = edges;
        self.asts[id as usize] = ast;
        self.in_progress[id as usize] = false;
        self.post_order.push(id);
        id
    }

    /// Resolve one `import "path"` declaration of module `importer` at
    /// nesting `depth`. Returns the imported module's id, or `None`
    /// with a diagnostic recorded.
    fn resolve_import(
        &mut self,
        importer: u32,
        import: &Spanned<String>,
        depth: u32,
    ) -> Option<u32> {
        let rel = Path::new(&import.node);
        if rel.is_absolute() {
            self.diags.push(
                Diagnostic::new(
                    import.span,
                    format!("import path {:?} is absolute", import.node),
                    "imports must be relative paths",
                )
                .with_note(
                    "imports resolve against the importing file's directory and the configured \
                 policy roots",
                ),
            );
            return None;
        }
        if depth >= MAX_MODULE_DEPTH {
            self.diags.push(Diagnostic::new(
                import.span,
                format!("imports nest more than {MAX_MODULE_DEPTH} deep"),
                "this import exceeds the module depth budget",
            ));
            return None;
        }

        // Candidate order: the importing file's directory, then each
        // configured root — declaration order, never filesystem order.
        let importer_dir = self.canon[importer as usize]
            .parent()
            .map(Path::to_path_buf)
            .expect("canonicalized module paths have parents");
        let mut candidates = vec![importer_dir];
        candidates.extend(self.confine[1..].iter().cloned());
        let Some(canon) = candidates
            .iter()
            .find_map(|dir| dir.join(rel).canonicalize().ok())
        else {
            self.diags.push(Diagnostic::new(
                import.span,
                format!("cannot resolve import {:?}", import.node),
                "not found relative to this file or any configured policy root",
            ));
            return None;
        };
        if !self.confine.iter().any(|root| canon.starts_with(root)) {
            self.diags.push(
                Diagnostic::new(
                    import.span,
                    format!(
                        "import {:?} escapes the configured policy roots",
                        import.node
                    ),
                    format!("resolves to {}", canon.display()),
                )
                .with_note(
                    "imports (including symlink targets) must stay under the main file's \
                     directory or a configured policy root",
                ),
            );
            return None;
        }

        if let Some(&existing) = self.index.get(&canon) {
            if self.in_progress[existing as usize] {
                // Name the cycle like the `fn` / `apply` DAG errors.
                let start = existing as usize;
                let mut names: Vec<String> = self
                    .modules
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| self.in_progress[*i] && *i >= start)
                    .map(|(_, m)| m.path.clone())
                    .collect();
                names.push(self.modules[existing as usize].path.clone());
                self.diags.push(Diagnostic::new(
                    import.span,
                    format!("import cycle: {}", names.join(" -> ")),
                    "this import closes the cycle",
                ));
                return None;
            }
            return Some(existing); // diamond: already loaded once
        }

        if self.modules.len() >= MAX_MODULE_FILES {
            self.diags.push(Diagnostic::new(
                import.span,
                format!("module graph has more than {MAX_MODULE_FILES} files"),
                "file-count budget exhausted at this import",
            ));
            return None;
        }
        let text = match std::fs::read_to_string(&canon) {
            Ok(text) => text,
            Err(e) => {
                self.diags.push(Diagnostic::new(
                    import.span,
                    format!("cannot read import {:?}: {e}", import.node),
                    "failed to read this import",
                ));
                return None;
            }
        };
        Some(self.visit(canon, text, depth + 1))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::super::RpolFile;
    use super::*;
    use crate::sets::SetStore;

    fn write(dir: &Path, rel: &str, text: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, text).expect("write");
    }

    fn load(dir: &Path, main: &str) -> Result<RpolFile, LoadError> {
        RpolFile::load(&dir.join(main), &[])
    }

    /// The rendered compile error of a load expected to fail.
    fn load_err(dir: &Path, main: &str) -> String {
        match load(dir, main) {
            Ok(_) => panic!("load unexpectedly succeeded"),
            Err(err) => err.render(false),
        }
    }

    const BOGONS: &str = "prefix-set bogons { 10.0.0.0/8 le 32, 192.168.0.0/16 le 32 }";

    #[test]
    fn import_resolves_relative_to_the_importing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Nested: main -> lib/sets.rpol -> deep/asns.rpol (relative to lib/).
        write(
            dir.path(),
            "lib/deep/asns.rpol",
            "asn-set transit { 65010, 65020 }",
        );
        write(
            dir.path(),
            "lib/sets.rpol",
            &format!("import \"deep/asns.rpol\"\n{BOGONS}"),
        );
        write(
            dir.path(),
            "main.rpol",
            "import \"lib/sets.rpol\"\n\
             policy edge-in {\n\
               term bogon { if route.prefix in bogons { reject } }\n\
               term transit { if route.origin-as in transit { set local-pref 50; accept } }\n\
               term rest { accept }\n\
             }",
        );
        let file = load(dir.path(), "main.rpol").expect("clean load");
        assert_eq!(file.modules().len(), 3, "main + 2 modules");
        // Module 0 is the main file; discovery order follows declarations.
        assert!(file.modules()[0].path.ends_with("main.rpol"));
        assert!(file.modules()[1].path.ends_with("sets.rpol"));
        assert!(file.modules()[2].path.ends_with("asns.rpol"));
        assert_eq!(file.modules()[0].imports, vec![1]);
        assert_eq!(file.modules()[1].imports, vec![2]);
        let mut store = SetStore::new();
        assert!(file.compile_policy("edge-in", &[], &mut store).is_some());
    }

    #[test]
    fn import_resolves_via_a_configured_root() {
        let main_dir = tempfile::tempdir().expect("tempdir");
        let lib_dir = tempfile::tempdir().expect("tempdir");
        write(lib_dir.path(), "common/bogons.rpol", BOGONS);
        write(
            main_dir.path(),
            "main.rpol",
            "import \"common/bogons.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        // Without the root the import cannot resolve …
        let err = load_err(main_dir.path(), "main.rpol");
        assert!(err.contains("cannot resolve import"), "{err}");
        // … with it, it does.
        let file = RpolFile::load(
            &main_dir.path().join("main.rpol"),
            &[lib_dir.path().to_path_buf()],
        )
        .expect("clean load with root");
        assert_eq!(file.modules().len(), 2);
    }

    #[test]
    fn traversal_above_every_root_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "outside.rpol", BOGONS);
        write(
            dir.path(),
            "nested/main.rpol",
            "import \"../outside.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        let err = load_err(dir.path(), "nested/main.rpol");
        assert!(err.contains("escapes the configured policy roots"), "{err}");
        // The same file is fine when its directory IS a root.
        let file = RpolFile::load(
            &dir.path().join("nested/main.rpol"),
            &[dir.path().to_path_buf()],
        )
        .expect("clean load once the parent is a root");
        assert_eq!(file.modules().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_a_root_is_fine_and_dedupes_with_its_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "real.rpol", BOGONS);
        std::os::unix::fs::symlink(dir.path().join("real.rpol"), dir.path().join("link.rpol"))
            .expect("symlink");
        // Diamond through a symlink: both spellings canonicalize to the
        // same module — loaded once, no duplicate-set diagnostics.
        write(
            dir.path(),
            "main.rpol",
            "import \"link.rpol\"\nimport \"real.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        let file = load(dir.path(), "main.rpol").expect("clean load");
        assert_eq!(file.modules().len(), 2, "symlink and target are one module");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_every_root_is_rejected() {
        let outside = tempfile::tempdir().expect("tempdir");
        write(outside.path(), "real.rpol", BOGONS);
        let dir = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(
            outside.path().join("real.rpol"),
            dir.path().join("link.rpol"),
        )
        .expect("symlink");
        write(
            dir.path(),
            "main.rpol",
            "import \"link.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("escapes the configured policy roots"), "{err}");
    }

    #[test]
    fn absolute_import_paths_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "lib.rpol", BOGONS);
        write(
            dir.path(),
            "main.rpol",
            &format!(
                "import {:?}\npolicy p {{ term t {{ if route.prefix in bogons {{ reject }} }} }}",
                dir.path().join("lib.rpol").display().to_string()
            ),
        );
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("is absolute"), "{err}");
    }

    #[test]
    fn a_missing_import_names_the_declaration() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "main.rpol", "import \"nope.rpol\"");
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("cannot resolve import \"nope.rpol\""), "{err}");
        assert!(err.contains("main.rpol"), "names the importing file: {err}");
    }

    #[test]
    fn an_import_cycle_is_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "a.rpol", "import \"b.rpol\"");
        write(dir.path(), "b.rpol", "import \"a.rpol\"");
        let err = load_err(dir.path(), "a.rpol");
        assert!(err.contains("import cycle"), "{err}");
        assert!(err.contains("a.rpol") && err.contains("b.rpol"), "{err}");
    }

    #[test]
    fn diamond_imports_load_the_shared_module_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "d.rpol", BOGONS);
        write(
            dir.path(),
            "b.rpol",
            "import \"d.rpol\"\npolicy from-b { term t { if route.prefix in bogons { reject } } }",
        );
        write(
            dir.path(),
            "c.rpol",
            "import \"d.rpol\"\npolicy from-c { term t { if route.prefix in bogons { reject } } }",
        );
        write(
            dir.path(),
            "main.rpol",
            "import \"b.rpol\"\nimport \"c.rpol\"",
        );
        let file = load(dir.path(), "main.rpol").expect("diamond loads");
        assert_eq!(file.modules().len(), 4, "d.rpol loads once");
        let mut store = SetStore::new();
        assert!(file.compile_policy("from-b", &[], &mut store).is_some());
        assert!(file.compile_policy("from-c", &[], &mut store).is_some());
    }

    #[test]
    fn duplicate_names_across_modules_error_naming_both_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "a.rpol", "policy dup { term t { accept } }");
        write(dir.path(), "b.rpol", "policy dup { term t { reject } }");
        write(
            dir.path(),
            "main.rpol",
            "import \"a.rpol\"\nimport \"b.rpol\"",
        );
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("duplicate policy `dup`"), "{err}");
        assert!(
            err.contains("a.rpol") && err.contains("b.rpol"),
            "both defining files are named: {err}"
        );
    }

    #[test]
    fn resolution_order_is_declaration_driven_and_compiled_identity_is_stable() {
        // The same definitions reached through differently-ordered
        // imports compile to structurally equal chains (ADR-0103
        // Decision 5.1: deterministic module-resolution order).
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "b.rpol", BOGONS);
        write(dir.path(), "c.rpol", "asn-set transit { 65010, 65020 }");
        let policy = "policy edge-in {\n\
             term bogon { if route.prefix in bogons { reject } }\n\
             term transit { if route.origin-as in transit { set local-pref 50; accept } }\n\
           }";
        write(
            dir.path(),
            "one.rpol",
            &format!("import \"b.rpol\"\nimport \"c.rpol\"\n{policy}"),
        );
        write(
            dir.path(),
            "two.rpol",
            &format!("import \"c.rpol\"\nimport \"b.rpol\"\n{policy}"),
        );
        let one = load(dir.path(), "one.rpol").expect("one loads");
        let two = load(dir.path(), "two.rpol").expect("two loads");
        let mut store_one = SetStore::new();
        let mut store_two = SetStore::new();
        let chain_one = one
            .compile_policy("edge-in", &[], &mut store_one)
            .expect("compiles");
        let chain_two = two
            .compile_policy("edge-in", &[], &mut store_two)
            .expect("compiles");
        assert_eq!(
            chain_one, chain_two,
            "import declaration order must not change the compiled identity"
        );
    }

    #[test]
    fn import_depth_eight_is_fine_and_nine_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Chain main(depth 0) -> m1 -> … -> m8 (depth 8): allowed.
        write(dir.path(), "m8.rpol", BOGONS);
        for level in (1..8).rev() {
            write(
                dir.path(),
                &format!("m{level}.rpol"),
                &format!("import \"m{}.rpol\"", level + 1),
            );
        }
        write(dir.path(), "main.rpol", "import \"m1.rpol\"");
        let file = load(dir.path(), "main.rpol").expect("depth 8 loads");
        assert_eq!(file.modules().len(), 9);

        // One more level: m8 imports m9 — the edge at depth 8 exceeds
        // the budget.
        write(dir.path(), "m9.rpol", BOGONS);
        write(dir.path(), "m8.rpol", "import \"m9.rpol\"");
        let err = load_err(dir.path(), "main.rpol");
        assert!(
            err.contains(&format!("nest more than {MAX_MODULE_DEPTH} deep")),
            "{err}"
        );
    }

    #[test]
    fn an_oversized_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut big = String::from("# padding\n");
        big.push_str(&"#".repeat(MAX_FILE_BYTES));
        write(dir.path(), "big.rpol", &big);
        write(dir.path(), "main.rpol", "import \"big.rpol\"");
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("per-file limit"), "{err}");
    }

    #[test]
    fn an_oversized_graph_is_rejected() {
        use std::fmt::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        // Nine modules of exactly 1 MiB each pass the per-file limit
        // but blow the 8 MiB graph budget.
        let filler = format!("# leaf\n{}", "#".repeat(MAX_FILE_BYTES - 7));
        assert_eq!(filler.len(), MAX_FILE_BYTES);
        let mut main = String::new();
        for index in 0..9 {
            write(dir.path(), &format!("leaf{index}.rpol"), &filler);
            let _ = writeln!(main, "import \"leaf{index}.rpol\"");
        }
        write(dir.path(), "main.rpol", &main);
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("total source bytes"), "{err}");
    }

    #[test]
    fn the_file_count_budget_is_enforced() {
        use std::fmt::Write;

        let dir = tempfile::tempdir().expect("tempdir");

        let mut main = String::new();
        for index in 0..MAX_MODULE_FILES {
            write(dir.path(), &format!("leaf{index}.rpol"), "# empty\n");
            let _ = writeln!(main, "import \"leaf{index}.rpol\"");
        }
        write(dir.path(), "main.rpol", &main);
        let err = load_err(dir.path(), "main.rpol");
        assert!(
            err.contains(&format!("more than {MAX_MODULE_FILES} files")),
            "{err}"
        );
    }

    #[test]
    fn diagnostics_attribute_spans_to_the_defining_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "lib.rpol",
            "policy broken { term t { if route.zzz == 1 { accept } } }",
        );
        write(dir.path(), "main.rpol", "import \"lib.rpol\"");
        let err = load_err(dir.path(), "main.rpol");
        assert!(err.contains("lib.rpol"), "names the imported file: {err}");
        assert!(
            err.contains("route.zzz") || err.contains("zzz"),
            "excerpts the offending source: {err}"
        );
    }

    #[test]
    fn tests_in_the_main_file_exercise_imported_policies_and_fns() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "lib.rpol",
            &format!(
                "{BOGONS}\n\
                 fn floor(value: u32, minimum: u32) -> u32 {{ max(value, minimum) }}\n\
                 policy hygiene {{ term bogon {{ if route.prefix in bogons {{ reject }} }} }}"
            ),
        );
        write(
            dir.path(),
            "main.rpol",
            "import \"lib.rpol\"\n\
             policy edge-in {\n\
               term guard { if !apply(hygiene) { reject } }\n\
               term pad { set local-pref floor(10, 100); accept }\n\
             }\n\
             test rejects-bogons {\n\
                 route { prefix 10.1.0.0/24 }\n\
                 expect edge-in == reject\n\
             }\n\
             test floors-local-pref {\n\
                 route { prefix 198.51.100.0/24 }\n\
                 expect edge-in == accept with local-pref 100\n\
             }",
        );
        let file = load(dir.path(), "main.rpol").expect("clean load");
        let report = file.run_tests();
        assert_eq!(report.total, 2, "both tests ran");
        assert!(
            report.all_passed(),
            "cross-module tests pass: {:?}",
            report.failures
        );
    }

    #[test]
    fn inline_sources_reject_imports_with_a_pointer_to_file_loading() {
        let report = super::super::check_rpol("import \"lib.rpol\"");
        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics.0[0]
                .message
                .contains("not available for inline sources"),
            "{}",
            report.diagnostics.0[0].message
        );
        assert!(super::super::RpolFile::parse("import \"lib.rpol\"").is_err());
    }

    #[test]
    fn policy_set_equality_follows_the_resolved_module_graph() {
        use std::collections::HashMap;
        use std::sync::Arc;

        use super::super::{RpolPolicyEntry, RpolPolicySet};

        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "leaf.rpol", BOGONS);
        write(
            dir.path(),
            "main.rpol",
            "import \"leaf.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        let set_for = |dir: &Path| -> RpolPolicySet {
            let file = Arc::new(load(dir, "main.rpol").expect("loads"));
            let mut policies = HashMap::new();
            policies.insert(
                "p".to_string(),
                RpolPolicyEntry {
                    file,
                    params: 0,
                    path: "main.rpol".to_string(),
                },
            );
            RpolPolicySet { policies }
        };
        let before = set_for(dir.path());
        // Untouched graph: content-equal — the #775 skip's input reads
        // an rpol-only reload with no edits as a no-op.
        assert_eq!(before, set_for(dir.path()));
        // A leaf-module edit makes every dependent unit read as
        // changed, even though the registered main file is untouched.
        write(
            dir.path(),
            "leaf.rpol",
            "prefix-set bogons { 10.0.0.0/8 le 32 }",
        );
        assert_ne!(before, set_for(dir.path()));
    }

    #[test]
    fn resolved_content_identity_tracks_leaf_edits_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "leaf.rpol", BOGONS);
        write(
            dir.path(),
            "main.rpol",
            "import \"leaf.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }",
        );
        let before = load(dir.path(), "main.rpol").expect("loads");
        // Untouched graph: content-equal (the #775 skip's precondition).
        let unchanged = load(dir.path(), "main.rpol").expect("loads");
        assert!(before.content_eq(&unchanged));

        // A leaf edit flips the identity even though the main file is
        // byte-identical.
        write(
            dir.path(),
            "leaf.rpol",
            "prefix-set bogons { 10.0.0.0/8 le 32 }",
        );
        let after = load(dir.path(), "main.rpol").expect("loads");
        assert!(!before.content_eq(&after), "leaf edits read as changes");
        assert_ne!(
            before.modules()[1].digest,
            after.modules()[1].digest,
            "the leaf digest moved"
        );
        assert_eq!(
            before.modules()[0].digest,
            after.modules()[0].digest,
            "the main digest did not"
        );
    }
}
