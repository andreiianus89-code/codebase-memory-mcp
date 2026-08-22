# Configuration Reference

This page documents the configuration files that `codebase-memory-mcp` reads or writes today.

## At a Glance

| Purpose | Path | Format | Notes |
|---|---|---|---|
| Global custom extension mapping | `$XDG_CONFIG_HOME/codebase-memory-mcp/config.json` | JSON | Falls back to `~/.config/codebase-memory-mcp/config.json` when `XDG_CONFIG_HOME` is unset. |
| Per-project custom extension mapping | `{repo_root}/.codebase-memory.json` | JSON | Overrides conflicting global `extra_extensions` entries. |
| CLI-managed runtime settings | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/_config.db` | SQLite | Written by `codebase-memory-mcp config set/reset`. |
| UI settings | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/config.json` | JSON | Stores `ui_enabled` and `ui_port`. |
| Daemon operation log | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/logs/cbm-daemon.log` | Structured log | Durable daemon lifecycle, watcher/indexing, UI, resource, and error events. |
| Admission conflict log | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/logs/daemon-conflicts.ndjson` | NDJSON | Exact-build, ABI, and canonical-cache conflicts. |
| Activation log | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/logs/activation-events.ndjson` | NDJSON | Install/update/uninstall activation progress and outcomes. |

CBM resolves `CBM_CACHE_DIR` to a canonical per-account path before using any of these locations. The log directory and files are private to the account.

## 1. Custom File Extension Mapping

Two optional JSON files let you map additional file extensions to built-in languages.

### Global config

Default path:

```text
$XDG_CONFIG_HOME/codebase-memory-mcp/config.json
```

Fallback when `XDG_CONFIG_HOME` is unset:

```text
~/.config/codebase-memory-mcp/config.json
```

### Per-project config

Place this file in the repository root:

```text
.codebase-memory.json
```

### Format

```json
{
  "extra_extensions": {
    ".blade.php": "php",
    ".mjs": "javascript",
    ".twig": "html"
  }
}
```

Notes:

- Extension keys must include the leading dot.
- Language names are case-insensitive.
- Unknown language names are skipped.
- Missing files are ignored.
- If the same extension appears in both files, the per-project file wins.

## 2. CLI-Managed Runtime Settings

The `config` subcommand stores runtime settings in a small SQLite database:

```text
${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/_config.db
```

Inspect or change values with the CLI:

```bash
codebase-memory-mcp config list
codebase-memory-mcp config get auto_index
codebase-memory-mcp config set auto_index true
codebase-memory-mcp config set auto_index_limit 50000
codebase-memory-mcp config reset auto_index
```

Current keys:

| Key | Default | Meaning |
|---|---|---|
| `auto_index` | `false` | Automatically index new projects when an MCP session starts. |
| `auto_index_limit` | `50000` | Maximum file count allowed for automatic indexing of a new project. |

## 3. UI Settings

The optional built-in graph UI stores its settings in:

```text
${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/config.json
```

Current format:

```json
{
  "ui_enabled": false,
  "ui_port": 9749
}
```

Notes:

- If the UI-enabled binary has embedded assets and no UI config file exists yet, the UI auto-enables on first run.
- `CBM_CACHE_DIR` changes both the UI config location and the runtime settings database location.
- CBM resolves `CBM_CACHE_DIR` to one canonical per-account cache root. A process configured with a different root fails while any CBM session or command is active; close them before switching roots.

## 4. Environment Variables

These environment variables affect runtime behavior:

| Variable | Default | Description |
|---|---|---|
| `CBM_ALLOWED_ROOT` | *(unset)* | Restrict `index_repository` to paths within this directory. When set, a `repo_path` that resolves (after symlink / `..` resolution) outside this root is refused; unset imposes no restriction. Useful when the server may be driven by an untrusted caller (agentic or multi-tenant deployments). |
| `CBM_CACHE_DIR` | `~/.cache/codebase-memory-mcp` | Override the cache directory used for indexes, `_config.db`, and UI `config.json`. |
| `CBM_DIAGNOSTICS` | `false` | Enable periodic `snapshot.json` and retained `trajectory.ndjson` below a fresh owner-private directory in the system temp directory. The daemon records the randomized paths in the `diagnostics.start` discovery record (a single JSON line) in `${CBM_CACHE_DIR}/logs/cbm-daemon.log`; that one record is emitted even when `CBM_LOG_LEVEL` suppresses ordinary logging, so the paths always remain discoverable. |
| `CBM_DOWNLOAD_URL` | GitHub releases | Override the update download URL. |
| `CBM_GIT_TRACKED_ONLY` | `false` | Set to `1` or `true` for a Git-bound trust snapshot (Git 2.31+ required). The effective mode is always `full`: sources and tracked graph-shaping manifests are SHA-256 bound; mutable ignore/user config is disabled; any material, HEAD, or branch change performs a clean FULL rebuild, while an identical snapshot is a no-op. Expect full-corpus hashing I/O and fail-closed behavior on unstable inputs. |
| `CBM_READ_ONLY` | `false` | Set to `1` or `true` before process startup to expose only non-mutating tools over existing, sealed indexes. Background indexing/watch work is disabled and SQLite is opened without CREATE or query sidecar writes. Use together with `CBM_GIT_TRACKED_ONLY=1` for repository freshness enforcement. |
| `CBM_LOG_LEVEL` | `info` | Set the log level to `debug`, `info`, `warn`, `error`, or `none` (or `0`-`4`). Thin-frontend messages use that session's stderr; detached daemon events use `${CBM_CACHE_DIR}/logs/cbm-daemon.log`. |
| `CBM_WORKERS` | auto-detected | Override the indexing worker count. |

Environment used by daemon-owned components—such as diagnostics, daemon logging, and process-wide indexing resource limits—is captured from the first daemon-backed session that starts the daemon. Later sessions join the existing process and cannot replace those values. To change them, close every daemon-backed session, update the relevant agent configurations consistently, and restart a session. `CBM_ALLOWED_ROOT` remains session-specific, a conflicting `CBM_CACHE_DIR` is rejected, and one-shot CLI commands use their own current environment without starting the daemon.

`CBM_GIT_TRACKED_ONLY` and `CBM_READ_ONLY` follow that process-wide daemon rule. A strict-serving deployment uses both flags, but it must be prepared in two phases:

1. With `CBM_READ_ONLY` off, enable `CBM_GIT_TRACKED_ONLY=1` and run one explicit index. This publishes a standalone DELETE-journal database with source, auxiliary-input, recipe, HEAD, branch, coverage, and provenance bindings.
2. Close all daemon-backed sessions and restart with both `CBM_GIT_TRACKED_ONLY=1` and `CBM_READ_ONLY=1`.

In read-only mode, index/delete/ingest/ADR mutation and source-search/change-detection tools are hidden and centrally rejected, as are background indexing and watching. Permitted database tools require an existing sealed generation; a live WAL, SHM, rollback journal, unreadable or schema-invalid store, stale repository, incomplete provenance, or snapshot change during a request produces an error instead of a fallback result. SQLite errors from any accessed damaged page also fail that request. To update an index, stop the read-only daemon, repeat phase 1, then restart phase 2.

The no-write boundary covers MCP-driven index/cache-database mutation and SQLite query sidecars. It does not disable explicitly configured diagnostics, stderr/daemon log output, or unrelated operating-system temporary activity. Trusted request admission reads and SHA-256 hashes the tracked corpus before and after a successful graph query, so enable it when that integrity guarantee is worth the extra repository read I/O.

`auto_watch` is separate from `auto_index` and requires a connected full-profile daemon session.

Tracked auxiliary inputs are `package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `composer.json`, `pubspec.yaml`, `pom.xml`, `build.gradle[.kts]`, `mix.exs`, `tsconfig.json`, `jsconfig.json`, and `*.gemspec`; untracked copies do not influence trusted indexing.

## 5. Agent and Editor Integration Files

The `install` command can also write MCP entries and instruction blocks into agent/editor config files such as Claude Code, Codex, Gemini, VS Code, Cursor, Zed, and others.

Those target paths vary by tool and platform, so the easiest way to inspect the exact files for your machine is:

```bash
codebase-memory-mcp install --dry-run
```

That prints the specific config files the installer would modify without writing anything.
