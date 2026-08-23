"""GREEN regression guard — non-ASCII repo paths keep all definitions on Windows.

Guards the fix for issue #636 / #357 (landed on main via #700) at the product
surface (real codebase-memory-mcp process, real SQLite DB, real stdio). Two
byte-identical TypeScript fixtures are indexed: one under an ASCII parent path,
one under a non-ASCII parent path. The invariant under test:

    A byte-identical fixture must produce equivalent graph counts regardless of
    whether its absolute path contains non-ASCII characters.

Before #700 native Windows extracted only File/Folder nodes for every non-ASCII
copy (Latin-1 accents, Cyrillic, CJK, Greek) — zero definitions — while the ASCII
copy extracted functions/classes/methods. Root cause: each pipeline pass read
source bytes with plain fopen(path, "rb") (src/pipeline/pass_definitions.c,
pass_calls.c, …); on Windows fopen() interprets the UTF-8 path in the active ANSI
code page, so a non-ASCII path could not be opened and the parser received
nothing. #700 routed the per-pass reads through cbm_fopen (→ _wfopen with a wide
path, src/foundation/compat_fs.c), so non-ASCII paths now parse identically.

This guard fails (red) if that fix regresses. It also passes on Linux/macOS
(byte-transparent UTF-8 filesystem).

The same tiny TypeScript fixture also exercises the Windows-native trusted
snapshot path: default FULL indexing includes an untracked file; tracked mode
forces FULL, persists exact digests/coverage, excludes that file, and refreshes
both generation and graph content after a tracked source edit.

Exit code: 0 == invariant holds (green), 1 == invariant violated (regression),
2 == environment/setup error.

Usage:
    python test_non_ascii_path.py <path-to-codebase-memory-mcp[.exe]>
"""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_stdio import McpServer  # noqa: E402

MATH_TS = (
    "export function add(a: number, b: number): number { return a + b; }\n"
    "export function mul(a: number, b: number): number { return add(a, a); }\n"
    "export class Calc {\n"
    "  total: number = 0;\n"
    "  push(x: number): void { this.total = add(this.total, x); }\n"
    "}\n"
)
MAIN_TS = (
    'import { add, mul, Calc } from "./math";\n'
    "function run(): number {\n"
    "  const c = new Calc();\n"
    "  c.push(add(1, 2));\n"
    "  return mul(3, 4);\n"
    "}\n"
    "run();\n"
)
UNTRACKED_TS = "export function UntrackedOnly(): number { return 99; }\n"
REFRESHED_MATH_TS = MATH_TS + (
    "export function RefreshedOnly(a: number): number { return a - 1; }\n"
)

# Distinct non-ASCII scripts — each must behave like the ASCII baseline.
NON_ASCII_SEGMENTS = {
    "latin1_accents": "café_repo",
    "cyrillic": "проект_repo",
    "cjk": "日本語_repo",
    "greek": "Ωμέγα_repo",
}

STATUS_POLL_S = 0.5
COHORT_DEADLINE_S = 45


def make_fixture(root):
    src = os.path.join(root, "src")
    os.makedirs(src, exist_ok=True)
    for name, text in (("math.ts", MATH_TS), ("main.ts", MAIN_TS)):
        with open(os.path.join(src, name), "wb") as f:
            f.write(text.encode("utf-8"))  # exact bytes, identical across copies


def run_daemon_cli(binary, cache, extra_env, arguments):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = cache
    env.update(extra_env or {})
    return subprocess.run([binary] + arguments, capture_output=True,
                          timeout=30, env=env)


def daemon_output(result):
    return ((result.stdout or b"") + (result.stderr or b"")).decode(
        "utf-8", "replace")


def stop_daemon_and_wait(binary, cache, extra_env):
    deadline = time.monotonic() + COHORT_DEADLINE_S
    last_stop = None
    while time.monotonic() < deadline:
        last_stop = run_daemon_cli(binary, cache, extra_env, ["daemon", "stop"])
        if last_stop.returncode == 0:
            break
        time.sleep(STATUS_POLL_S)
    else:
        raise RuntimeError("daemon stop did not succeed after MCP close: %s" %
                           daemon_output(last_stop)[-500:])

    deadline = time.monotonic() + COHORT_DEADLINE_S
    while time.monotonic() < deadline:
        status = run_daemon_cli(binary, cache, extra_env, ["daemon", "status"])
        if status.returncode != 0 and "not running" in daemon_output(status):
            return
        time.sleep(STATUS_POLL_S)
    raise RuntimeError("daemon remained active after accepted stop")


def is_transient_cohort_conflict(error):
    detail = str(error)
    return (
        "active account daemon uses a different cache directory" in detail or
        "a conflicting CBM process is active" in detail
    )


@contextmanager
def cohort_session(binary, cache, extra_env=None):
    deadline = time.monotonic() + COHORT_DEADLINE_S
    while True:
        server = McpServer(binary, cache_dir=cache, extra_env=extra_env)
        try:
            server.start()
            server.initialize()
            break
        except Exception as error:
            server.close()
            if not is_transient_cohort_conflict(error) or time.monotonic() >= deadline:
                raise
            time.sleep(STATUS_POLL_S)
    try:
        yield server
    finally:
        server.close()
        stop_daemon_and_wait(binary, cache, extra_env)


def index_and_count(binary, repo, cache):
    """Index `repo` into an isolated cache and return label-resolved counts."""
    os.makedirs(cache, exist_ok=True)
    with cohort_session(binary, cache) as s:
        resp = s.call_tool("index_repository", {"repo_path": repo}, timeout=180)
        _, err = s.tool_text(resp)
        if err:
            return {"error": "index tools/call error: %r" % err}
        lp = s.call_tool("list_projects", {}, timeout=60)
        lp_txt, _ = s.tool_text(lp)
        projects = json.loads(lp_txt).get("projects") or []
        if not projects:
            return {"error": "no project listed after index"}
        p = projects[0]
        out = {"name": p.get("name"), "nodes": p.get("nodes"),
               "edges": p.get("edges")}
        # Definition-level counts prove the parser ran (not just discovery).
        # query_graph defaults to TOON text; this scripted consumer requests
        # format="json" ({"columns":[...],"rows":[["<n>"]],...}) explicitly.
        name = p.get("name")
        defs = 0
        for label in ("Function", "Class", "Method"):
            q = "MATCH (n:%s) RETURN count(n)" % label
            r = s.call_tool("query_graph",
                            {"query": q, "project": name, "format": "json"},
                            timeout=60)
            t, _ = s.tool_text(r)
            try:
                rows = json.loads(t).get("rows") or []
                if rows and rows[0]:
                    defs += int(rows[0][0])
            except Exception:
                pass
        out["definition_nodes"] = defs
        return out


def tool_json(server, name, arguments, timeout=60):
    response = server.call_tool(name, arguments, timeout=timeout)
    text, error = server.tool_text(response)
    if error or response.get("result", {}).get("isError"):
        raise RuntimeError("%s failed: %r %r" % (name, error, text))
    structured = response.get("result", {}).get("structuredContent")
    if not isinstance(structured, dict):
        raise RuntimeError("%s returned no structuredContent: %r" % (name, text))
    return structured


def run_git(repo, *arguments):
    result = subprocess.run(["git", "-C", repo] + list(arguments),
                            capture_output=True, timeout=60)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace")
        raise RuntimeError("git %s failed: %s" % (" ".join(arguments), detail[-500:]))
    return result.stdout.decode("utf-8", "replace").strip()


def index_snapshot(binary, repo, cache, tracked, mode, symbol):
    os.makedirs(cache, exist_ok=True)
    env = {"CBM_GIT_TRACKED_ONLY": "1" if tracked else "0", "CBM_READ_ONLY": "0"}
    with cohort_session(binary, cache, env) as server:
        indexed = tool_json(server, "index_repository",
                            {"repo_path": repo, "mode": mode}, timeout=180)
        project = indexed.get("project")
        found = None
        if symbol:
            found = tool_json(server, "search_graph",
                              {"project": project, "name_pattern": symbol,
                               "format": "json", "limit": 10})
    return indexed, found


def inspect_trusted_snapshot(binary, cache, project, symbol):
    env = {"CBM_GIT_TRACKED_ONLY": "1", "CBM_READ_ONLY": "1"}
    with cohort_session(binary, cache, env) as server:
        found = tool_json(server, "search_graph",
                          {"project": project, "name_pattern": symbol,
                           "format": "json", "limit": 10})
        coverage = tool_json(server, "check_index_coverage",
                             {"project": project,
                              "paths": ["src/math.ts", "src/main.ts",
                                        "src/untracked.ts"]})
    return found, coverage


def stored_hashes(cache, project):
    db_path = os.path.join(cache, project + ".db")
    if not os.path.isfile(db_path):
        raise RuntimeError("trusted database not found: %s" % db_path)
    sidecar_suffixes = ("-wal", "-shm", "-journal")
    before_digest = hashlib.sha256(Path(db_path).read_bytes()).hexdigest()
    before_sidecars = tuple(os.path.exists(db_path + suffix)
                            for suffix in sidecar_suffixes)
    if any(before_sidecars):
        raise RuntimeError("trusted database is not sealed: %r" % (before_sidecars,))
    uri = Path(db_path).resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        hashes = dict(connection.execute(
            "SELECT rel_path, sha256 FROM file_hashes WHERE project=?", (project,)))
    finally:
        connection.close()
    after_digest = hashlib.sha256(Path(db_path).read_bytes()).hexdigest()
    after_sidecars = tuple(os.path.exists(db_path + suffix)
                           for suffix in sidecar_suffixes)
    if before_digest != after_digest or before_sidecars != after_sidecars:
        raise RuntimeError("immutable digest oracle changed the database family")
    return hashes


def trusted_full_guard(binary, work):
    """Windows-native product guard for default and trusted FULL snapshots."""
    repo = os.path.join(work, "trusted_full_repo")
    make_fixture(repo)
    run_git(repo, "init", "-q")
    run_git(repo, "add", "src/math.ts", "src/main.ts")
    run_git(repo, "-c", "user.name=CBM Test", "-c",
            "user.email=cbm@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", "fixture")
    untracked_path = os.path.join(repo, "src", "untracked.ts")
    with open(untracked_path, "wb") as source:
        source.write(UNTRACKED_TS.encode("utf-8"))

    default_index, default_untracked = index_snapshot(
        binary, repo, os.path.join(work, "c_default_full"), False, "full",
        "UntrackedOnly")

    trusted_cache = os.path.join(work, "c_trusted_full")
    initial_index, _ = index_snapshot(binary, repo, trusted_cache, True, "fast", None)
    project = initial_index.get("project")
    initial_untracked, initial_coverage = inspect_trusted_snapshot(
        binary, trusted_cache, project, "UntrackedOnly")
    initial_hashes = stored_hashes(trusted_cache, project)
    head = run_git(repo, "rev-parse", "HEAD")

    math_path = os.path.join(repo, "src", "math.ts")
    with open(math_path, "wb") as source:
        source.write(REFRESHED_MATH_TS.encode("utf-8"))
    refreshed_index, _ = index_snapshot(
        binary, repo, trusted_cache, True, "moderate", None)
    refreshed_symbol, refreshed_coverage = inspect_trusted_snapshot(
        binary, trusted_cache, project, "RefreshedOnly")
    refreshed_hashes = stored_hashes(trusted_cache, project)

    expected_initial_math = hashlib.sha256(MATH_TS.encode("utf-8")).hexdigest()
    expected_refreshed_math = hashlib.sha256(REFRESHED_MATH_TS.encode("utf-8")).hexdigest()
    expected_main = hashlib.sha256(MAIN_TS.encode("utf-8")).hexdigest()
    initial_paths = {entry.get("path"): entry
                     for entry in initial_coverage.get("paths", [])}
    refreshed_paths = {entry.get("path"): entry
                       for entry in refreshed_coverage.get("paths", [])}
    initial_meta = initial_coverage.get("metadata", {})
    refreshed_meta = refreshed_coverage.get("metadata", {})
    initial_provenance = initial_untracked.get("provenance", {})
    refreshed_provenance = refreshed_symbol.get("provenance", {})

    checks = {
        "default FULL indexes untracked source":
            default_index.get("status") == "indexed" and default_untracked.get("total", 0) > 0,
        "tracked requests publish successfully":
            initial_index.get("status") == "indexed" and
            refreshed_index.get("status") == "indexed",
        "tracked snapshot excludes untracked source":
            initial_untracked.get("total") == 0 and
            initial_paths.get("src/untracked.ts", {}).get("freshness") == "not_tracked" and
            "src/untracked.ts" not in initial_hashes and
            "src/untracked.ts" not in refreshed_hashes,
        "trusted request reports current snapshot and HEAD":
            initial_untracked.get("trusted_snapshot") == "current" and
            refreshed_symbol.get("trusted_snapshot") == "current" and
            initial_provenance.get("head_sha") == head and
            refreshed_provenance.get("head_sha") == head,
        "FAST/MODERATE requests are recorded as FULL":
            initial_meta.get("index_mode") == "full" and
            refreshed_meta.get("index_mode") == "full",
        "coverage and digest recording are complete":
            initial_meta.get("recording_status") == "complete" and
            refreshed_meta.get("recording_status") == "complete" and
            initial_meta.get("hash_records_complete") is True and
            refreshed_meta.get("hash_records_complete") is True and
            initial_meta.get("generation_matches") is True and
            refreshed_meta.get("generation_matches") is True and
            initial_paths.get("src/math.ts", {}).get("freshness") ==
                "trusted_content_match" and
            initial_paths.get("src/main.ts", {}).get("freshness") ==
                "trusted_content_match" and
            refreshed_paths.get("src/math.ts", {}).get("freshness") ==
                "trusted_content_match",
        "persisted digests exactly match tracked bytes":
            initial_hashes.get("src/math.ts") == expected_initial_math and
            initial_hashes.get("src/main.ts") == expected_main and
            refreshed_hashes.get("src/math.ts") == expected_refreshed_math and
            refreshed_hashes.get("src/main.ts") == expected_main,
        "refresh replaces generation":
            bool(initial_provenance.get("generation")) and
            initial_provenance.get("generation") != refreshed_provenance.get("generation"),
        "refresh replaces graph content":
            refreshed_symbol.get("total", 0) > 0,
    }
    failed = [name for name, passed in checks.items() if not passed]
    return not failed, "; ".join(failed)


def main():
    if len(sys.argv) < 2:
        print("usage: python test_non_ascii_path.py <binary>")
        return 2
    binary = os.path.abspath(sys.argv[1])
    if not os.path.exists(binary):
        print("FAIL: binary not found: %s" % binary)
        return 2

    work = tempfile.mkdtemp(prefix="cbm_win_nonascii_")
    failures = []
    try:
        ascii_repo = os.path.join(work, "ascii_repo")
        make_fixture(ascii_repo)
        base = index_and_count(binary, ascii_repo, os.path.join(work, "c_ascii"))
        if base.get("error") or not base.get("nodes"):
            print("SETUP FAIL: ASCII baseline did not index: %r" % base)
            return 2
        print("baseline (ASCII): nodes=%s edges=%s definitions=%s" %
              (base["nodes"], base["edges"], base["definition_nodes"]))
        if base["definition_nodes"] < 1:
            print("SETUP FAIL: ASCII baseline produced no definitions: %r" % base)
            return 2

        for key, seg in NON_ASCII_SEGMENTS.items():
            repo = os.path.join(work, seg)
            make_fixture(repo)
            got = index_and_count(binary, repo, os.path.join(work, "c_" + key))
            ok = (not got.get("error")
                  and got.get("nodes") == base["nodes"]
                  and got.get("edges") == base["edges"]
                  and got.get("definition_nodes") == base["definition_nodes"])
            status = "PASS" if ok else "FAIL"
            print("[%s] non-ascii/%-14s nodes=%s edges=%s definitions=%s "
                  "(baseline %s/%s/%s) name=%r" %
                  (status, key, got.get("nodes"), got.get("edges"),
                   got.get("definition_nodes"), base["nodes"], base["edges"],
                   base["definition_nodes"], got.get("name")))
            if not ok:
                failures.append(key)

        if not shutil.which("git"):
            print("SETUP FAIL: git is required by the trusted FULL guard")
            return 2
        try:
            trusted_ok, trusted_detail = trusted_full_guard(binary, work)
        except Exception as error:
            trusted_ok = False
            trusted_detail = "guard raised: %s" % error
        print("[%s] trusted FULL index/digest/coverage/refresh%s" %
              ("PASS" if trusted_ok else "FAIL",
               "" if trusted_ok else ": " + trusted_detail))
        if not trusted_ok:
            failures.append("trusted_full")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if failures:
        print("\nREGRESSION (red): guards failed: %s" % ", ".join(failures))
        print("Invariant violated: non-ASCII fixtures must match the ASCII baseline, "
              "and trusted FULL snapshots must preserve their digest/coverage/refresh "
              "contract.")
        return 1
    print("\nGREEN: non-ASCII paths and trusted FULL snapshots behave.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
