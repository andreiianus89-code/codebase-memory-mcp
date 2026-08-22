r"""GREEN guard — explicit daemon lifecycle (`daemon start|status|stop`).

Guards the PR #1139 daemon-control surface at the product level:

* ``daemon status`` with no daemon reports not-running and exits nonzero.
* ``daemon start`` launches a PERMANENT daemon: it reports a pid, and the
  daemon survives its clients (a one-shot ``cli`` command recycles it without
  printing the cold-start hint, and the daemon is still active afterwards).
* A cold one-shot ``cli`` command (no daemon) prints the startup-tax hint.
* ``daemon stop`` on an idle daemon stops it; a second ``stop`` is idempotent.
* Read-only ``start/status/--open`` never advertises or opens the disabled UI.
* On Windows, cache roots are owned by the exact process user and carry one
  protected, non-inherited, current-user-only full-control DACL entry.

Every path carries a kill-by-pid backstop so a stuck daemon can never hang the
suite (the Windows leg's test-infra hang sensitivity is on record).

Exit code: 0 == lifecycle behaves (green), 1 == regression, 2 == setup error.

Usage:
    python test_daemon_lifecycle.py <path-to-codebase-memory-mcp[.exe]>
"""
import os
import re
import subprocess
import sys
import tempfile


def run_cli(binary, cache, args, timeout=60, read_only=False):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = cache
    env.pop("CBM_READ_ONLY", None)
    if read_only:
        env["CBM_READ_ONLY"] = "1"
    return subprocess.run([binary] + args, capture_output=True, timeout=timeout, env=env)


def output_text(result):
    return ((result.stdout or b"") + (result.stderr or b"")).decode("utf-8", "replace")


def windows_private_directory_oracle(path):
    """Return (ok, detail) for the exact owner-only DACL stamped by CBM."""
    if os.name != "nt":
        return True, ""
    script = r"""
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $env:CBM_DACL_ORACLE_PATH
$raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
    $acl.GetSecurityDescriptorBinaryForm(), 0)
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$dacl = $raw.DiscretionaryAcl
$count = if ($null -eq $dacl) { -1 } else { $dacl.Count }
$ace = if ($count -eq 1) { $dacl[0] } else { $null }
$protected = ($raw.ControlFlags -band
    [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
$mask = if ($null -eq $ace) { [uint32]0 } else { [uint32]$ace.AccessMask }
$fileAll = [uint32][System.Security.AccessControl.FileSystemRights]::FullControl
$genericAll = [uint32]0x10000000
$ok = ($raw.Owner.Equals($current) -and $protected -and $count -eq 1 -and
    $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
    $ace.AceFlags -eq [System.Security.AccessControl.AceFlags]::None -and
    $ace.SecurityIdentifier.Equals($current) -and
    ($mask -eq $fileAll -or $mask -eq $genericAll))
if (-not $ok) {
    [Console]::Error.WriteLine(
        "owner={0} current={1} protected={2} ace_count={3} mask=0x{4:x8}",
        $raw.Owner.Value, $current.Value, $protected, $count, $mask)
    exit 1
}
"""
    env = dict(os.environ)
    env["CBM_DACL_ORACLE_PATH"] = path
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                             "-Command", script], capture_output=True, timeout=30, env=env)
    return result.returncode == 0, output_text(result).strip()


def force_kill(pid):
    if not pid:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=30)
    else:
        subprocess.run(["kill", "-9", str(pid)], capture_output=True, timeout=30)


def main():
    if len(sys.argv) < 2:
        print("usage: python test_daemon_lifecycle.py <binary>")
        return 2
    binary = os.path.abspath(sys.argv[1])
    if not os.path.exists(binary):
        print("FAIL: binary not found: %s" % binary)
        return 2

    work = tempfile.mkdtemp(prefix="cbm_win_daemonctl_")
    cache = os.path.join(work, "cache")
    os.makedirs(cache, exist_ok=True)
    daemon_pid = 0
    try:
        status_absent = run_cli(binary, cache, ["daemon", "status"])
        if status_absent.returncode == 0 or "not running" not in output_text(status_absent):
            print("RED: `daemon status` with no daemon should report not-running "
                  "and exit nonzero:\n%s" % output_text(status_absent)[:300])
            return 1
        print("PASS: status reports not-running before any daemon exists")
        if os.name == "nt":
            private, detail = windows_private_directory_oracle(cache)
            if not private:
                print("RED: daemon cache owner/DACL is not exact-user private: %s" % detail)
                return 1
            print("PASS: daemon cache has exact-user owner and protected private DACL")

        cold = run_cli(binary, cache, ["cli", "list_projects", "{}"])
        cold_text = output_text(cold)
        if cold.returncode != 0 or "daemon start" not in cold_text:
            print("RED: a cold one-shot cli command should succeed and hint at "
                  "`daemon start`:\n%s" % cold_text[:400])
            return 1
        print("PASS: cold cli one-shot succeeded and printed the startup-tax hint")

        start = run_cli(binary, cache, ["daemon", "start"])
        start_text = output_text(start)
        pid_match = re.search(r"pid (\d+)", start_text)
        daemon_pid = int(pid_match.group(1)) if pid_match else 0
        if start.returncode != 0 or "permanent" not in start_text or not daemon_pid:
            print("RED: `daemon start` should report a permanent daemon with a pid:\n%s"
                  % start_text[:400])
            return 1
        print("PASS: daemon start reported permanent pid %d" % daemon_pid)

        warm = run_cli(binary, cache, ["cli", "list_projects", "{}"])
        warm_text = output_text(warm)
        if warm.returncode != 0 or "daemon start" in warm_text:
            print("RED: a warm cli one-shot should recycle the daemon without the "
                  "cold-start hint:\n%s" % warm_text[:400])
            return 1
        status_active = run_cli(binary, cache, ["daemon", "status"])
        status_text = output_text(status_active)
        if status_active.returncode != 0 or "permanent" not in status_text:
            print("RED: the permanent daemon should survive its cli client:\n%s"
                  % status_text[:400])
            return 1
        print("PASS: warm cli recycled the daemon; daemon survived its client")

        stop = run_cli(binary, cache, ["daemon", "stop"])
        if stop.returncode != 0:
            print("RED: `daemon stop` on an idle daemon failed:\n%s"
                  % output_text(stop)[:300])
            return 1
        stop_again = run_cli(binary, cache, ["daemon", "stop"])
        if stop_again.returncode != 0:
            print("RED: a second `daemon stop` should be idempotent:\n%s"
                  % output_text(stop_again)[:300])
            return 1
        print("PASS: stop retired the idle daemon; second stop was idempotent")

        read_only_cache = os.path.join(work, "read-only-cache")
        os.makedirs(read_only_cache, mode=0o700, exist_ok=True)
        if os.name == "nt":
            prepare_read_only = run_cli(binary, read_only_cache, ["daemon", "status"])
            if (prepare_read_only.returncode == 0 or
                    "not running" not in output_text(prepare_read_only)):
                print("RED: writable preflight could not secure the read-only cache:\n%s" %
                      output_text(prepare_read_only)[:400])
                return 1
            private, detail = windows_private_directory_oracle(read_only_cache)
            if not private:
                print("RED: prepared read-only cache owner/DACL is not private: %s" % detail)
                return 1
        else:
            os.chmod(read_only_cache, 0o700)
        read_only_start = run_cli(binary, read_only_cache,
                                  ["daemon", "start", "--open"], read_only=True)
        read_only_text = output_text(read_only_start)
        pid_match = re.search(r"pid (\d+)", read_only_text)
        daemon_pid = int(pid_match.group(1)) if pid_match else 0
        if (read_only_start.returncode != 0 or not daemon_pid or
                "ui: disabled (read-only mode)" not in read_only_text or
                "--port/--open have no effect in read-only mode" not in read_only_text or
                "http://127.0.0.1" in read_only_text):
            print("RED: read-only `daemon start --open` must not configure, advertise, or "
                  "open the disabled HTTP UI:\n%s" % read_only_text[:500])
            return 1
        read_only_status = run_cli(binary, read_only_cache, ["daemon", "status"],
                                   read_only=True)
        read_only_status_text = output_text(read_only_status)
        if (read_only_status.returncode != 0 or
                "ui: disabled (read-only mode)" not in read_only_status_text or
                "http://127.0.0.1" in read_only_status_text):
            print("RED: read-only `daemon status` must report the actual disabled UI:\n%s"
                  % read_only_status_text[:500])
            return 1
        read_only_stop = run_cli(binary, read_only_cache, ["daemon", "stop"], read_only=True)
        if read_only_stop.returncode != 0:
            print("RED: stopping the read-only daemon failed:\n%s"
                  % output_text(read_only_stop)[:300])
            return 1
        if os.name == "nt":
            private, detail = windows_private_directory_oracle(read_only_cache)
            if not private:
                print("RED: read-only lifecycle left an unsafe cache owner/DACL: %s" % detail)
                return 1
        print("PASS: read-only start/status/--open report the disabled UI truthfully")

        print("\nGREEN: daemon lifecycle (status/start/recycle/stop) behaves.")
        return 0
    finally:
        force_kill(daemon_pid)


if __name__ == "__main__":
    sys.exit(main())
