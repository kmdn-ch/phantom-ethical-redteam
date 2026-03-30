# Phantom Security Specification

**Version:** 1.0.0
**Date:** 2026-03-29
**Author:** Security Engineering
**Classification:** INTERNAL -- SENSITIVE

---

## 0. Executive Summary

Phantom is an autonomous AI red team agent that can write and execute arbitrary Python
scripts at runtime, operate unsupervised, and perform full exploitation including
persistence, lateral movement, and data exfiltration. This combination creates an
exceptionally dangerous failure mode: a single scope enforcement gap or sandbox escape
could turn Phantom into an uncontrolled offensive weapon against unauthorized targets.

This specification defines defense-in-depth controls across seven domains. The
fundamental design principle is **enforcement at every layer** -- application-level
checks are necessary but never sufficient. Every control must be independently
enforceable at the OS/network level so that even a complete bypass of the Python
application layer cannot result in out-of-scope activity.

---

## 1. Sandboxing for Dynamic Tools

### 1.1 Threat Model

Dynamic tool generation means the LLM produces arbitrary Python code and Phantom
executes it. Threats include:

- **Sandbox escape:** Generated code disables or circumvents scope checking.
- **Host compromise:** Code reads `/etc/shadow`, SSH keys, `.env` files, or API keys
  from the host filesystem.
- **Persistence on host:** Code installs backdoors, cron jobs, or services on the
  machine running Phantom (not the target).
- **Resource exhaustion:** Fork bombs, infinite loops, memory allocation attacks.
- **Supply chain injection:** Code runs `pip install` or downloads and executes
  binaries from attacker-controlled sources.

### 1.2 Architecture: Containerized Execution

All dynamically generated scripts MUST execute inside a disposable container. Never on
the host directly.

```
+------------------------------------------------------------------+
|  HOST (operator machine)                                         |
|                                                                  |
|  +-----------------------------+    +-------------------------+  |
|  | Phantom Agent (Python)      |    | Network Policy          |  |
|  | - LLM reasoning loop        |    | - iptables/nftables     |  |
|  | - Scope checker             |    | - Allowlist enforcement  |  |
|  | - Audit logger              |    +-------------------------+  |
|  | - Kill switch controller    |                                 |
|  +--------+--------------------+                                 |
|           |                                                      |
|           | Docker API (unix socket, read-only mount of scope)   |
|           v                                                      |
|  +-----------------------------+                                 |
|  | Sandbox Container           |                                 |
|  | - Ephemeral (--rm)          |                                 |
|  | - No host network           |                                 |
|  | - Read-only root filesystem |                                 |
|  | - No capabilities           |                                 |
|  | - seccomp + AppArmor        |                                 |
|  | - Resource limits enforced  |                                 |
|  | - /workspace (tmpfs, noexec)|                                 |
|  | - /output (volume, results) |                                 |
|  +-----------------------------+                                 |
+------------------------------------------------------------------+
```

### 1.3 Container Configuration

```python
SANDBOX_CONFIG = {
    # Container lifecycle
    "auto_remove": True,                    # --rm: destroy on exit
    "detach": False,                        # Synchronous execution
    "network_mode": "phantom-scope-net",    # Custom network with iptables rules (see Section 6)

    # Filesystem isolation
    "read_only": True,                      # Read-only root filesystem
    "tmpfs": {
        "/tmp": "size=100M,noexec,nosuid,nodev",
        "/workspace": "size=200M,noexec,nosuid,nodev",
    },

    # Only mount what is strictly required
    "volumes": {
        # Script to execute (read-only, single file)
        "/path/to/generated_script.py": {"bind": "/workspace/run.py", "mode": "ro"},
        # Output directory (write-only from container perspective)
        "/path/to/session/sandbox_output": {"bind": "/output", "mode": "rw"},
        # Scope file (read-only -- container can read but not modify scope)
        "/path/to/scopes/current_scope.md": {"bind": "/scope/current_scope.md", "mode": "ro"},
    },

    # NEVER mount these:
    # - Docker socket (/var/run/docker.sock) -- container escape
    # - Host home directory -- credential theft
    # - Host /etc -- configuration theft
    # - Any .env or config.yaml files -- API key theft

    # Drop ALL capabilities, then add back only what is needed
    "cap_drop": ["ALL"],
    "cap_add": [],                          # Empty -- no capabilities

    # Security options
    "security_opt": [
        "no-new-privileges:true",           # Prevent privilege escalation via setuid
        "seccomp=phantom-seccomp.json",     # Custom seccomp profile (Section 1.5)
        "apparmor=phantom-sandbox",         # Custom AppArmor profile (Section 1.6)
    ],

    # Resource limits
    "mem_limit": "512m",                    # Hard memory limit
    "memswap_limit": "512m",               # No swap (same as mem_limit)
    "cpu_period": 100000,
    "cpu_quota": 50000,                     # 50% of one CPU core
    "pids_limit": 64,                       # Prevent fork bombs
    "ulimits": [
        {"Name": "nofile", "Soft": 256, "Hard": 512},   # File descriptor limit
        {"Name": "nproc", "Soft": 32, "Hard": 64},      # Process limit
        {"Name": "fsize", "Soft": 52428800, "Hard": 104857600},  # 50/100MB file size
    ],

    # User isolation
    "user": "1000:1000",                    # Run as non-root

    # Execution timeout (enforced externally by the host)
    # Container is killed after this duration regardless of script state
    "_phantom_timeout_seconds": 300,
}
```

### 1.4 Execution Flow

```python
import docker
import hashlib
import os
import signal
import tempfile
import time
from pathlib import Path

class SandboxExecutor:
    """Execute dynamically generated scripts in disposable containers."""

    SANDBOX_IMAGE = "phantom-sandbox:latest"  # Minimal image, built from Dockerfile
    MAX_SCRIPT_SIZE = 50_000                  # 50KB -- reject absurdly large scripts
    MAX_OUTPUT_SIZE = 10_000_000              # 10MB -- truncate output beyond this

    # Patterns that MUST NOT appear in generated scripts
    BLOCKED_PATTERNS = [
        # Scope/security bypass attempts
        r"scope_checker",          # Importing or modifying scope checker
        r"scope_guard",
        r"is_in_scope",
        r"current_scope\.md",      # Direct scope file manipulation
        r"PHANTOM_SESSION_DIR",    # Session directory manipulation
        r"auth\.json",             # Credential file access

        # Host escape attempts
        r"/var/run/docker\.sock",  # Docker socket access
        r"docker\.",               # Docker API usage
        r"subprocess\..*Popen",    # Arbitrary subprocess (use controlled wrappers)
        r"os\.exec",              # Process replacement
        r"ctypes",                 # C-level calls, FFI
        r"importlib",             # Dynamic imports (bypass other blocks)

        # Network bypass attempts
        r"iptables",               # Firewall modification
        r"nftables",
        r"ip\s+route",            # Route manipulation
        r"sysctl",                # Kernel parameter manipulation

        # Data exfiltration to non-scope targets
        r"pastebin\.com",
        r"transfer\.sh",
        r"ngrok",
        r"webhook\.site",
    ]

    def __init__(self, session_dir: str, scope_file: str):
        self.client = docker.from_env()
        self.session_dir = session_dir
        self.scope_file = scope_file
        self.output_dir = os.path.join(session_dir, "sandbox_output")
        os.makedirs(self.output_dir, exist_ok=True)

    def validate_script(self, script: str) -> tuple[bool, str]:
        """Static analysis of generated script before execution.

        Returns (is_safe, reason).
        """
        import re

        if len(script) > self.MAX_SCRIPT_SIZE:
            return False, f"Script exceeds maximum size ({len(script)} > {self.MAX_SCRIPT_SIZE})"

        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                return False, f"Script contains blocked pattern: {pattern}"

        return True, "OK"

    def execute(self, script: str, timeout: int = 300) -> dict:
        """Execute a script in a sandbox container.

        Returns dict with: exit_code, stdout, stderr, script_hash, duration_seconds
        """
        # 1. Validate script content
        is_safe, reason = self.validate_script(script)
        if not is_safe:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"BLOCKED: {reason}",
                "script_hash": hashlib.sha256(script.encode()).hexdigest(),
                "duration_seconds": 0,
            }

        # 2. Write script to temp file (will be mounted read-only)
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        script_path = os.path.join(self.output_dir, f"script_{script_hash[:12]}.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)

        # 3. Log the script for audit (BEFORE execution)
        audit_path = os.path.join(self.session_dir, "sandbox_audit.jsonl")
        import json
        audit_entry = {
            "timestamp": time.time(),
            "script_hash": script_hash,
            "script_path": script_path,
            "script_size": len(script),
            "timeout": timeout,
            "status": "STARTED",
        }
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit_entry) + "\n")

        # 4. Run in container
        start_time = time.time()
        try:
            container = self.client.containers.run(
                image=self.SANDBOX_IMAGE,
                command=["python3", "/workspace/run.py"],
                volumes={
                    os.path.abspath(script_path): {
                        "bind": "/workspace/run.py", "mode": "ro"
                    },
                    os.path.abspath(self.output_dir): {
                        "bind": "/output", "mode": "rw"
                    },
                    os.path.abspath(self.scope_file): {
                        "bind": "/scope/current_scope.md", "mode": "ro"
                    },
                },
                # All SANDBOX_CONFIG options from Section 1.3
                auto_remove=False,  # We need to read logs before removal
                read_only=True,
                network_mode="phantom-scope-net",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit="512m",
                memswap_limit="512m",
                cpu_quota=50000,
                pids_limit=64,
                user="1000:1000",
                tmpfs={
                    "/tmp": "size=100M,noexec,nosuid,nodev",
                    "/workspace/tmp": "size=200M,nosuid,nodev",
                },
                detach=True,
            )

            # 5. Wait with timeout (host-enforced, not container-enforced)
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

        except Exception as e:
            exit_code = -1
            stdout = ""
            stderr = f"Container execution failed: {str(e)}"
        finally:
            duration = time.time() - start_time
            # Force-kill and remove container
            try:
                container.kill()
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass

        # 6. Truncate output
        if len(stdout) > self.MAX_OUTPUT_SIZE:
            stdout = stdout[:self.MAX_OUTPUT_SIZE] + "\n[TRUNCATED]"
        if len(stderr) > self.MAX_OUTPUT_SIZE:
            stderr = stderr[:self.MAX_OUTPUT_SIZE] + "\n[TRUNCATED]"

        # 7. Audit completion
        completion_entry = {
            "timestamp": time.time(),
            "script_hash": script_hash,
            "exit_code": exit_code,
            "duration_seconds": round(duration, 2),
            "stdout_size": len(stdout),
            "stderr_size": len(stderr),
            "status": "COMPLETED" if exit_code == 0 else "FAILED",
        }
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(completion_entry) + "\n")

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "script_hash": script_hash,
            "duration_seconds": round(duration, 2),
        }
```

### 1.5 Seccomp Profile

The sandbox container MUST run with a restricted seccomp profile that blocks dangerous
syscalls. Use Docker's default seccomp profile as a baseline and additionally block:

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "comment": "Phantom sandbox -- allow minimal syscalls only",
    "syscalls": [
        {
            "names": [
                "read", "write", "open", "close", "stat", "fstat", "lstat",
                "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
                "access", "pipe", "select", "dup", "dup2", "nanosleep",
                "getpid", "socket", "connect", "sendto", "recvfrom",
                "bind", "listen", "accept", "getsockname", "getpeername",
                "sendmsg", "recvmsg", "shutdown", "setsockopt", "getsockopt",
                "clone", "fork", "execve", "exit", "wait4", "kill",
                "uname", "fcntl", "flock", "fsync", "fdatasync",
                "getcwd", "chdir", "rename", "mkdir", "rmdir", "unlink",
                "readlink", "chmod", "getuid", "getgid", "geteuid", "getegid",
                "getppid", "getpgrp", "setsid", "getgroups",
                "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                "ioctl", "pread64", "pwrite64", "readv", "writev",
                "pipe2", "epoll_create1", "epoll_ctl", "epoll_wait",
                "eventfd2", "openat", "newfstatat", "getrandom",
                "clock_gettime", "clock_getres", "futex",
                "set_tid_address", "set_robust_list", "arch_prctl",
                "exit_group", "tgkill", "madvise", "sched_getaffinity",
                "prlimit64", "close_range", "rseq", "statx"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ],
    "comment_blocked": "Explicitly blocked (not in allowlist): mount, umount, ptrace, reboot, swapon, swapoff, pivot_root, chroot, setuid, setgid, setns, unshare, keyctl, bpf, userfaultfd, perf_event_open, kexec_load, init_module, finit_module, delete_module"
}
```

### 1.6 AppArmor Profile (Linux hosts)

```
#include <tunables/global>

profile phantom-sandbox flags=(attach_disconnected) {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/python>

    # Deny all file access by default, then allow specific paths
    deny /etc/shadow r,
    deny /etc/passwd w,
    deny /root/** rwx,
    deny /home/** rwx,
    deny /var/run/docker.sock rw,
    deny /proc/*/mem rw,
    deny /sys/** w,
    deny /dev/** w,

    # Allow workspace and output
    /workspace/** r,
    /workspace/run.py r,
    /output/** rw,
    /tmp/** rw,
    /scope/current_scope.md r,

    # Allow Python runtime
    /usr/bin/python3* ix,
    /usr/lib/python3/** r,
    /usr/local/lib/python3/** r,

    # Network: allow TCP/UDP outbound (iptables handles scope enforcement)
    network tcp,
    network udp,
    network inet,
    network inet6,

    # Deny raw sockets (no ARP spoofing, no packet crafting from sandbox)
    deny network raw,
    deny network packet,
}
```

### 1.7 Sandbox Docker Image

The sandbox image must be minimal and purpose-built:

```dockerfile
FROM python:3.12-slim AS phantom-sandbox

# Install only the packages that dynamic scripts may need
RUN pip install --no-cache-dir \
    requests \
    httpx \
    beautifulsoup4 \
    lxml \
    pycryptodome \
    paramiko \
    impacket \
    scapy \
    dnspython \
    python-nmap \
    jwt \
    && rm -rf /root/.cache

# Create non-root user
RUN groupadd -g 1000 phantom && \
    useradd -u 1000 -g phantom -s /bin/false phantom

# Create workspace directories
RUN mkdir -p /workspace /output /scope && \
    chown phantom:phantom /workspace /output

USER phantom
WORKDIR /workspace

# Default entrypoint: execute the mounted script
ENTRYPOINT ["python3"]
```

---

## 2. Scope Enforcement

### 2.1 Threat Model

Scope bypass is the single most dangerous failure mode. An out-of-scope action turns
authorized penetration testing into an unauthorized attack -- a criminal act in most
jurisdictions. Threats include:

- **Direct bypass:** Generated script makes HTTP requests without calling `scope_guard`.
- **DNS rebinding:** Target resolves to an in-scope IP during `scope_guard` check, then
  resolves to out-of-scope IP during actual request.
- **URL parsing differentials:** `scope_guard` parses a URL differently than the HTTP
  client (e.g., `http://in-scope.com@evil.com` -- already mitigated in current code).
- **SSRF via target:** In-scope target is instructed to make requests to out-of-scope
  destinations.
- **Redirect following:** HTTP client follows a 302 redirect from in-scope host to
  out-of-scope host.
- **Scope file modification:** Agent or generated script modifies `current_scope.md` to
  add unauthorized targets.

### 2.2 Defense-in-Depth: Three Independent Layers

```
Layer 1: Application-level scope_guard (current implementation)
  |
  | Can be bypassed by dynamic scripts -- NECESSARY BUT NOT SUFFICIENT
  |
Layer 2: Network-level enforcement (iptables/nftables -- see Section 6)
  |
  | Cannot be bypassed by application code -- enforced by kernel
  |
Layer 3: DNS-level enforcement (local resolver with allowlist)
  |
  | Prevents DNS rebinding and resolution of out-of-scope hostnames
```

All three layers must agree. If any layer blocks a request, the request is denied.

### 2.3 Application-Level Improvements

#### 2.3.1 Existing Bug: Empty Scope Default

The current `is_in_scope()` correctly implements default-deny when the scope file is
empty. However, `tests/test_scope_checker.py` line 117 contains a contradictory test:

```python
def test_empty_scope_permissive(self, scope_file):
    f = scope_file("")
    assert is_in_scope("anything.com", f) is True  # BUG: test expects True
```

The test name says "permissive" but the code correctly returns `False`. **The test must
be fixed to expect `False`.** An empty scope must NEVER be permissive.

#### 2.3.2 Scope File Integrity

The scope file must be protected from modification after mission start:

```python
import hashlib

class ScopeEnforcer:
    """Immutable scope enforcement with integrity checking."""

    def __init__(self, scope_file: str):
        self._scope_file = scope_file
        self._targets = load_scope_targets(scope_file)
        self._file_hash = self._compute_hash(scope_file)

        if not self._targets:
            raise ValueError(
                "FATAL: No scope targets loaded. "
                "Cannot start a mission without an authorized scope."
            )

    def _compute_hash(self, path: str) -> str:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def check_integrity(self) -> bool:
        """Verify scope file has not been modified since mission start."""
        current_hash = self._compute_hash(self._scope_file)
        if current_hash != self._file_hash:
            raise SecurityError(
                f"SCOPE FILE TAMPERED: hash mismatch. "
                f"Expected {self._file_hash[:16]}..., got {current_hash[:16]}... "
                f"Mission aborted."
            )
        return True

    def is_in_scope(self, target: str) -> bool:
        """Check scope with integrity verification."""
        self.check_integrity()
        return is_in_scope(target, self._scope_file)
```

#### 2.3.3 Redirect Following

All HTTP requests made by Phantom tools MUST disable automatic redirect following or
validate each redirect destination against scope:

```python
import requests

def scope_safe_request(url: str, scope_enforcer: ScopeEnforcer, **kwargs) -> requests.Response:
    """Make an HTTP request with scope-checked redirect following."""
    kwargs["allow_redirects"] = False
    max_redirects = kwargs.pop("max_redirects", 10)

    for i in range(max_redirects):
        if not scope_enforcer.is_in_scope(url):
            raise ScopeViolation(f"Request to out-of-scope URL: {url}")

        response = requests.request(kwargs.pop("method", "GET"), url, **kwargs)

        if response.is_redirect:
            redirect_url = response.headers.get("Location", "")
            if not redirect_url:
                return response

            # Resolve relative redirects
            from urllib.parse import urljoin
            redirect_url = urljoin(url, redirect_url)

            if not scope_enforcer.is_in_scope(redirect_url):
                raise ScopeViolation(
                    f"Redirect to out-of-scope URL blocked: {url} -> {redirect_url}"
                )
            url = redirect_url
            continue
        else:
            return response

    raise TooManyRedirects(f"Exceeded {max_redirects} redirects")
```

#### 2.3.4 Dynamic Script Scope Enforcement

Generated scripts running in the sandbox container must also be subject to scope
enforcement. The sandbox container has the scope file mounted at `/scope/current_scope.md`.
The sandbox Python environment must include a `phantom_scope` module that wraps all
network calls:

```python
# phantom_scope.py -- baked into the sandbox image
# Intercepts socket.connect to enforce scope at the lowest Python level

import socket
import ipaddress
import functools

_original_connect = socket.socket.connect
_allowed_ips = set()     # Populated at container startup from /scope/current_scope.md
_allowed_cidrs = []

def _load_scope():
    """Load scope from mounted file."""
    global _allowed_ips, _allowed_cidrs
    try:
        with open("/scope/current_scope.md") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Parse IPs, CIDRs, resolve hostnames
                # (Implementation matches scope_checker.py logic)
    except FileNotFoundError:
        pass  # No scope = no connections allowed

def _checked_connect(self, address):
    """Intercept socket.connect to enforce scope."""
    host = address[0] if isinstance(address, tuple) else str(address)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname -- resolve first
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            raise ConnectionError(f"SCOPE: Cannot resolve {host}")

    if str(ip) not in _allowed_ips:
        in_cidr = any(ip in cidr for cidr in _allowed_cidrs)
        if not in_cidr:
            raise ConnectionError(
                f"SCOPE VIOLATION: Connection to {host} ({ip}) blocked. "
                f"Target is not in authorized scope."
            )

    return _original_connect(self, address)

# Monkey-patch at import time
_load_scope()
socket.socket.connect = _checked_connect
```

This module must be auto-imported via the sandbox's `PYTHONSTARTUP` or `sitecustomize.py`.

### 2.4 DNS-Level Enforcement

Run a local DNS resolver (e.g., `dnsmasq` or `unbound`) that only resolves hostnames
present in the scope file. All other queries return NXDOMAIN.

```bash
# Generate dnsmasq config from scope file
# This runs on the HOST, before mission start

phantom-dns-setup() {
    local scope_file="$1"
    local dns_conf="/etc/dnsmasq.d/phantom-scope.conf"

    echo "# Phantom scope DNS enforcement -- auto-generated" > "$dns_conf"
    echo "no-resolv" >> "$dns_conf"
    echo "no-hosts" >> "$dns_conf"

    # For each domain in scope, allow resolution via upstream DNS
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [ -z "$line" ] && continue

        # Extract hostname from URL
        host=$(echo "$line" | sed -E 's|https?://||; s|/.*||; s|:.*||')
        [ -z "$host" ] && continue

        echo "server=/$host/8.8.8.8" >> "$dns_conf"
    done < "$scope_file"

    # Block everything else
    echo "address=/#/0.0.0.0" >> "$dns_conf"

    systemctl restart dnsmasq
}
```

The sandbox container MUST use this local resolver as its only DNS server:

```python
# In container run config:
"dns": ["172.17.0.1"],     # Host's Docker bridge IP (where dnsmasq listens)
"dns_search": ["."],       # Prevent search domain expansion
```

---

## 3. Secret Protection

### 3.1 Threat Model

The host machine running Phantom contains secrets that must never be exposed:

- **LLM API keys** (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) in `.env` or environment
- **SSH keys** in `~/.ssh/`
- **Cloud credentials** (`~/.aws/`, `~/.gcp/`, `~/.azure/`)
- **Git credentials** (`~/.gitconfig`, credential helpers)
- **Browser data** (cookies, saved passwords)
- **Target credentials** obtained during the engagement (stored in `auth.json`)

### 3.2 Environment Variable Isolation

The sandbox container MUST NOT inherit the host's environment variables. The container
run config must explicitly set only the variables needed:

```python
SANDBOX_ENV_ALLOWLIST = [
    "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
    "TERM",
    "LANG",
    "LC_ALL",
    "HOME",
    "USER",
    "PATH",
    # Phantom-specific
    "PHANTOM_SCOPE_FILE",
    "PHANTOM_SESSION_ID",
]

def get_sandbox_env(session_id: str) -> dict:
    """Build a clean environment for the sandbox container."""
    return {
        "PYTHONPATH": "/workspace",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TERM": "xterm",
        "LANG": "C.UTF-8",
        "HOME": "/tmp",
        "USER": "phantom",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PHANTOM_SCOPE_FILE": "/scope/current_scope.md",
        "PHANTOM_SESSION_ID": session_id,
        # Explicitly empty -- prevent any leak
        "ANTHROPIC_API_KEY": "",
        "OPENAI_API_KEY": "",
        "GEMINI_API_KEY": "",
        "MISTRAL_API_KEY": "",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
    }
```

### 3.3 Auth Manager Hardening

The current `auth_manager.py` uses XOR "obfuscation" which provides no real protection.
For the dynamic tool generation model, credentials must be handled differently:

1. **Credentials never enter the sandbox container.** The sandbox makes HTTP requests
   through a proxy (running on the host) that injects authentication headers. The
   generated script never sees the actual credential values.

2. **Auth proxy architecture:**

```
Sandbox Container                     Host
+------------------+                  +----------------------+
| Generated Script |  -- HTTP -->     | Auth Injection Proxy |
| requests.get(    |  (plain request) | - Reads auth.json    |
|   "http://target"|                  | - Adds auth headers  |
|   proxies={...}) |                  | - Forwards to target |
+------------------+                  +----------------------+
                                              |
                                              v
                                        Target Server
```

3. **Host-side secret storage** should use OS-level secret storage (e.g., `keyring`
   library, macOS Keychain, Windows Credential Manager) rather than JSON files.
   `auth.json` with XOR obfuscation is acceptable only as a fallback when no OS
   credential store is available.

### 3.4 Log Redaction

The current `_SecretRedactFilter` in `main.py` is a good start. It must be extended and
also applied to sandbox output:

```python
class SecretRedactFilter:
    """Redact secrets from any text output."""

    PATTERNS = [
        # API keys (various providers)
        re.compile(r'(sk-[a-zA-Z0-9]{20,})'),
        re.compile(r'(xai-[a-zA-Z0-9]{20,})'),
        re.compile(r'(AIza[a-zA-Z0-9_-]{35})'),              # Google API keys
        re.compile(r'(ghp_[a-zA-Z0-9]{36})'),                # GitHub tokens
        re.compile(r'(AKIA[A-Z0-9]{16})'),                   # AWS access key IDs

        # Auth headers
        re.compile(r'(Bearer\s+[A-Za-z0-9\-._~+/]+=*)'),
        re.compile(r'(Basic\s+[A-Za-z0-9+/]+=*)'),

        # Generic patterns
        re.compile(r'(?i)(api[_-]?key\s*[=:]\s*)\S+'),
        re.compile(r'(?i)(password\s*[=:]\s*)\S+'),
        re.compile(r'(?i)(secret\s*[=:]\s*)\S+'),
        re.compile(r'(?i)(token\s*[=:]\s*)\S+'),

        # Private key material
        re.compile(r'(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)'),

        # Connection strings
        re.compile(r'(?i)((?:mysql|postgres|mongodb|redis)://\S+:\S+@\S+)'),
    ]

    @classmethod
    def redact(cls, text: str) -> str:
        for pattern in cls.PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text
```

### 3.5 Filesystem Protection on Host

Even for the built-in tools (which run on the host, not in the sandbox), filesystem
access must be restricted:

```python
# In logs_helper.py -- already partially implemented (path traversal check)
# Extend to all file operations across the codebase

FORBIDDEN_HOST_PATHS = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.gcp"),
    os.path.expanduser("~/.azure"),
    os.path.expanduser("~/.gnupg"),
    os.path.expanduser("~/.gitconfig"),
    os.path.expanduser("~/.npmrc"),
    os.path.expanduser("~/.pypirc"),
    os.path.expanduser("~/.docker"),
    os.path.expanduser("~/.kube"),
    "/etc/shadow",
    "/etc/sudoers",
]

def assert_safe_path(path: str) -> None:
    """Raise SecurityError if path points to a sensitive location."""
    abs_path = os.path.abspath(path)
    for forbidden in FORBIDDEN_HOST_PATHS:
        forbidden_abs = os.path.abspath(forbidden)
        if abs_path == forbidden_abs or abs_path.startswith(forbidden_abs + os.sep):
            raise SecurityError(f"Access to sensitive path blocked: {path}")
```

---

## 4. Audit Trail

### 4.1 Requirements

Every action Phantom takes must be logged with sufficient detail for a complete post-engagement
debrief and for forensic review if something goes wrong. The audit trail is the engagement's
legal record.

### 4.2 Audit Event Schema

```python
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import json
import hashlib

class AuditSeverity(Enum):
    INFO = "INFO"
    ACTION = "ACTION"         # Normal tool execution
    SCOPE_CHECK = "SCOPE"     # Scope verification
    EXPLOIT = "EXPLOIT"       # Exploitation attempt
    DYNAMIC = "DYNAMIC"       # Dynamic script execution
    SECURITY = "SECURITY"     # Security-relevant event (blocked action, scope violation)
    KILL = "KILL"             # Kill switch activation

@dataclass
class AuditEvent:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = ""                # e.g., "tool_execution", "scope_check", "dynamic_script"
    severity: str = "INFO"
    tool_name: str = ""
    target: str = ""                    # Target host/IP
    parameters: dict = field(default_factory=dict)
    result_summary: str = ""            # First 500 chars of result
    result_hash: str = ""               # SHA-256 of full result (for integrity)
    scope_verified: bool = False
    session_id: str = ""
    turn_number: int = 0
    script_hash: str = ""               # For dynamic scripts
    exit_code: int | None = None        # For dynamic scripts
    blocked: bool = False               # True if action was blocked by security controls
    block_reason: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)
```

### 4.3 Audit Logger

```python
import fcntl
import os

class AuditLogger:
    """Append-only, tamper-evident audit log."""

    def __init__(self, session_dir: str):
        self.log_path = os.path.join(session_dir, "audit.jsonl")
        self._event_count = 0
        self._hash_chain = hashlib.sha256(b"PHANTOM_AUDIT_GENESIS").hexdigest()

    def log(self, event: AuditEvent) -> None:
        """Append an audit event to the log with hash chaining."""
        self._event_count += 1

        # Hash chain: each entry includes the hash of the previous entry
        # This makes retroactive modification detectable
        event_json = event.to_json()
        chain_input = f"{self._hash_chain}:{event_json}"
        self._hash_chain = hashlib.sha256(chain_input.encode()).hexdigest()

        log_line = json.dumps({
            "seq": self._event_count,
            "chain_hash": self._hash_chain,
            "event": asdict(event),
        }, ensure_ascii=False)

        # Atomic append with file locking
        with open(self.log_path, "a", encoding="utf-8") as f:
            # fcntl.flock for Unix; on Windows use msvcrt.locking
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except (ImportError, AttributeError, OSError):
                pass  # Best effort on Windows
            f.write(log_line + "\n")
            f.flush()
            os.fsync(f.fileno())

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the hash chain of the audit log.

        Returns (is_valid, last_valid_sequence_number).
        """
        chain = hashlib.sha256(b"PHANTOM_AUDIT_GENESIS").hexdigest()
        last_valid = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                entry = json.loads(line)
                event_json = json.dumps(entry["event"], ensure_ascii=False)
                expected = hashlib.sha256(f"{chain}:{event_json}".encode()).hexdigest()

                if entry["chain_hash"] != expected:
                    return False, last_valid

                chain = expected
                last_valid = entry["seq"]

        return True, last_valid
```

### 4.4 What Gets Logged

| Event                        | Severity   | Details Captured                                      |
|------------------------------|------------|-------------------------------------------------------|
| Tool execution (built-in)    | ACTION     | Tool name, parameters, target, result summary         |
| Scope check                  | SCOPE      | Target, result (in/out), authorized targets list      |
| Scope violation (blocked)    | SECURITY   | Target, which layer blocked it, authorized targets    |
| Dynamic script submitted     | DYNAMIC    | Full script content (SHA-256 + path to stored copy)   |
| Dynamic script result        | DYNAMIC    | Exit code, stdout/stderr summary, duration            |
| Dynamic script blocked       | SECURITY   | Script hash, blocked pattern, full script preserved   |
| Exploit attempt              | EXPLOIT    | Module, target, payload, options, outcome             |
| Auth credential configured   | SECURITY   | Auth type, target scope (NOT the credential value)    |
| Kill switch activated        | KILL       | Trigger (manual/automatic), reason, state at trigger  |
| Mission start/stop           | INFO       | Config, scope hash, provider, model                   |
| State save/resume            | INFO       | Turn number, message count                            |
| Network connection (sandbox) | ACTION     | Destination IP, port, protocol, scope check result    |
| Rate limit detected          | INFO       | Tool, target, count, stealth profile change           |
| Stall detection triggered    | INFO       | Turns without findings, total findings                |

### 4.5 Dynamic Script Archival

Every dynamically generated script must be preserved in its entirety, regardless of
whether it was executed or blocked:

```
logs/<session>/
    audit.jsonl                    # Hash-chained audit log
    agent.log                      # Detailed application log
    sandbox_audit.jsonl            # Sandbox-specific execution log
    sandbox_output/
        script_<hash12>.py         # Every generated script (by content hash)
        script_<hash12>.stdout     # Corresponding stdout
        script_<hash12>.stderr     # Corresponding stderr
    state.json                     # Mission state (for resume)
    report_*.md                    # Final reports
```

---

## 5. Kill Switch

### 5.1 Requirements

The operator must be able to abort the mission immediately and completely. "Immediately"
means within 1 second of activation, not after the current tool finishes. "Completely"
means all activity stops -- including sandbox containers, background processes, and
network connections.

### 5.2 Kill Switch Mechanisms

#### 5.2.1 Manual Kill Switch (Operator-Initiated)

```python
import os
import signal
import sys
import threading

# Global kill flag -- checked by every tool before execution
_KILL_FLAG = threading.Event()
_KILL_FILE = os.path.join(os.environ.get("PHANTOM_SESSION_DIR", "logs"), ".kill")

def activate_kill_switch(reason: str = "Manual abort"):
    """Activate the kill switch. Stops everything."""
    _KILL_FLAG.set()

    # Write kill file (persists across restarts, prevents resume)
    with open(_KILL_FILE, "w") as f:
        f.write(f"{reason}\n{time.time()}\n")

    # Kill all sandbox containers
    try:
        import docker
        client = docker.from_env()
        for container in client.containers.list(filters={"label": "phantom-sandbox"}):
            container.kill()
            container.remove(force=True)
    except Exception:
        pass

    # Flush audit log
    # (audit logger should handle this in its destructor)

    # Log the kill
    import logging
    logging.getLogger("phantom.kill").critical(
        "KILL SWITCH ACTIVATED: %s", reason
    )

def is_killed() -> bool:
    """Check if the kill switch has been activated."""
    if _KILL_FLAG.is_set():
        return True
    if os.path.exists(_KILL_FILE):
        _KILL_FLAG.set()
        return True
    return False

def check_kill_or_raise():
    """Raise SystemExit if kill switch is active. Call this before every tool execution."""
    if is_killed():
        raise SystemExit("KILL SWITCH ACTIVE -- mission aborted")
```

#### 5.2.2 Signal-Based Kill (Ctrl+C Enhancement)

The current `KeyboardInterrupt` handler in `main.py` saves state and exits. For the
autonomous model, this must be more aggressive:

```python
def _setup_kill_signals():
    """Register signal handlers for immediate abort."""

    def _handler(signum, frame):
        print("\n\n*** KILL SWITCH ACTIVATED ***")
        activate_kill_switch(f"Signal {signum}")
        sys.exit(1)

    signal.signal(signal.SIGINT, _handler)    # Ctrl+C
    signal.signal(signal.SIGTERM, _handler)   # kill <pid>
    if hasattr(signal, "SIGQUIT"):
        signal.signal(signal.SIGQUIT, _handler)  # Ctrl+\ (Unix)
```

#### 5.2.3 File-Based Kill (Remote/Headless Abort)

For headless operation, the operator can trigger a kill by creating a file:

```bash
# From another terminal or SSH session:
touch logs/<session>/.kill

# Or with a reason:
echo "Target owner requested immediate stop" > logs/<session>/.kill
```

The main loop and every tool must check for this file.

#### 5.2.4 Automatic Kill Triggers

The system must automatically activate the kill switch if:

1. **Repeated scope violations:** More than 3 scope violations in a single session
   indicate the agent is misbehaving.
2. **Sandbox escape detected:** Any sandbox container exits with a security-relevant
   error (e.g., capability use, prohibited syscall).
3. **Scope file tampering:** Integrity check fails (hash mismatch).
4. **Resource exhaustion:** Host system memory or disk usage exceeds 90%.

```python
class AutoKillMonitor:
    """Monitor for conditions that should trigger automatic abort."""

    MAX_SCOPE_VIOLATIONS = 3
    MAX_DISK_USAGE_PERCENT = 90
    MAX_MEMORY_USAGE_PERCENT = 90

    def __init__(self):
        self._scope_violation_count = 0

    def on_scope_violation(self, target: str):
        self._scope_violation_count += 1
        if self._scope_violation_count >= self.MAX_SCOPE_VIOLATIONS:
            activate_kill_switch(
                f"Automatic: {self._scope_violation_count} scope violations "
                f"(last target: {target})"
            )

    def on_scope_tamper(self):
        activate_kill_switch("Automatic: scope file integrity check failed")

    def check_resources(self):
        import shutil
        disk = shutil.disk_usage("/")
        disk_percent = (disk.used / disk.total) * 100
        if disk_percent > self.MAX_DISK_USAGE_PERCENT:
            activate_kill_switch(
                f"Automatic: disk usage at {disk_percent:.1f}%"
            )
```

### 5.3 Kill Switch Integration Points

The kill switch check (`check_kill_or_raise()`) MUST be called:

1. Before every tool execution in `AgentClient._execute_tool()`
2. Before every LLM API call in `AgentClient.think()`
3. At the start of every iteration of the main loop in `main.py`
4. Before every sandbox container launch
5. Inside long-running tools (nmap, sqlmap, etc.) at periodic intervals

---

## 6. Network-Level Controls

### 6.1 Design Principle

Application-level scope checking (Python code) can be bypassed by dynamic scripts.
Network-level enforcement (kernel iptables/nftables rules) cannot be bypassed by
application code. This is the most critical layer of defense.

### 6.2 Architecture

Create a dedicated Docker network (`phantom-scope-net`) with iptables rules that only
allow traffic to in-scope destinations. This network is used by all sandbox containers.

### 6.3 Network Setup Script

```bash
#!/bin/bash
# phantom-network-setup.sh
# Run as root before starting a mission.
# Reads the scope file and creates iptables rules.

set -euo pipefail

SCOPE_FILE="${1:?Usage: $0 <scope-file>}"
CHAIN_NAME="PHANTOM_SCOPE"
DOCKER_NETWORK="phantom-scope-net"
DOCKER_SUBNET="172.30.0.0/24"
DNS_SERVER="172.30.0.1"

# ------------------------------------------------------------------
# 1. Create Docker network (if not exists)
# ------------------------------------------------------------------
if ! docker network inspect "$DOCKER_NETWORK" &>/dev/null; then
    docker network create \
        --driver bridge \
        --subnet "$DOCKER_SUBNET" \
        --opt "com.docker.network.bridge.name=br-phantom" \
        "$DOCKER_NETWORK"
    echo "[+] Created Docker network: $DOCKER_NETWORK ($DOCKER_SUBNET)"
fi

# ------------------------------------------------------------------
# 2. Create iptables chain
# ------------------------------------------------------------------
# Flush existing rules if chain exists
iptables -N "$CHAIN_NAME" 2>/dev/null || iptables -F "$CHAIN_NAME"

# Remove old jump rule if exists
iptables -D FORWARD -s "$DOCKER_SUBNET" -j "$CHAIN_NAME" 2>/dev/null || true

# ------------------------------------------------------------------
# 3. Default: DROP all traffic from phantom containers
# ------------------------------------------------------------------
iptables -A "$CHAIN_NAME" -j LOG --log-prefix "PHANTOM_BLOCKED: " --log-level warning
iptables -A "$CHAIN_NAME" -j DROP

# ------------------------------------------------------------------
# 4. Allow DNS to local resolver only
# ------------------------------------------------------------------
iptables -I "$CHAIN_NAME" 1 -d "$DNS_SERVER" -p udp --dport 53 -j ACCEPT
iptables -I "$CHAIN_NAME" 2 -d "$DNS_SERVER" -p tcp --dport 53 -j ACCEPT

# ------------------------------------------------------------------
# 5. Allow traffic to in-scope targets only
# ------------------------------------------------------------------
RULE_NUM=3
while IFS= read -r line; do
    # Strip comments and whitespace
    line=$(echo "$line" | sed 's/#.*//' | xargs)
    [ -z "$line" ] && continue

    # Extract host from URL
    host=$(echo "$line" | sed -E 's|https?://||; s|/.*||; s|:.*||')
    [ -z "$host" ] && continue

    # Check if it is a CIDR
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
        iptables -I "$CHAIN_NAME" "$RULE_NUM" -d "$host" -j ACCEPT
        echo "[+] Allowed CIDR: $host"
        RULE_NUM=$((RULE_NUM + 1))
        continue
    fi

    # Check if it is an IP
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        iptables -I "$CHAIN_NAME" "$RULE_NUM" -d "$host" -j ACCEPT
        echo "[+] Allowed IP: $host"
        RULE_NUM=$((RULE_NUM + 1))
        continue
    fi

    # It is a hostname -- resolve all IPs and allow them
    resolved=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [ -z "$resolved" ]; then
        echo "[!] WARNING: Cannot resolve $host -- skipping"
        continue
    fi

    for ip in $resolved; do
        iptables -I "$CHAIN_NAME" "$RULE_NUM" -d "$ip" -j ACCEPT -m comment --comment "scope:$host"
        echo "[+] Allowed $host -> $ip"
        RULE_NUM=$((RULE_NUM + 1))
    done

done < "$SCOPE_FILE"

# ------------------------------------------------------------------
# 6. Allow established/related connections (for TCP responses)
# ------------------------------------------------------------------
iptables -I "$CHAIN_NAME" 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# ------------------------------------------------------------------
# 7. Insert jump from FORWARD chain
# ------------------------------------------------------------------
iptables -I FORWARD -s "$DOCKER_SUBNET" -j "$CHAIN_NAME"

echo ""
echo "[+] Network enforcement active."
echo "[+] Phantom containers on $DOCKER_NETWORK can only reach in-scope targets."
echo "[+] Blocked traffic logged with prefix 'PHANTOM_BLOCKED:'"
```

### 6.4 Network Teardown

```bash
#!/bin/bash
# phantom-network-teardown.sh
# Run after mission ends or on kill switch activation.

CHAIN_NAME="PHANTOM_SCOPE"
DOCKER_NETWORK="phantom-scope-net"
DOCKER_SUBNET="172.30.0.0/24"

# Remove jump rule
iptables -D FORWARD -s "$DOCKER_SUBNET" -j "$CHAIN_NAME" 2>/dev/null || true

# Flush and delete chain
iptables -F "$CHAIN_NAME" 2>/dev/null || true
iptables -X "$CHAIN_NAME" 2>/dev/null || true

# Remove Docker network
docker network rm "$DOCKER_NETWORK" 2>/dev/null || true

echo "[+] Network enforcement removed."
```

### 6.5 Windows Support

On Windows (the current development environment), iptables is not available. Options:

1. **WSL2 with iptables:** Run Phantom inside WSL2 where iptables rules can be applied.
   This is the recommended approach for Windows.

2. **Windows Firewall (netsh):** Less granular but functional:

```powershell
# phantom-network-setup.ps1
param([string]$ScopeFile)

$scopeLines = Get-Content $ScopeFile | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }

# Block all outbound from phantom containers by default
# (requires Hyper-V isolation or Windows containers)

foreach ($line in $scopeLines) {
    $host = $line -replace 'https?://' -replace '/.*' -replace ':.*'
    if ($host) {
        $ips = [System.Net.Dns]::GetHostAddresses($host) | ForEach-Object { $_.IPAddressToString }
        foreach ($ip in $ips) {
            netsh advfirewall firewall add rule name="Phantom-Allow-$host" `
                dir=out action=allow remoteip=$ip profile=any
        }
    }
}

# Block-all rule (lower priority)
netsh advfirewall firewall add rule name="Phantom-Block-All" `
    dir=out action=block program="*" profile=any
```

3. **Docker Desktop with custom networks:** Docker Desktop on Windows supports custom
   bridge networks. Combine with the sandbox container's `--network` flag.

### 6.6 Logging Blocked Connections

All blocked connection attempts are logged by iptables (`--log-prefix "PHANTOM_BLOCKED:"`).
These logs must be monitored by the `AutoKillMonitor` and included in the audit trail.

```python
def _monitor_firewall_log(log_path: str = "/var/log/kern.log"):
    """Watch firewall logs for PHANTOM_BLOCKED entries."""
    import subprocess
    proc = subprocess.Popen(
        ["tail", "-F", log_path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True,
    )
    for line in proc.stdout:
        if "PHANTOM_BLOCKED" in line:
            # Parse destination IP from log line
            # Log to audit trail as SECURITY event
            audit_logger.log(AuditEvent(
                event_type="network_blocked",
                severity=AuditSeverity.SECURITY.value,
                result_summary=line.strip()[:500],
            ))
```

---

## 7. Risk Classification

### 7.1 Action Categories

Every action Phantom can take is classified into one of four risk tiers. Each tier has
different security requirements.

| Tier | Risk Level | Description                            | Examples                                       |
|------|------------|----------------------------------------|------------------------------------------------|
| T1   | LOW        | Passive information gathering          | DNS lookups, WHOIS, certificate inspection     |
| T2   | MEDIUM     | Active scanning and enumeration        | Nmap, ffuf, Nuclei, WhatWeb, directory fuzzing |
| T3   | HIGH       | Exploitation and credential attacks    | SQLMap, Metasploit, Hydra, custom exploits     |
| T4   | CRITICAL   | Persistence, lateral movement, exfil   | Reverse shells, pivoting, data extraction      |

### 7.2 Security Requirements by Tier

```
                    T1 (LOW)    T2 (MED)    T3 (HIGH)   T4 (CRIT)
                    --------    --------    ---------   ---------
Scope check         Required    Required    Required    Required
Network firewall    Active      Active      Active      Active
Sandbox container   Optional    Optional    Required    Required
Audit logging       Standard    Standard    Enhanced    Enhanced
Script review       N/A         N/A         Auto-scan   Auto-scan
Kill switch check   Yes         Yes         Yes         Yes
Human approval      No          No          Configurable Required*
Rate limiting       Yes         Yes         Yes         Yes
```

*Human approval for T4 actions is configurable via `config.yaml`. When running in fully
autonomous mode, T4 actions are allowed without approval but trigger enhanced logging
and an alert to the operator (if monitoring is configured).

### 7.3 Tool-to-Tier Mapping

```python
TOOL_RISK_TIERS = {
    # T1: Passive
    "check_scope": "T1",
    "read_log": "T1",
    "set_stealth_profile": "T1",
    "cleanup_temp": "T1",
    "generate_report": "T1",
    "request_human_input": "T1",
    "compute_cvss": "T1",

    # T2: Active scanning
    "run_nmap": "T2",
    "run_nuclei": "T2",
    "run_ffuf": "T2",
    "run_recon": "T2",
    "run_whatweb": "T2",
    "take_screenshot": "T2",
    "run_wpscan": "T2",
    "graphql_enum": "T2",
    "run_payloads": "T2",  # Fetches payloads; injection is T3
    "run_bettercap": "T2",

    # T3: Exploitation
    "run_sqlmap": "T3",
    "run_metasploit": "T3",
    "run_hydra": "T3",
    "jwt_tool": "T3",
    "generate_phish_template": "T3",
    "generate_zphisher_template": "T3",
    "configure_auth": "T3",

    # T4: Post-exploitation
    "run_privesc_check": "T4",
    "mission_diff": "T4",

    # Dynamic scripts: classified at runtime based on content analysis
    "dynamic_script": "T3",  # Default; elevated to T4 if persistence/exfil detected
}
```

### 7.4 Dynamic Script Risk Assessment

Generated scripts must be classified before execution:

```python
import re

T4_INDICATORS = [
    # Persistence mechanisms
    r"cron",
    r"systemctl\s+enable",
    r"at\s+",
    r"\.bashrc",
    r"\.profile",
    r"registry",
    r"scheduled.?task",
    r"service\s+--status-all",
    r"authorized_keys",

    # Lateral movement
    r"paramiko",
    r"psexec",
    r"wmiexec",
    r"smbclient",
    r"evil-winrm",
    r"spray",

    # Data exfiltration
    r"tar\s+.*-c",
    r"zip\s+.*-r",
    r"base64.*encode",
    r"exfil",
    r"upload.*file",
    r"ftp\.",
    r"smtplib",
    r"dns.*txt.*record",

    # Privilege escalation
    r"setuid",
    r"chmod\s+[0-7]*s",
    r"sudo\s+",
    r"dirtypipe",
    r"dirtycow",
    r"potato",
]

def classify_dynamic_script(script: str) -> str:
    """Return risk tier for a generated script."""
    for pattern in T4_INDICATORS:
        if re.search(pattern, script, re.IGNORECASE):
            return "T4"
    return "T3"  # Default for any dynamic code execution
```

### 7.5 Configurable Approval Gates

```yaml
# config.yaml
risk_gates:
    # Require human approval before executing actions at these tiers
    require_approval: ["T4"]    # Options: [], ["T3", "T4"], ["T4"]

    # In fully autonomous mode, override approval gates
    # WARNING: This means T4 actions execute without human confirmation
    autonomous_override: true

    # Alert mechanisms (always active, even in autonomous mode)
    alert_on_t3: false
    alert_on_t4: true
    alert_webhook: ""          # Optional: POST to webhook on T3/T4 execution
    alert_file: "logs/alerts.jsonl"
```

---

## 8. Implementation Priority

The following implementation order is recommended, based on risk reduction per effort:

| Priority | Component                          | Effort  | Risk Reduction |
|----------|------------------------------------|---------|----------------|
| P0       | Fix empty scope test bug           | 1 hour  | Critical       |
| P0       | Kill switch (file + signal based)  | 4 hours | Critical       |
| P0       | Scope file integrity checking      | 4 hours | Critical       |
| P1       | Audit logger with hash chaining    | 8 hours | High           |
| P1       | Network-level enforcement script   | 8 hours | Critical       |
| P1       | Container sandbox executor         | 16 hours| Critical       |
| P1       | Secret redaction (extended)        | 4 hours | High           |
| P2       | Risk classification enforcement    | 8 hours | Medium         |
| P2       | Auth proxy for sandbox             | 16 hours| High           |
| P2       | DNS-level enforcement              | 8 hours | Medium         |
| P2       | Redirect scope checking            | 4 hours | High           |
| P3       | Seccomp + AppArmor profiles        | 8 hours | Medium         |
| P3       | Sandbox Docker image build         | 4 hours | Medium         |
| P3       | Firewall log monitor               | 4 hours | Low            |
| P3       | Windows Firewall support           | 8 hours | Medium         |

---

## 9. Known Vulnerabilities in Current Codebase

The following issues were identified during the code review for this specification:

### 9.1 CRITICAL

1. **No network-level scope enforcement.** All scope checking is application-level only.
   A dynamically generated script can make arbitrary network connections to any
   destination. There is no kernel-level enforcement to prevent this.

2. **No sandboxing exists.** All tools execute on the host with full host privileges.
   The `privesc.py` tool runs `find / -perm -4000` and reads `/etc/shadow` on the HOST,
   not on a target. Once dynamic tool generation is added, arbitrary code will execute
   with the operator's full permissions.

3. **Test asserts wrong behavior for empty scope** (`test_empty_scope_permissive`). The
   test expects `True` (allow all) when the scope is empty, but the production code
   correctly returns `False` (deny all). If someone "fixes" the code to match the test,
   an empty scope file would authorize attacks against any target.

### 9.2 HIGH

4. **Auth credentials stored with reversible obfuscation.** `auth_manager.py` uses XOR
   with a predictable key derived from the session directory name. Anyone with access to
   `auth.json` and knowledge of the session directory can recover credentials in
   seconds. The comment says "not encryption" but the code returns these to the LLM in
   plaintext via `get_auth_headers()`.

5. **No redirect scope checking.** HTTP tools (recon, ffuf, etc.) follow redirects by
   default. An in-scope target can redirect to an out-of-scope host, and the tool will
   follow without re-checking scope.

6. **Metasploit blocked modules list is bypassable.** The `BLOCKED_MODULE_PATTERNS`
   check in `metasploit.py` is a substring match on the module path. Metasploit module
   aliases, symbolic links, or custom module paths could bypass this check. The check
   also does not cover all dangerous module categories.

7. **Secret redaction is incomplete.** The `_SecretRedactFilter` only covers a few
   patterns. AWS keys, GCP service account keys, GitHub tokens, and private key material
   are not redacted. The filter also only applies to Python logging, not to tool output
   that is sent back to the LLM (and potentially logged in `state.json`).

### 9.3 MEDIUM

8. **`privesc.py` runs on the host without scope context.** It enumerates SUID binaries,
   reads `/etc/shadow`, checks Docker socket access, and finds SSH keys -- all on the
   machine running Phantom. This is a local privilege escalation enumeration tool that
   should only run on a target system (inside a shell session or sandbox), never on the
   operator's machine.

9. **Path traversal in `log_path()` is mitigated but the safe fallback is weak.** When a
   traversal is detected, the code strips to `basename` but does not reject the
   operation. A more secure approach would raise an exception.

10. **State file (`state.json`) contains full conversation history** including tool
    results that may contain sensitive data (credentials found during the engagement,
    API responses with tokens, etc.). This file is written in plaintext with no access
    controls.

---

## 10. Security Testing Requirements

Before the dynamic tool generation feature ships, the following tests must pass:

### 10.1 Scope Enforcement Tests

- [ ] Empty scope file denies all targets (fix existing broken test)
- [ ] Scope file modification after mission start triggers kill switch
- [ ] HTTP redirect from in-scope to out-of-scope host is blocked
- [ ] URL with userinfo (`http://inscope@evil.com`) is rejected (already works)
- [ ] DNS rebinding is prevented by local resolver
- [ ] iptables rules block connections to out-of-scope IPs from sandbox
- [ ] Sandbox container cannot modify the mounted scope file

### 10.2 Sandbox Isolation Tests

- [ ] Sandbox container cannot access host filesystem beyond mounted volumes
- [ ] Sandbox container cannot access Docker socket
- [ ] Sandbox container cannot escalate privileges (no setuid, no capabilities)
- [ ] Sandbox container is killed after timeout
- [ ] Fork bomb in sandbox is contained by pids_limit
- [ ] Memory bomb in sandbox is contained by mem_limit
- [ ] Generated script with blocked pattern is rejected before execution
- [ ] Sandbox environment does not contain host API keys

### 10.3 Kill Switch Tests

- [ ] `Ctrl+C` stops all activity within 1 second
- [ ] `.kill` file creation stops all activity within 1 second
- [ ] Kill switch terminates running sandbox containers
- [ ] Killed mission cannot be resumed (`.kill` file prevents it)
- [ ] 3 scope violations trigger automatic kill

### 10.4 Audit Trail Tests

- [ ] Every tool execution produces an audit event
- [ ] Every dynamic script is archived with its full content
- [ ] Hash chain integrity can be verified after mission
- [ ] Secrets are not present in audit log (redaction works)
- [ ] Audit log survives a kill switch activation (fsync before exit)

---

## Appendix A: Threat Model Summary (STRIDE)

| Threat              | Component           | Risk     | Mitigation                                          |
|---------------------|---------------------|----------|-----------------------------------------------------|
| Spoofing            | Scope check         | Critical | Three-layer enforcement (app + network + DNS)       |
| Tampering           | Scope file          | Critical | SHA-256 integrity check, read-only mount            |
| Tampering           | Audit log           | High     | Hash-chained log, append-only, fsync                |
| Repudiation         | Tool execution      | High     | Comprehensive audit with tamper detection            |
| Info Disclosure     | API keys on host    | High     | Env isolation, no mount, auth proxy                 |
| Info Disclosure     | Target credentials  | High     | Secret redaction, secure delete                     |
| Info Disclosure     | State file          | Medium   | Redaction before write, access controls             |
| Denial of Service   | Host resources      | Medium   | Container resource limits, auto-kill on exhaustion  |
| Elevation of Priv   | Sandbox escape      | Critical | seccomp, AppArmor, no capabilities, non-root        |
| Elevation of Priv   | Dynamic code exec   | Critical | Container isolation, blocked patterns, risk tiers   |

## Appendix B: Glossary

- **Scope:** The set of authorized targets defined in `scopes/current_scope.md`.
- **Dynamic tool:** A Python script generated by the LLM at runtime.
- **Sandbox:** A disposable Docker container that executes dynamic tools in isolation.
- **Kill switch:** A mechanism to immediately abort all mission activity.
- **Scope guard:** Application-level function that checks if a target is authorized.
- **Audit trail:** The complete log of all actions taken during a mission.
- **Risk tier:** Classification of an action by its potential impact (T1-T4).
- **Defense-in-depth:** Multiple independent security layers so that failure of one
  layer does not compromise the system.
