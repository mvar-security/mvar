"""Curated sink catalog: dotted call names -> structural sink classes.

This is the one piece of real domain knowledge in the structural analyzer and
must be maintained as the ecosystem moves. Classes are MVAR-internal structural
sink classes, deliberately decoupled from the SinkPolicy registry so the
analyzer stays generic (it knows about ``requests.post``, never about MIRRA).

Soundness posture: over-approximate. A reachable sink that is never actually
called at runtime still counts — for a security control the false-positive
direction is a step-up, never a silent allow.
"""

from __future__ import annotations

# Structural sink classes
NET_HTTP = "net.http"      # network egress
PROC_EXEC = "proc.exec"    # subprocess / shell execution
DYN_EVAL = "dyn.eval"      # dynamic code evaluation
FS_WRITE = "fs.write"      # filesystem mutation
CRED_READ = "cred.read"    # credential / environment read

# Escalation tiers consumed by the gates. cred.read is deliberately
# informational-only in v0.1: environment reads are ubiquitous in legitimate
# tools, and escalating on them alone would make the control unusable. A
# cred.read that matters is almost always paired with net.http, which blocks.
CRITICAL_CLASSES = frozenset({NET_HTTP, PROC_EXEC, DYN_EVAL})
STEP_UP_CLASSES = frozenset({FS_WRITE})
INFORMATIONAL_CLASSES = frozenset({CRED_READ})

# Any call into these modules counts as the mapped class (prefix match on the
# resolved dotted name). Deliberately module-wide for egress/exec libraries:
# requests.get is egress just as much as requests.post.
MODULE_PREFIX_CLASSES = {
    "requests": NET_HTTP,
    "urllib.request": NET_HTTP,
    "urllib3": NET_HTTP,
    "http.client": NET_HTTP,
    "socket": NET_HTTP,
    "aiohttp": NET_HTTP,
    "httpx": NET_HTTP,
    "ftplib": NET_HTTP,
    "smtplib": NET_HTTP,
    "subprocess": PROC_EXEC,
    "pty": PROC_EXEC,
    "shutil": FS_WRITE,
    "keyring": CRED_READ,
}

# Exact dotted-name sinks. os is handled exclusively here (never module-wide:
# os.path.exists must not classify).
EXACT_SINKS = {
    "os.system": PROC_EXEC,
    "os.popen": PROC_EXEC,
    "os.execv": PROC_EXEC,
    "os.execve": PROC_EXEC,
    "os.execvp": PROC_EXEC,
    "os.spawnl": PROC_EXEC,
    "os.spawnv": PROC_EXEC,
    "os.startfile": PROC_EXEC,
    "os.remove": FS_WRITE,
    "os.unlink": FS_WRITE,
    "os.rename": FS_WRITE,
    "os.replace": FS_WRITE,
    "os.rmdir": FS_WRITE,
    "os.makedirs": FS_WRITE,
    "os.mkdir": FS_WRITE,
    "os.chmod": FS_WRITE,
    "os.getenv": CRED_READ,
    "os.environ.get": CRED_READ,
}

# Bare-name builtin sinks (calls to unqualified names).
NAME_SINKS = {
    "eval": DYN_EVAL,
    "exec": DYN_EVAL,
}

# Attribute *reads* (not calls) that classify — e.g. ``os.environ[...]``.
ATTRIBUTE_READ_SINKS = {
    "os.environ": CRED_READ,
}


def classify_dotted(dotted: str) -> str | None:
    """Map a resolved dotted call name to a sink class, or None."""
    if dotted in EXACT_SINKS:
        return EXACT_SINKS[dotted]
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in MODULE_PREFIX_CLASSES:
            return MODULE_PREFIX_CLASSES[prefix]
    return None
