import os
import re
import base64
from urllib.parse import urlsplit

from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_HOME = "/home/agent"
AGENT_CWD = "/home/agent/workspace"
SECRET_FILE = "/home/agent/.netrc"
WRITE_ROOT = "/home/agent/workspace/output"
ALLOWED_HOSTS = {"pypi.org", "objects.githubusercontent.com"}

# ---------- helpers ----------

def _b64_candidates(s):
    """Find base64-ish substrings and decode them."""
    out = []
    for c in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", s):
        try:
            padded = c + "=" * (-len(c) % 4)
            d = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if d.strip():
                out.append(d)
        except Exception:
            pass
    return out


def _expand_env(s):
    s = s.replace("${HOME}", AGENT_HOME).replace("$HOME", AGENT_HOME)
    s = re.sub(r"~(?=/|$)", AGENT_HOME, s)
    return s


def _resolve(token, cwd):
    token = token.strip("'\"")
    if not token.startswith("/"):
        token = os.path.join(cwd, token)
    return os.path.normpath(token)


def command_touches_secret(command: str) -> bool:
    """Detect any reference (direct or obfuscated) to the secret file."""
    layers = [command, _expand_env(command)]
    seen = set(layers)
    frontier = list(layers)

    # Recursively decode nested base64 a few levels deep
    for _ in range(3):
        new_layer = []
        for t in frontier:
            for d in _b64_candidates(t):
                for variant in (d, _expand_env(d)):
                    if variant not in seen:
                        seen.add(variant)
                        new_layer.append(variant)
        if not new_layer:
            break
        layers.extend(new_layer)
        frontier = new_layer

    for t in layers:
        if ".netrc" not in t:
            continue
        tokens = re.findall(r"[^\s'\"|;&<>()`]+\.netrc[^\s'\"|;&<>()`]*", t)
        for tok in tokens:
            if _resolve(tok, AGENT_CWD) == SECRET_FILE:
                return True
        # crude fallback for odd slashes/spacing
        if SECRET_FILE in t.replace("//", "/"):
            return True
    return False


def resolve_write_path(path: str) -> str:
    p = path
    if p == "/workspace" or p.startswith("/workspace/"):
        p = AGENT_HOME + p  # shorthand -> /home/agent/workspace/...
    if not p.startswith("/"):
        p = os.path.join(AGENT_CWD, p)
    return os.path.normpath(p)


def write_is_allowed(path: str) -> bool:
    resolved = resolve_write_path(path)
    return resolved == WRITE_ROOT or resolved.startswith(WRITE_ROOT + os.sep)


def host_is_allowed(url: str) -> bool:
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        host = (parts.hostname or "").lower().rstrip(".")
    except Exception:
        return False
    return host in ALLOWED_HOSTS


# ---------- route ----------


@app.route("/", methods=["POST"])
@app.route("/guardrail", methods=["POST"])
@app.route("/check", methods=["POST"])
def guardrail():

    try:
        body = request.get_json(force=True, silent=True) or {}
        tool = body.get("tool")

        if tool == "bash":
            command = body.get("command", "") or ""
            if command_touches_secret(command):
                return jsonify(decision="block",
                                reason="Command references the protected secrets file (.netrc), directly or via obfuscation.")
            return jsonify(decision="allow", reason="Command does not touch restricted paths.")

        if tool == "write_file":
            path = body.get("path", "") or ""
            if write_is_allowed(path):
                return jsonify(decision="allow", reason="Write target is inside the permitted output directory.")
            return jsonify(decision="block",
                            reason="Writes are only permitted inside /workspace/output/.")

        if tool == "http_request":
            url = body.get("url", "") or ""
            if host_is_allowed(url):
                return jsonify(decision="allow", reason="Destination host is on the allowed list.")
            return jsonify(decision="block", reason="Destination host is not exactly pypi.org or objects.githubusercontent.com.")

        return jsonify(decision="block", reason="Unknown or missing tool field.")
    except Exception as e:
        return jsonify(decision="block", reason=f"Malformed request: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
