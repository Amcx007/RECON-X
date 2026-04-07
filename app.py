from flask import Flask, render_template, request, send_file, jsonify
import subprocess
import json
import time
import re
import uuid
import os
import socket

app = Flask(__name__)

# ─── Storage Setup ────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR  = os.path.join(BASE_DIR, "results")
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
os.makedirs(RESULTS_DIR, exist_ok=True)

if os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "r") as f:
        scan_history = json.load(f)
else:
    scan_history = []

# ─── Whitelists ───────────────────────────────────────────────────
ALLOWED_TOOLS      = {"nmap", "masscan", "rustscan"}
ALLOWED_SCAN_TYPES = {"fast", "full", "service", "aggressive"}

TOOL_SCAN_TYPES = {
    "nmap":     {"fast", "full", "service", "aggressive"},
    "rustscan": {"fast", "full"},
    "masscan":  {"fast", "full"},
}

TIMEOUT_MAP = {
    "nmap": {
        "fast":       90,
        "full":       900,
        "service":    300,
        "aggressive": 600,
    },
    "rustscan": {
        "fast":  60,
        "full":  300,
    },
    "masscan": {
        "fast":  30,
        "full":  900,
    },
}

UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# ─── Environment ─────────────────────────────────────────────────
RUSTSCAN_CANDIDATES = [
    "/home/kali/.cargo/bin/rustscan",
    "/root/.cargo/bin/rustscan",
    "/usr/local/bin/rustscan",
    "/usr/bin/rustscan",
]

def find_rustscan():
    for path in RUSTSCAN_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    expanded = os.path.expanduser("~/.cargo/bin/rustscan")
    if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
        return expanded
    try:
        env_with_cargo = os.environ.copy()
        for candidate in RUSTSCAN_CANDIDATES:
            candidate_dir = os.path.dirname(candidate)
            if candidate_dir not in env_with_cargo.get("PATH", ""):
                env_with_cargo["PATH"] = candidate_dir + ":" + env_with_cargo.get("PATH", "")
        result = subprocess.run(["which", "rustscan"], capture_output=True, text=True, env=env_with_cargo)
        found = result.stdout.strip()
        if found:
            return found
    except Exception:
        pass
    return "rustscan"

def get_env():
    env = os.environ.copy()
    extra_paths = [os.path.dirname(c) for c in RUSTSCAN_CANDIDATES]
    existing = env.get("PATH", "")
    for p in extra_paths:
        if p not in existing:
            existing = p + ":" + existing
    env["PATH"] = existing
    return env

# ─── Port Risk Map ────────────────────────────────────────────────
PORT_RISK = {
    "21":    ("FTP — unencrypted file transfer",   "high"),
    "22":    ("SSH exposed",                        "medium"),
    "23":    ("Telnet — unencrypted & insecure",    "critical"),
    "25":    ("SMTP mail server",                   "medium"),
    "53":    ("DNS service exposed",                "medium"),
    "80":    ("HTTP — unencrypted web traffic",     "medium"),
    "110":   ("POP3 mail — unencrypted",            "high"),
    "143":   ("IMAP mail — unencrypted",            "high"),
    "443":   ("HTTPS — encrypted web traffic",      "low"),
    "445":   ("SMB — Windows file sharing",         "critical"),
    "3306":  ("MySQL database exposed",             "critical"),
    "3389":  ("RDP — remote desktop exposed",       "high"),
    "5432":  ("PostgreSQL database exposed",        "critical"),
    "5900":  ("VNC remote desktop exposed",         "high"),
    "6379":  ("Redis — no auth by default",         "critical"),
    "8080":  ("HTTP alternate port",                "medium"),
    "8443":  ("HTTPS alternate port",               "low"),
    "27017": ("MongoDB — no auth by default",       "critical"),
}

def analyze_port(port):
    return PORT_RISK.get(str(port), ("Unknown service exposed", "low"))

# ─── Input Validation ─────────────────────────────────────────────
def is_valid_target(target):
    if not target or len(target) > 253:
        return False
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$"
    if re.match(ip_pattern, target):
        ip_part = target.split("/")[0]
        return all(0 <= int(p) <= 255 for p in ip_part.split("."))
    hostname_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9]$"
    return bool(re.match(hostname_pattern, target))

def is_ip(target):
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$", target))

def resolve_to_ip(target):
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    try:
        result = subprocess.run(
            ["nmap", "-sL", "-n", "--resolve-all", target],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", line)
            if match:
                return match.group(1)
    except Exception:
        pass
    try:
        results = socket.getaddrinfo(target, None, socket.AF_INET)
        if results:
            ip = results[0][4][0]
            if ip_re.match(ip):
                return ip
    except socket.gaierror:
        pass
    try:
        result = subprocess.run(["dig", "+short", "+time=3", "+tries=2", target], capture_output=True, text=True, timeout=8)
        for token in result.stdout.split():
            if ip_re.match(token.strip()):
                return token.strip()
    except Exception:
        pass
    try:
        result = subprocess.run(["host", "-t", "A", target], capture_output=True, text=True, timeout=8)
        for token in result.stdout.split():
            if ip_re.match(token.strip()):
                return token.strip()
    except Exception:
        pass
    return None

# ─── Command Builder ──────────────────────────────────────────────
def get_command(tool, scan_type, target):
    if tool == "nmap":
        base = ["nmap", "-n", "-Pn", "--open"]
        if scan_type == "fast":
            return base + ["-F", target]
        elif scan_type == "full":
            return base + ["-p-", "-T4", target]
        elif scan_type == "service":
            return base + ["-sV", "--version-intensity", "5", "--top-ports", "1000", target]
        elif scan_type == "aggressive":
            return base + ["-A", "-T4", target]

    elif tool == "rustscan":
        rustscan_bin = find_rustscan()
        base_rs = [rustscan_bin, "-a", target, "--ulimit", "5000", "--timeout", "1500", "--tries", "1"]
        if scan_type == "fast":
            return base_rs + ["--range", "1-1024", "--", "-n", "-Pn", "--open"]
        elif scan_type == "full":
            return base_rs + ["--", "-sV", "--version-light", "-n", "-Pn", "--open"]

    elif tool == "masscan":
        if scan_type == "fast":
            return ["masscan", target, "-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,8888,27017", "--rate", "5000", "--wait", "3"]
        elif scan_type == "full":
            return ["masscan", target, "-p", "1-65535", "--rate", "1000", "--wait", "5"]

    return ["nmap", "-F", "-n", "-Pn", "--open", target]

# ─── Output Parsers ───────────────────────────────────────────────
def parse_nmap(output):
    ports = []
    port_line_re = re.compile(r"^(\d+)/(tcp|udp)\s+open")
    for line in output.split("\n"):
        line = line.strip()
        if not port_line_re.match(line):
            continue
        parts   = line.split()
        port    = parts[0].split("/")[0]
        service = parts[2] if len(parts) > 2 else "unknown"
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        if not port.isdigit():
            continue
        risk, severity = analyze_port(port)
        ports.append({"port": port, "service": service, "version": version, "risk": risk, "severity": severity})
    return ports

def parse_rustscan(output):
    nmap_results = parse_nmap(output)
    if nmap_results:
        return nmap_results
    ports = []
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Open ") and ":" in line:
            port = line.rsplit(":", 1)[-1].strip()
            if port.isdigit() and 1 <= int(port) <= 65535:
                risk, severity = analyze_port(port)
                ports.append({"port": port, "service": "unknown", "version": "", "risk": risk, "severity": severity})
    return ports

def parse_masscan(output):
    ports = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("Discovered open port"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        port = parts[3].split("/")[0]
        if port.isdigit() and 1 <= int(port) <= 65535:
            risk, severity = analyze_port(port)
            ports.append({"port": port, "service": "unknown", "version": "", "risk": risk, "severity": severity})
    return ports

def parse_output(tool, output):
    if tool == "nmap":       return parse_nmap(output)
    elif tool == "rustscan": return parse_rustscan(output)
    elif tool == "masscan":  return parse_masscan(output)
    return []

# ─── Routes ───────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", history=scan_history)

@app.route("/scan", methods=["POST"])
def scan():
    target    = (request.form.get("target")    or "").strip()
    tool      = (request.form.get("tool")      or "").strip()
    scan_type = (request.form.get("scan_type") or "").strip()

    if not target or not tool or not scan_type:
        return "Missing required fields.", 400
    if tool not in ALLOWED_TOOLS:
        return f"Invalid tool. Allowed: {', '.join(ALLOWED_TOOLS)}", 400
    if scan_type not in ALLOWED_SCAN_TYPES:
        return "Invalid scan type.", 400
    if scan_type not in TOOL_SCAN_TYPES.get(tool, ALLOWED_SCAN_TYPES):
        allowed = ', '.join(sorted(TOOL_SCAN_TYPES[tool]))
        return f"{tool.upper()} only supports: {allowed}.", 400
    if not is_valid_target(target):
        return "Invalid target.", 400

    scan_target = target
    resolved_ip = None
    if tool == "masscan" and not is_ip(target):
        resolved_ip = resolve_to_ip(target)
        if not resolved_ip:
            return f"Masscan requires an IP. '{target}' could not be resolved.", 400
        scan_target = resolved_ip

    command = get_command(tool, scan_type, scan_target)
    timeout = TIMEOUT_MAP.get(tool, {}).get(scan_type, 180)

    try:
        start  = time.time()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=get_env())
        duration = round(time.time() - start, 2)
    except subprocess.TimeoutExpired:
        return f"Scan timed out after {timeout}s.", 408
    except FileNotFoundError:
        return f"Tool '{tool}' was not found.", 500
    except Exception as e:
        return f"Unexpected error: {str(e)}", 500

    output     = result.stdout or ""
    err_output = result.stderr or ""
    full_output = output + ("\n\n--- STDERR ---\n" + err_output if err_output.strip() else "")

    open_ports = parse_output(tool, output + err_output)

    seen, deduped = set(), []
    for p in open_ports:
        if p["port"] not in seen:
            seen.add(p["port"])
            deduped.append(p)
    open_ports = sorted(deduped, key=lambda x: int(x["port"]) if str(x["port"]).isdigit() else 0)

    file_id   = str(uuid.uuid4())
    file_path = os.path.join(RESULTS_DIR, f"{file_id}.json")
    with open(file_path, "w") as f:
        json.dump(open_ports, f, indent=4)

    scan_entry = {
        "target":      target,
        "resolved_ip": resolved_ip,
        "tool":        tool,
        "scan_type":   scan_type,
        "ports":       len(open_ports),
        "duration":    duration,
        "file_id":     file_id,
    }
    scan_history.append(scan_entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(scan_history, f, indent=4)

    return render_template(
        "results.html",
        ports=open_ports,
        raw_output=full_output[:5000],
        history=scan_history,
        target=target,
        resolved_ip=resolved_ip,
        tool=tool,
        scan_type=scan_type,
        duration=duration,
        file_id=file_id,
    )

@app.route("/download/<file_id>")
def download(file_id):
    if not UUID_PATTERN.match(file_id):
        return "Invalid file ID.", 400
    file_path = os.path.join(RESULTS_DIR, f"{file_id}.json")
    if not os.path.exists(file_path):
        return "File not found.", 404
    return send_file(file_path, as_attachment=True, download_name="scan_results.json")

@app.route("/history")
def history():
    return jsonify(scan_history)

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
