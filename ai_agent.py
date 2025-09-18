#!/usr/bin/env python3
"""
ai_agent.py
A workshop-ready Linux AI Agent that:
 - sends NL requests to Gemini (Gemini 2.0 Flash)
 - asks LLM to return a structured JSON intent with commands
 - applies safety checks & approval flow
 - executes allowed commands securely, logs everything

Notes:
 - Set environment variable GEMINI_API_KEY before running.
 - This script uses the Google Generative API REST style (generateContent / model-based).
 - See docs (generateContent / Gemini examples) for more integration options. 
"""

import os
import json
import time
import shlex
import logging
import re
import subprocess
from typing import List, Dict, Any, Tuple
import requests
from dotenv import load_dotenv
from string import Template
import platform
from pathlib import Path

# -----------------------------
# Configuration
# -----------------------------
# Load .env if present for convenience
load_dotenv()

API_KEY = os.environ.get("GEMINI_API_KEY")
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")   # as requested
GEN_API_BASE = "https://generativelanguage.googleapis.com/v1beta"  # use official REST base for generateContent
LOGFILE = "agent.log"

# Safety configuration
WHITELIST_COMMAND_PATTERNS = [
    r'^(free|df|uptime|top|htop|ps|uname)\b',          # monitoring
    r'^(systemctl|service)\b',                        # service management
    r'^(dnf|apt|yum|apt-get)\b',                      # package management (install/remove)
    r'^(firewall-cmd|ufw)\b',                         # firewall
    r'^(useradd|usermod|userdel|passwd)\b',           # user management
    r'^(podman|docker)\b',                            # containers
    r'^(cat|tail|less)\b',                            # read files
    r'^(journalctl)\b',                               # logs
    r'^(id|whoami|groups)\b',
]

# Blacklist (dangerous commands / patterns)
BLACKLIST_PATTERNS = [
    r'rm\s+-rf\s+/', r'rm\s+-rf\s+\*\*', r':\s*(){:|:&};:',  # forkbomb
    r'mkfs\b', r'fdisk\b', r'dd\b', r'passwd\s+--stdin', r'shutdown\b', r'reboot\b',
    r'curl\s+.*\|.*sh', r"wget\s+.*\|.*sh",
    r'base64\s+-d', r'openssl\s+.*', r'chmod\s+777\s+/', r'chown\s+.*root:root\s+/',
    r'\bNC\b', r'\bnetcat\b',                                  # optionally block netcat
]

# Commands that require admin approval (example)
CRITICAL_COMMAND_PATTERNS = [
    r'^(userdel|usermod\s+-L|passwd\s+-l|passwd\s+-u|usermod\s+-aG)',
    r'^(dnf|apt|yum).*remove',  # removing packages
    r'^(firewall-cmd).*--remove', # removing firewall rules
    r'^(podman|docker)\s+rm\b',  # removing containers
]

# Logging setup
logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# -----------------------------
# Helper: call the Gemini REST API (generateContent)
# -----------------------------
def call_gemini(prompt: str, temperature: float = 0.0) -> str:
    """
    Call the Gemini generate API. Uses the public endpoint documented by Google.
    Returns the model text response (string).
    """
    if not API_KEY:
        raise RuntimeError("GEMINI_API_KEY environment variable not set")

    url = f"{GEN_API_BASE}/models/{MODEL}:generateContent?key={API_KEY}"
    # Request body per v1beta generateContent
    data = {
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": 512
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "You are a secure Linux automation assistant. Respond ONLY in JSON (no extra text)."},
                    {"text": prompt}
                ]
            }
        ]
    }

    headers = {"Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=data, timeout=30)
    resp.raise_for_status()
    j = resp.json()

    # Extract text from candidates → content → parts
    text = None
    try:
        candidates = j.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            for part in parts:
                if "text" in part:
                    text = part["text"]
                    break
    except Exception:
        pass
    if text is None:
        text = json.dumps(j)
    return text

# -----------------------------
# LLM prompt templates
# -----------------------------
INTENT_PROMPT_TEMPLATE = Template("""
You are a secure Linux automation assistant. The user will give a natural language request.
Produce ONLY a single JSON object with the following keys:
 - "action": short description string
 - "commands": an array of command strings (one shell command each) that, when run on a RHEL/Ubuntu system, accomplish the user's request
 - "requires_approval": boolean, true if this should be confirmed by a human before execution
 - "explain": short explanation of what the commands will do

Constraints:
 - DO NOT include multiple piped constructs in a single command when avoidable; return the final core commands (e.g., 'systemctl restart nginx')
 - For read-only or safe queries (monitoring) set requires_approval=false
 - For destructive commands set requires_approval=true
 - Do NOT include thoughts or any text outside the JSON. If you cannot fulfill, return {"action": "", "commands": [], "requires_approval": false, "explain": "cannot fulfill"}.

User request:
---
$nl_request
---
Respond with JSON only.
""")

# -----------------------------
# Safety checks
# -----------------------------
def matches_any(patterns: List[str], command: str) -> bool:
    for p in patterns:
        if re.search(p, command):
            return True
    return False

def is_safe_command(command: str) -> Tuple[bool, List[str]]:
    """
    Run whitelist/blacklist checks and critical checks.
    Returns (is_safe_overall, reasons[])
    """
    reasons = []
    # blacklist first (absolute deny)
    for p in BLACKLIST_PATTERNS:
        if re.search(p, command):
            reasons.append(f"blacklist match: {p}")
            return False, reasons

    # then whitelist (allow if matches whitelist)
    if matches_any(WHITELIST_COMMAND_PATTERNS, command):
        # check critical patterns
        for p in CRITICAL_COMMAND_PATTERNS:
            if re.search(p, command):
                reasons.append(f"requires approval pattern: {p}")
                return True, reasons  # safe but needs approval
        return True, reasons

    # if not whitelisted, it's potentially unsafe
    reasons.append("not whitelisted")
    return False, reasons

# -----------------------------
# Execute command securely
# -----------------------------
def run_command(command: str, cwd: str = "/", timeout: int = 120) -> Dict[str, Any]:
    """
    Executes the given command (string). We parse with shlex and run with subprocess.run
    to avoid shell=True dangers. Returns {returncode, stdout, stderr, command}
    """
    logging.info(f"Executing: {command}")
    try:
        args = shlex.split(command)
        completed = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        result = {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip()
        }
    except Exception as e:
        result = {"command": command, "returncode": -1, "stdout": "", "stderr": str(e)}
    logging.info(f"Finished: {command} rc={result['returncode']}")
    return result

# -----------------------------
# Approval UI (console-based)
# -----------------------------
def request_approval(human_message: str) -> bool:
    """
    Simple console confirmation. For workshop/demo. In production use
    proper approval workflow (web UI, email, or RBAC approval).
    """
    print("\n===== ACTION REQUIRES APPROVAL =====")
    print(human_message)
    print("Approve? (y/N): ", end="", flush=True)
    ans = input().strip().lower()
    return ans == "y"

# -----------------------------
# Agent main flow
# -----------------------------
def interpret_request(nl: str) -> Dict[str, Any]:
    prompt = INTENT_PROMPT_TEMPLATE.substitute(nl_request=nl)
    logging.info("Sending prompt to LLM for intent extraction")
    llm_text = call_gemini(prompt, temperature=0.0)
    logging.info("LLM returned text: " + (llm_text[:400] if llm_text else "<empty>"))
    # Attempt to parse JSON
    try:
        parsed = json.loads(llm_text)
    except Exception as e:
        logging.error("Failed to parse LLM JSON response: " + str(e))
        # fallback: try to extract JSON substring
        m = re.search(r'\{.*\}', llm_text, re.S)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except Exception as e2:
                logging.error("Fallback JSON parse failed: " + str(e2))
                parsed = {"action": "", "commands": [], "requires_approval": False, "explain": "parse error"}
        else:
            parsed = {"action": "", "commands": [], "requires_approval": False, "explain": "no json found"}
    return parsed

def handle_request(nl: str):
    start = time.time()
    logging.info(f"User request: {nl}")
    parsed = interpret_request(nl)
    logging.info("Parsed intent: " + json.dumps(parsed))

    # Validate shape
    commands = parsed.get("commands", []) or []
    requires_approval_flag = parsed.get("requires_approval", False)

    executed_results = []
    # Detect package manager based on OS
    def detect_package_manager() -> str:
        try:
            os_release = {}
            path = "/etc/os-release"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            os_release[k] = v.strip('"')
            os_id = (os_release.get("ID") or "").lower()
            id_like = (os_release.get("ID_LIKE") or "").lower()
            if any(x in (os_id + " " + id_like) for x in ["rhel", "fedora", "centos", "rocky", "almalinux"]):
                return "dnf"
            if any(x in (os_id + " " + id_like) for x in ["debian", "ubuntu", "linuxmint"]):
                return "apt"
        except Exception:
            pass
        # Fallbacks by existence
        if shutil.which("dnf"):
            return "dnf"
        if shutil.which("apt"):
            return "apt"
        if shutil.which("yum"):
            return "yum"
        return "unknown"

    def normalize_pkg_command(command: str, pkg_mgr: str) -> str:
        c = command
        # Map apt/apt-get to dnf when needed
        if pkg_mgr == "dnf":
            c = re.sub(r'^apt-get\s+update\b', 'dnf -y makecache', c)
            c = re.sub(r'^apt\s+update\b', 'dnf -y makecache', c)
            c = re.sub(r'^apt-get\s+install\b', 'dnf install', c)
            c = re.sub(r'^apt\s+install\b', 'dnf install', c)
            c = re.sub(r'^apt-get\s+purge\b', 'dnf remove', c)
            c = re.sub(r'^apt\s+purge\b', 'dnf remove', c)
            c = re.sub(r'^apt-get\s+remove\b', 'dnf remove', c)
            c = re.sub(r'^apt\s+remove\b', 'dnf remove', c)
            c = re.sub(r'^apt-get\s+upgrade\b', 'dnf upgrade', c)
            c = re.sub(r'^apt\s+upgrade\b', 'dnf upgrade', c)
            c = re.sub(r'^apt-get\s+autoremove\b', 'dnf autoremove', c)
            c = re.sub(r'^apt\s+autoremove\b', 'dnf autoremove', c)
            # Convert yum to dnf
            c = re.sub(r'^yum\b', 'dnf', c)
        elif pkg_mgr in ("apt", "unknown"):
            # Normalize apt-get to apt
            c = re.sub(r'^apt-get\b', 'apt', c)
        return c

    import shutil  # local import to avoid top clutter
    pkg_mgr = detect_package_manager()

    for cmd in commands:
        # Normalize command: drop pipes and adapt per OS
        original_cmd = cmd
        # Enforce no pipes: take only the first segment
        if '|' in cmd:
            cmd = cmd.split('|', 1)[0].strip()

        # Platform-specific fixes
        system_name = platform.system()
        if system_name == 'Darwin':
            # macOS 'top' uses -l <samples>
            cmd = re.sub(r"^top\s+-b?n?1\b", "top -l 1", cmd)
            cmd = re.sub(r"^top\s+-b\s+-n\s*1\b", "top -l 1", cmd)

        # Package manager normalization
        cmd_after_top = cmd
        cmd = normalize_pkg_command(cmd, pkg_mgr)

        if cmd != original_cmd:
            logging.info(f"Normalized command from '{original_cmd}' to '{cmd}' for safety/compatibility")
        safe, reasons = is_safe_command(cmd)
        if not safe:
            logging.warning(f"Blocked unsafe command: {cmd} reasons: {reasons}")
            executed_results.append({"command": cmd, "status": "blocked", "reasons": reasons})
            continue

        # If flagged as needing approval by either LLM or pattern
        needs_human = requires_approval_flag or any(re.search(p, cmd) for p in CRITICAL_COMMAND_PATTERNS)
        if needs_human:
            human_message = f"About to run: {cmd}\nExplanation: {parsed.get('explain','')}\nReasons: {reasons}"
            approved = request_approval(human_message)
            if not approved:
                logging.info("Human denied approval for command: " + cmd)
                executed_results.append({"command": cmd, "status": "denied_by_human"})
                continue

        # Execute command
        res = run_command(cmd)
        executed_results.append({"command": cmd, "status": "executed", "result": res})

    # Audit log entry
    audit = {
        "timestamp": int(time.time()),
        "request": nl,
        "parsed_intent": parsed,
        "executed_results": executed_results,
        "duration_seconds": time.time() - start
    }
    logging.info("AUDIT: " + json.dumps(audit))
    return audit

# -----------------------------
# Demo / CLI
# -----------------------------
def main():
    print("Linux AI Agent (demo). Type 'exit' to quit.")
    while True:
        try:
            nl = input("\nEnter command (natural language): ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        if not nl:
            continue
        if nl.lower() in ("exit", "quit"):
            break
        try:
            audit = handle_request(nl)
            print("\n== Audit summary ==")
            print(json.dumps(audit, indent=2))
        except Exception as e:
            logging.exception("Error handling request: " + str(e))
            print("Error: ", e)

if __name__ == "__main__":
    main()


