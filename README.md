# Linux AI Agent for Automation

Minimal workshop-ready Linux AI Agent that sends natural language requests to Gemini 2.0 Flash, extracts a structured JSON intent, applies safety checks and optional approval, then executes allowed commands with full logging.

## Clone

```bash
git clone https://github.com/auspicious27/Linux-AI-Aagent-Automation.git
cd Linux-AI-Aagent-Automation
```

## Setup

1) Python 3.9+
2) Create a virtualenv and install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) Export your API key (or copy `.env.example` to `.env` and export manually):

```bash
export GEMINI_API_KEY=your_key_here
```

## Run

```bash
python ai_agent.py
```

Type a natural language request like "show disk usage".

## Notes

- All executions are logged to `agent.log`.
- The agent uses a whitelist/blacklist for safety and may ask for approval for critical actions.
- Tested on macOS and Linux; commands are targeted to RHEL/Ubuntu systems.

## Example prompts to try

Copy-paste any of these after you start the agent.

- Monitoring (no approval expected):
  - "show disk usage"
  - "check cpu and memory usage"
  - "what kernel version is this machine running?"

- Services (may ask approval to restart/stop):
  - "restart nginx"
  - "check status of ssh service"

- Packages (approval expected for changes):
  - "install htop"
  - "remove nginx"

- Logs and files (read-only):
  - "show the last 50 lines of the system journal"
  - "show the last 100 lines of /var/log/syslog"

- Users (approval expected for sensitive ops):
  - "add user demo and set a password"
  - "lock the user account alice"

- Containers (approval expected for destructive ops):
  - "list docker containers"
  - "remove container named web"

Tip: If something is blocked as "not whitelisted", rephrase as a standard admin command (service, package, firewall, user, docker, logs, read-only file).

## Linux prompts cheat-sheet (basics)

- System info
  - "show OS version and kernel"
  - "show uptime and load average"
  - "list logged-in users"

- Disk, memory, CPU
  - "show disk usage with mount points"
  - "show memory usage"
  - "top 10 processes by CPU"

- Networking
  - "show IP addresses and interfaces"
  - "ping 8.8.8.8"
  - "show open ports"

- Services
  - "check status of sshd"
  - "restart chronyd service"
  - "enable nginx to start on boot"

- Packages (auto-maps apt/yum to dnf on RHEL)
  - "install curl"
  - "remove nginx"
  - "upgrade all packages"

- Users and groups (approval expected)
  - "create user demo"
  - "add demo to wheel group"
  - "lock user demo"

- Firewall
  - "show firewall rules"
  - "open tcp port 8080"
  - "close tcp port 8080"

- Logs and troubleshooting
  - "tail last 100 lines of system journal"
  - "show sshd logs for today"
  - "check last reboot reason"

- Files (read-only)
  - "show last 50 lines of /var/log/messages"
  - "print /etc/os-release"

- Containers (Docker/Podman)
  - "list running containers"
  - "show logs of container web"
  - "restart container web"

Note: Destructive actions may trigger approval. On RHEL, the agent converts Debian-style commands (apt) into dnf equivalents and can auto-enable EPEL when needed.
