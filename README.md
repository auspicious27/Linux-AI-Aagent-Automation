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
