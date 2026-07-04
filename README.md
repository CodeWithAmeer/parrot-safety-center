# Parrot Safety Center

Unofficial project for Parrot OS.

Created by CodeWithAmeer.
GitHub: https://github.com/CodeWithAmeer
License: Apache-2.0

Parrot Safety Center is a read-only local desktop dashboard that helps review system health, security hardening, privacy readiness, recovery readiness, update risk, logs, tools, and role fit from one place.

## Status

Version: 1.0.0

This project is ready for public use and continued development. It is not an official Parrot OS component.

## Core principles

- Read-only local checks
- No telemetry
- No online API calls
- No network requests
- No automatic fixes
- No system modification
- No root required to open
- No package installation from inside the app
- No firewall changes from inside the app
- No AppArmor changes from inside the app
- No snapshot or rollback actions from inside the app

All fix guidance is shown as manual text only.

## Features

- Overview safety dashboard
- System health score
- Security score
- Privacy score
- Recovery score
- Tools readiness score
- Updates score
- Parrot baseline compliance score
- Role-aware scoring
- Fix Plan page
- Update Guard page
- Workspaces page
- Timeline page
- Logs page
- Recommendations page
- Reports page
- Screenshot Safe Mode
- JSON, HTML, text, baseline, fix plan, workspace, update guard, logs, and tool readiness exports
- System tray menu

## Project layout

```text
parrot-safety-center/
  parrot_safety_center.py          # compatibility launcher
  src/parrot_safety_center/
    app.py                         # application entrypoint
    common.py                      # shared imports and constants
    redaction.py                   # redaction and output limiting
    guides.py                      # fix guide text
    models.py                      # dataclasses
    runner.py                      # safe read-only command runner
    checks.py                      # system checks and scoring data
    workers.py                     # background worker objects
    widgets.py                     # shared UI widgets
    pages.py                       # application pages
    main_window.py                 # main window and export actions
  docs/
  tests/
```

## Requirements

- Linux desktop environment
- Python 3.10 or newer
- PySide6

Tested target: Parrot OS.
Also designed to work where possible on Debian, Kali, and Ubuntu.

## Install for development

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

## Run from source

```bash
python3 parrot_safety_center.py
```

Or:

```bash
PYTHONPATH=src python3 -m parrot_safety_center
```

## Build package

```bash
python3 -m pip install build
python3 -m build
```

## Safety model

The app uses a guarded command runner. Commands are executed with `shell=False`, strict timeouts, and output limits. Dangerous command patterns are blocked before execution.

Examples of blocked patterns include package modifications, firewall modifications, snapshot creation or rollback, dmesg clearing, `sudo`, and `pkexec`.

## Screenshot Safe Mode

Screenshot Safe Mode is enabled by default. It redacts sensitive details such as usernames, hostnames, home paths, IP addresses, DNS server IPs, MAC addresses, interface names, repository URLs, proxy values, UUIDs, device IDs, tokens, passwords, and secrets.

## Contributing

See `CONTRIBUTING.md`.

## Security

See `SECURITY.md`.
