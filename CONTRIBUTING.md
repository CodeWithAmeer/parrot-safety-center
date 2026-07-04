# Contributing

Thank you for helping improve Parrot Safety Center.

## Rules for contributions

- Keep checks read-only.
- Do not add automatic fixes.
- Do not add telemetry.
- Do not add online API calls.
- Do not add commands that modify package, firewall, AppArmor, snapshot, or system state.
- Do not use `shell=True`.
- Use timeouts for every command.
- Redact sensitive data before showing, copying, or exporting it.
- Keep Screenshot Safe Mode working across GUI, clipboard, and exports.

## Local checks

```bash
python3 -m compileall src parrot_safety_center.py
python3 tests/test_static_safety.py
```

## Pull request checklist

- The app starts locally.
- No feature was removed.
- New output is redacted when Screenshot Safe Mode is on.
- JSON exports remain valid JSON.
- HTML exports remain self-contained.
