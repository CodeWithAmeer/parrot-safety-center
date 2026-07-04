# Release Checklist

Before publishing a release:

```bash
python3 -m compileall src parrot_safety_center.py
python3 tests/test_static_safety.py
python3 parrot_safety_center.py
```

Manual desktop checks:

- Open every page.
- Refresh checks.
- Toggle Screenshot Safe Mode.
- Export JSON report.
- Export HTML report.
- Export baseline report.
- Export fix plan.
- Export workspace report.
- Export update guard report.
- Copy screenshot-safe summary.
- Confirm no action modifies system state.
