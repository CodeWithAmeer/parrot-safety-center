# Architecture

The project was split from one standalone file into focused modules under `src/parrot_safety_center`.

## Module guide

- `common.py`: imports, constants, palette, output limits, denylist patterns
- `redaction.py`: normal and screenshot-safe redaction
- `guides.py`: fix guide text and fallback guidance
- `models.py`: dataclasses
- `runner.py`: safe command execution wrapper
- `checks.py`: system checks, scoring, baseline, role data, reports data
- `workers.py`: background refresh worker
- `widgets.py`: reusable UI widgets
- `pages.py`: dashboard pages
- `main_window.py`: main window, page wiring, actions, exports, tray
- `app.py`: application entrypoint

## Maintenance rules

Keep system logic out of UI pages when possible. New checks should be added to `checks.py`, rendered by pages, and exported by the existing report paths.
