# Safety Model

Parrot Safety Center is intentionally read-only.

## Command rules

- Commands run with `shell=False`.
- Every command has a timeout.
- Output is captured and limited.
- Forbidden command patterns are blocked before execution.
- Missing commands are handled as unavailable, not as success.

## Export rules

- Redact before GUI rendering, clipboard operations, and exports.
- Screenshot Safe Mode must hide sensitive identifiers.
- JSON exports must stay valid JSON.
- HTML exports must be self-contained and use no external resources.
