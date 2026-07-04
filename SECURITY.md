# Security Policy

Parrot Safety Center is a read-only local dashboard.

## Supported version

| Version | Status |
| --- | --- |
| 1.0.x | Supported |

## Report a security issue

Open a private report or contact CodeWithAmeer through GitHub.

GitHub: https://github.com/CodeWithAmeer

## Safety expectations

The app should not:

- Change system configuration
- Install or remove packages
- Enable or disable firewall rules
- Change AppArmor state
- Create or restore snapshots
- Clear logs
- Use telemetry
- Make online API calls

If you find behavior that violates those expectations, report it immediately.
