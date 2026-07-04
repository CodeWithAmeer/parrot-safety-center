from .common import *
from .redaction import redact_text

FIX_GUIDES = {
    "AppArmor status": {
        "title": "AppArmor inactive",
        "means": "AppArmor is not clearly active from local read-only checks.",
        "matters": "Mandatory access control can limit damage if an application is compromised.",
        "verify": "systemctl status apparmor\naa-status",
        "steps": "Review distribution documentation and enable profiles manually only after confirming compatibility."
    },
    "Firewall status": {
        "title": "No firewall detected",
        "means": "The app did not detect an active ufw, firewalld, or nftables ruleset.",
        "matters": "A host firewall helps reduce exposure from listening services and mistakes.",
        "verify": "ufw status\nnft list ruleset\nsystemctl status firewalld",
        "steps": "Choose one firewall manager, review required services, and apply rules manually using your trusted workflow."
    },
    "Disk encryption status": {
        "title": "Disk encryption not detected",
        "means": "The root storage path did not clearly show LUKS or dm-crypt encryption.",
        "matters": "Lost or stolen devices can expose local data when disk encryption is absent.",
        "verify": "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT\nfindmnt /",
        "steps": "Plan encryption during installation or a tested migration with verified backups."
    },
    "Secure Boot status": {
        "title": "Secure Boot unknown or disabled",
        "means": "Secure Boot was disabled, unknown, or mokutil was unavailable.",
        "matters": "Secure Boot can reduce some boot-chain tampering risks when configured correctly.",
        "verify": "mokutil --sb-state",
        "steps": "Review firmware settings and Parrot/Debian Secure Boot compatibility before changing boot policy."
    },
    "APT automatic update timer status": {
        "title": "APT automatic timers disabled",
        "means": "APT daily timer services were not clearly active or enabled.",
        "matters": "Update reminders and metadata refresh workflows help avoid falling behind on security fixes.",
        "verify": "systemctl status apt-daily.timer\nsystemctl status apt-daily-upgrade.timer",
        "steps": "Decide whether manual or automatic update scheduling fits your workflow and configure it outside this app."
    },
    "SSH service status": {
        "title": "SSH active",
        "means": "An SSH service appears active.",
        "matters": "Remote login increases attack surface if authentication or network exposure is weak.",
        "verify": "systemctl status ssh\nss -tuln",
        "steps": "Confirm SSH is intentional, restrict exposure, and review key-only authentication and access controls."
    },
    "Failed systemd units": {
        "title": "Failed systemd units",
        "means": "One or more systemd units are in a failed state.",
        "matters": "Failed units can indicate broken services, update issues, or disabled security components.",
        "verify": "systemctl --failed\njournalctl -u UNITNAME --no-pager",
        "steps": "Inspect the failed unit logs and resolve the underlying cause before masking or restarting services."
    },
    "Broken package check": {
        "title": "Broken packages",
        "means": "dpkg reported package audit output.",
        "matters": "Broken package states can block updates and security fixes.",
        "verify": "dpkg --audit",
        "steps": "Review package manager output during a maintenance window and use your normal trusted recovery workflow."
    },
    "APT update age": {
        "title": "Old APT metadata",
        "means": "APT metadata appears stale based on local file timestamps.",
        "matters": "Old metadata can hide newer security fixes or show inaccurate package availability.",
        "verify": "stat /var/lib/apt/lists",
        "steps": "Refresh metadata manually with your trusted package manager. This app never runs apt update."
    },
    "Recovery readiness": {
        "title": "No recovery snapshots",
        "means": "No clear Timeshift, Snapper, Btrfs snapshot, or recovery readiness signal was detected.",
        "matters": "A rollback path helps recover from bad updates, driver issues, and lab mistakes.",
        "verify": "timeshift --list\nsnapper list\nfindmnt /",
        "steps": "Choose and test a recovery workflow such as Timeshift, Snapper, Btrfs snapshots, or external backups."
    },
    "Snapshot readiness": {
        "title": "No recovery snapshots",
        "means": "Existing snapshot entries were not clearly detected.",
        "matters": "Snapshots or tested backups reduce recovery time after failures.",
        "verify": "timeshift --list\nsnapper list\nbtrfs subvolume list /",
        "steps": "Create and verify snapshots with trusted tools outside this app."
    },
    "Privacy mode": {
        "title": "No privacy routing signal",
        "means": "Tor, AnonSurf, VPN, or proxy routing was not clearly active.",
        "matters": "Daily networking may expose your provider, DNS path, and local network context.",
        "verify": "systemctl status tor\nip link\nenv | grep -i proxy",
        "steps": "Use privacy routing only when it matches your threat model and verify DNS behavior with tools you trust."
    },
    "Missing tools for selected profile": {
        "title": "Missing tools for selected profile",
        "means": "The selected or detected role has missing suggested tools.",
        "matters": "Missing tools can slow labs or professional workflows, but installing unnecessary tools increases maintenance burden.",
        "verify": "command -v TOOLNAME",
        "steps": "Review missing tools and install only what you need from trusted repositories outside this app."
    }
}

def fix_guide_content(name):
    guide = FIX_GUIDES.get(name)
    if not guide:
        category = "General"
        lower = str(name).lower()
        if any(word in lower for word in ["firewall", "port", "network", "ssh"]):
            category = "Network Exposure"
        elif any(word in lower for word in ["apparmor", "secure boot", "sysctl", "lockdown", "encryption"]):
            category = "Security Hardening"
        elif any(word in lower for word in ["privacy", "vpn", "tor", "anonsurf", "proxy", "dns", "firefox"]):
            category = "Privacy Readiness"
        elif any(word in lower for word in ["snapshot", "recovery", "btrfs", "timeshift", "snapper"]):
            category = "Recovery Readiness"
        elif any(word in lower for word in ["apt", "package", "dpkg", "held", "upgrade"]):
            category = "Updates"
        elif any(word in lower for word in ["journal", "dmesg", "systemd", "failed", "log"]):
            category = "Logs and Stability"
        elif any(word in lower for word in ["tool", "profile", "role"]):
            category = "Tool Readiness"
        fallback_steps = {
            "General": "Review the detected value, compare it with the recommended state, then apply changes manually using trusted system tools. This app never applies fixes automatically.",
            "Security Hardening": "Review the hardening value, verify it with the command shown, then change it manually only if it matches your workflow. This app never applies fixes automatically.",
            "Network Exposure": "Review the exposed service or port, confirm it is intentional, then restrict or disable it manually if it is not needed. This app never applies fixes automatically.",
            "Privacy Readiness": "Review the privacy signal, confirm your threat model, then enable trusted privacy routing manually only when needed. This app never applies fixes automatically.",
            "Recovery Readiness": "Review snapshot and backup readiness, then configure or test recovery manually before risky changes. This app never applies fixes automatically.",
            "Updates": "Review package state and update readiness before running manual package maintenance. This app never applies fixes automatically.",
            "Logs and Stability": "Inspect the related logs first, then resolve the underlying service or kernel issue manually. This app never applies fixes automatically.",
            "Tool Readiness": "Install only the tools you actually need from trusted repositories outside this app. This app never applies fixes automatically."
        }
        guide = {
            "title": name,
            "means": "This item needs review based on local read-only checks.",
            "matters": "Reviewing warnings helps keep the system reliable and ready for your workflow.",
            "verify": "Use the details output in this app and verify manually with trusted system tools.",
            "steps": fallback_steps.get(category, fallback_steps["General"])
        }
    return "What this means\n" + guide["means"] + "\n\nWhy it matters\n" + guide["matters"] + "\n\nHow to verify manually\n" + guide["verify"] + "\n\nSafe next steps\n" + guide["steps"]

def brief_detail(value, limit=180):
    text = redact_text(value).replace("\r", " ").strip()
    if not text:
        return "No additional details were returned by the read-only check."
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    first = lines[0] if lines else text
    if len(lines) > 1:
        first += f"  Details available: {len(lines)} lines."
    if len(first) > limit:
        first = first[:limit - 3].rstrip() + "..."
    return first
