from .common import *
from .models import CommandResult, CheckDefinition, NormalizedCheckResult
from .runner import CommandRunner
from .redaction import *
from .guides import *

class SystemChecks:
    tool_map = {
        "nmap": {"bins": ["nmap"], "category": "Red Team"},
        "wireshark": {"bins": ["wireshark", "tshark"], "category": "DFIR"},
        "burpsuite": {"bins": ["burpsuite", "burp"], "category": "Web"},
        "metasploit-framework": {"bins": ["msfconsole"], "category": "Red Team"},
        "sqlmap": {"bins": ["sqlmap"], "category": "Web"},
        "gobuster": {"bins": ["gobuster"], "category": "Web"},
        "ffuf": {"bins": ["ffuf"], "category": "Web"},
        "hydra": {"bins": ["hydra"], "category": "Red Team"},
        "john": {"bins": ["john"], "category": "Red Team"},
        "hashcat": {"bins": ["hashcat"], "category": "Red Team"},
        "aircrack-ng": {"bins": ["aircrack-ng"], "category": "Red Team"},
        "nikto": {"bins": ["nikto"], "category": "Web"},
        "wpscan": {"bins": ["wpscan"], "category": "Web"},
        "dirsearch": {"bins": ["dirsearch"], "category": "Web"},
        "masscan": {"bins": ["masscan"], "category": "Red Team"},
        "amass": {"bins": ["amass"], "category": "Red Team"},
        "theharvester": {"bins": ["theHarvester", "theharvester"], "category": "Red Team"},
        "ghidra": {"bins": ["ghidra", "ghidraRun"], "category": "Reverse Engineering"},
        "radare2": {"bins": ["radare2", "r2"], "category": "Reverse Engineering"},
        "rizin": {"bins": ["rizin", "rz-bin"], "category": "Reverse Engineering"},
        "gdb": {"bins": ["gdb"], "category": "Reverse Engineering"},
        "strace": {"bins": ["strace"], "category": "Reverse Engineering"},
        "ltrace": {"bins": ["ltrace"], "category": "Reverse Engineering"},
        "binwalk": {"bins": ["binwalk"], "category": "DFIR"},
        "foremost": {"bins": ["foremost"], "category": "DFIR"},
        "volatility3": {"bins": ["volatility3", "vol"], "category": "DFIR"},
        "autopsy": {"bins": ["autopsy"], "category": "DFIR"},
        "yara": {"bins": ["yara"], "category": "DFIR"},
        "clamav": {"bins": ["clamscan", "clamdscan"], "category": "System"},
        "docker": {"bins": ["docker"], "category": "Cloud"},
        "podman": {"bins": ["podman"], "category": "Cloud"},
        "kubectl": {"bins": ["kubectl"], "category": "Cloud"},
        "helm": {"bins": ["helm"], "category": "Cloud"},
        "terraform": {"bins": ["terraform"], "category": "Cloud"},
        "ansible": {"bins": ["ansible"], "category": "Cloud"},
        "python3": {"bins": ["python3"], "category": "Developer"},
        "pipx": {"bins": ["pipx"], "category": "Developer"},
        "git": {"bins": ["git"], "category": "Developer"},
        "code": {"bins": ["code", "codium"], "category": "Developer"},
        "vim": {"bins": ["vim"], "category": "Developer"},
        "nvim": {"bins": ["nvim"], "category": "Developer"},
        "tor": {"bins": ["tor", "torbrowser-launcher"], "category": "Privacy"},
        "anonsurf": {"bins": ["anonsurf"], "category": "Privacy"},
        "openvpn": {"bins": ["openvpn"], "category": "Privacy"},
        "wireguard-tools": {"bins": ["wg", "wg-quick"], "category": "Privacy"},
        "proxychains4": {"bins": ["proxychains4", "proxychains"], "category": "Privacy"},
        "firefox": {"bins": ["firefox", "firefox-esr"], "category": "Privacy"}
    }

    profiles = {
        "Daily User": {"purpose": "Balanced safety and system awareness for everyday Parrot OS use.", "tools": ["python3", "git", "vim", "nmap", "clamav"], "next": "Keep packages current, review firewall posture, and configure recovery."},
        "Privacy Mode": {"purpose": "Privacy-focused desktop use with Tor, VPN, DNS, and proxy awareness.", "tools": ["tor", "anonsurf", "openvpn", "wireguard-tools", "proxychains4", "firefox"], "next": "Confirm VPN, Tor, proxy, and DNS behavior before sensitive browsing sessions."},
        "Developer Workstation": {"purpose": "Software development, scripting, containers, automation, and source control.", "tools": ["python3", "pipx", "git", "code", "vim", "nvim", "docker", "podman", "ansible"], "next": "Use isolated environments and keep dependency tooling patched."},
        "Web Pentesting": {"purpose": "Web application testing, directory discovery, proxy testing, and common assessment workflows.", "tools": ["burpsuite", "sqlmap", "gobuster", "ffuf", "nikto", "wpscan", "dirsearch", "nmap"], "next": "Validate authorization scope and keep engagement evidence organized."},
        "Red Team": {"purpose": "Offensive security labs and authorized adversary simulation readiness.", "tools": ["nmap", "metasploit-framework", "hydra", "john", "hashcat", "amass", "theharvester", "masscan"], "next": "Separate lab networks from daily use and document permissions."},
        "Cloud Security": {"purpose": "Cloud-native administration, infrastructure as code, and Kubernetes security practice.", "tools": ["docker", "podman", "kubectl", "helm", "terraform", "ansible", "python3", "git"], "next": "Review local kubeconfig handling and cloud credential storage."},
        "Malware Analysis and Reverse Engineering": {"purpose": "Reverse engineering and static or dynamic malware analysis lab readiness.", "tools": ["ghidra", "radare2", "rizin", "gdb", "strace", "ltrace", "binwalk", "yara", "python3"], "next": "Use isolated lab VMs and avoid analyzing samples on the daily desktop."},
        "DFIR and Blue Team": {"purpose": "Incident response, forensic triage, artifact review, and defensive diagnostics.", "tools": ["wireshark", "binwalk", "foremost", "volatility3", "autopsy", "yara", "clamav", "python3"], "next": "Prepare external evidence storage and confirm time synchronization."},
        "Automation Security Research": {"purpose": "Security research workflows around automation, code review, data handling, and reproducible experiments.", "tools": ["python3", "pipx", "git", "docker", "podman", "vim", "nvim", "code"], "next": "Isolate experiments and keep datasets out of shell histories."}
    }

    def __init__(self):
        self.runner = CommandRunner()
        self.selected_role = None

    def safe_text(self, value, fallback="Unknown"):
        if value is None:
            return fallback
        text = redact_text(str(value).strip())
        return text if text else fallback

    def read_file(self, path, max_chars=20000):
        try:
            p = Path(path)
            if not p.exists():
                return ""
            return safe_limit_text(p.read_text(errors="replace")[:max_chars], max_chars)
        except PermissionError:
            return "Permission denied"
        except Exception as exc:
            return redact_text(str(exc))

    def human_bytes(self, value):
        try:
            num = float(value)
        except Exception:
            return "Unknown"
        for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
            if abs(num) < 1024.0:
                return f"{num:.1f} {unit}"
            num /= 1024.0
        return f"{num:.1f} EB"

    def command_text(self, result, fallback="No output"):
        if not result.available:
            return "Not installed"
        if result.timed_out:
            return "Command timed out"
        if result.stdout:
            return safe_limit_text(result.stdout, REPORT_FIELD_LIMIT)
        if result.stderr:
            return safe_limit_text(result.stderr, REPORT_FIELD_LIMIT)
        if result.error:
            return safe_limit_text(result.error, REPORT_FIELD_LIMIT)
        return safe_limit_text(fallback, 50000)

    def os_release(self):
        data = {}
        text = self.read_file("/etc/os-release")
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        pretty = data.get("PRETTY_NAME") or data.get("NAME") or "Unknown"
        return pretty, data

    def cpu_name(self):
        text = self.read_file("/proc/cpuinfo")
        for line in text.splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
        value = platform.processor()
        return value if value else "Unknown"

    def ram_summary(self):
        text = self.read_file("/proc/meminfo")
        info = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    info[parts[0].rstrip(":")] = int(parts[1])
                except Exception:
                    pass
        total = info.get("MemTotal")
        available = info.get("MemAvailable")
        if not total:
            return "Unknown"
        used = total - available if available else 0
        percent = used / total * 100 if total else 0
        return f"{self.human_bytes(used * 1024)} used / {self.human_bytes(total * 1024)} total ({percent:.0f}%)"

    def disk_usage(self):
        try:
            usage = shutil.disk_usage("/")
            percent = usage.used / usage.total * 100 if usage.total else 0
            return {"used": usage.used, "free": usage.free, "total": usage.total, "percent": percent, "summary": f"{self.human_bytes(usage.used)} used / {self.human_bytes(usage.total)} total ({percent:.0f}%)"}
        except Exception:
            return {"used": 0, "free": 0, "total": 0, "percent": 0, "summary": "Unknown"}

    def uptime_summary(self):
        text = self.read_file("/proc/uptime", 200)
        try:
            seconds = int(float(text.split()[0]))
            days, rem = divmod(seconds, 86400)
            hours, rem = divmod(rem, 3600)
            minutes, _ = divmod(rem, 60)
            parts = []
            if days:
                parts.append(f"{days}d")
            if hours:
                parts.append(f"{hours}h")
            parts.append(f"{minutes}m")
            return " ".join(parts)
        except Exception:
            return "Unknown"

    def desktop_environment(self):
        return os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or os.environ.get("GDMSESSION") or "Unknown"

    def systemctl_state(self, unit):
        result = self.runner.run(["systemctl", "is-active", unit], timeout=4)
        if not result.available:
            return "Unknown"
        return self.safe_text(result.stdout or result.stderr or result.error, "unknown")

    def systemctl_enabled(self, unit):
        result = self.runner.run(["systemctl", "is-enabled", unit], timeout=4)
        if not result.available:
            return "Unknown"
        return self.safe_text(result.stdout or result.stderr or result.error, "unknown")

    def service_check(self, label, units):
        details = []
        found = False
        active = False
        for unit in units:
            state = self.systemctl_state(unit)
            enabled = self.systemctl_enabled(unit)
            if state != "Unknown" or enabled != "Unknown":
                found = True
            details.append(f"{unit}: active={state}, enabled={enabled}")
            if state == "active":
                active = True
        if not found:
            return "Not installed", "No matching systemd unit detected", "info"
        if active:
            return "Active", "\n".join(details), "good"
        return "Inactive", "\n".join(details), "warn"

    def apparmor_status(self):
        state = self.systemctl_state("apparmor")
        aa = self.runner.run(["aa-status"], timeout=6)
        detail = self.command_text(aa, f"systemctl apparmor: {state}")
        low = detail.lower()
        if state == "active" or "profiles are loaded" in low or "apparmor module is loaded" in low:
            return "Active", detail, "good"
        if state in ["inactive", "failed"]:
            return state.capitalize(), detail, "bad"
        return "Unknown", detail, "warn"

    def firewall_status(self):
        sources = []
        active_detected = False
        rules_detected = False
        inactive_detected = False
        unclear_detected = False
        tool_detected = False
        ufw = self.runner.run(["ufw", "status"], timeout=6)
        if ufw.available:
            tool_detected = True
            text = self.command_text(ufw)
            sources.append("ufw: " + text)
            low = text.lower()
            if "status: active" in low:
                active_detected = True
            elif "status: inactive" in low:
                inactive_detected = True
            else:
                unclear_detected = True
        firewalld_state = self.systemctl_state("firewalld")
        if firewalld_state != "Unknown":
            tool_detected = True
            sources.append(f"firewalld: {firewalld_state}")
            if firewalld_state == "active":
                active_detected = True
            elif firewalld_state in ["inactive", "failed"]:
                inactive_detected = True
            else:
                unclear_detected = True
        nft = self.runner.run(["nft", "list", "ruleset"], timeout=7)
        if nft.available:
            tool_detected = True
            nft_text = self.command_text(nft)
            has_rules = bool(nft.stdout.strip())
            sources.append("nftables: ruleset detected" if has_rules else "nftables: no ruleset output")
            if has_rules:
                rules_detected = True
            elif nft.code not in [0, 1] and (nft.stderr or nft.error):
                unclear_detected = True
        if active_detected:
            return "Active", "\n\n".join(sources), "good"
        if rules_detected:
            return "Rules detected", "\n\n".join(sources), "good"
        if inactive_detected:
            return "Inactive", "\n\n".join(sources), "bad"
        if tool_detected and unclear_detected:
            return "Unknown", "\n\n".join(sources), "warn"
        return "No active firewall detected", "\n\n".join(sources) if sources else "No ufw, firewalld, or nftables ruleset signal was detected.", "bad"

    def disk_encryption_status(self):
        result = self.runner.run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "-P"], timeout=6)
        text = self.command_text(result)
        low = text.lower()
        crypt_detected = "type=\"crypt\"" in low or "fstype=\"crypto_luks\"" in low or "crypto_luks" in low
        root_crypt = any("MOUNTPOINT=\"/\"" in line and ("TYPE=\"crypt\"" in line or "crypto_luks" in line.lower()) for line in text.splitlines())
        if crypt_detected:
            return "Detected", text, "good" if root_crypt else "warn"
        if result.available:
            return "Not detected", text, "bad"
        return "Unknown", text, "warn"

    def secure_boot_status(self):
        result = self.runner.run(["mokutil", "--sb-state"], timeout=5)
        text = self.command_text(result)
        low = text.lower()
        if not result.available:
            return "Unknown", "mokutil is not installed", "warn"
        if "enabled" in low:
            return "Enabled", text, "good"
        if "disabled" in low:
            return "Disabled", text, "warn"
        return "Unknown", text, "warn"

    def apt_timer_status(self):
        units = ["apt-daily.timer", "apt-daily-upgrade.timer"]
        details = []
        good = False
        bad = True
        for unit in units:
            state = self.systemctl_state(unit)
            enabled = self.systemctl_enabled(unit)
            details.append(f"{unit}: active={state}, enabled={enabled}")
            if state == "active" or enabled in ["enabled", "static"]:
                good = True
                bad = False
        if good:
            return "Configured", "\n".join(details), "good"
        if bad:
            return "Not enabled", "\n".join(details), "warn"
        return "Unknown", "\n".join(details), "warn"

    def dns_resolver_info(self):
        status = self.runner.first_output([["resolvectl", "dns"], ["systemd-resolve", "--status"]], timeout=5)
        if status and status.available and status.stdout:
            lines = []
            for line in status.stdout.splitlines():
                if len(lines) < 80:
                    lines.append(line)
            return "Detected", "\n".join(lines), "good"
        text = self.read_file("/etc/resolv.conf", 6000)
        entries = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("nameserver") or stripped.startswith("search") or stripped.startswith("options"):
                entries.append(stripped)
        if entries:
            return "Detected", "\n".join(entries), "good"
        if text == "Permission denied":
            return "Unknown", text, "warn"
        return "Unknown", "No DNS resolver details detected", "warn"

    def sudo_status(self):
        exists = self.runner.exists("sudo")
        details = ["sudo binary: installed" if exists else "sudo binary: not installed"]
        label = "Available" if exists else "Not installed"
        severity = "good" if exists else "warn"
        try:
            user = getpass.getuser()
            groups = []
            for group in grp.getgrall():
                if user in group.gr_mem:
                    groups.append(group.gr_name)
            primary_group = grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name
            if primary_group not in groups:
                groups.append(primary_group)
            details.append("current user groups: " + ", ".join(sorted(set(groups))))
            if "sudo" in groups or "wheel" in groups:
                details.append("current user appears to be in a sudo-capable group")
            else:
                details.append("current user is not in common sudo-capable groups")
        except Exception as exc:
            details.append(redact_text(str(exc)))
        return label, "\n".join(details), severity

    def ssh_status(self):
        states = []
        active = False
        detected = False
        for unit in ["ssh", "sshd", "ssh.service", "sshd.service"]:
            state = self.systemctl_state(unit)
            enabled = self.systemctl_enabled(unit)
            if state != "Unknown" or enabled != "Unknown":
                detected = True
            states.append(f"{unit}: active={state}, enabled={enabled}")
            if state == "active":
                active = True
        if active:
            return "Active", "\n".join(states), "bad"
        if detected:
            return "Inactive", "\n".join(states), "good"
        return "Unknown", "No SSH systemd unit detected", "info"

    def failed_units(self):
        result = self.runner.run(["systemctl", "--failed", "--no-pager", "--plain"], timeout=7)
        text = self.command_text(result)
        if not result.available:
            return "Unknown", text, "warn", []
        failed = []
        for line in text.splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.lower().startswith("unit ") or "loaded units listed" in cleaned.lower() or cleaned.startswith("0 loaded"):
                continue
            if ".service" in cleaned or ".timer" in cleaned or ".mount" in cleaned or ".socket" in cleaned:
                failed.append(cleaned)
        if failed:
            return str(len(failed)), "\n".join(failed[:80]), "bad", failed
        return "0", "No failed systemd units reported", "good", []

    def open_ports(self):
        result = self.runner.first_output([["ss", "-tulpen"], ["ss", "-tuln"], ["netstat", "-tuln"]], timeout=7)
        text = self.command_text(result)
        if not result or not result.available:
            return "Unknown", text, "warn", []
        rows = []
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("netid") or low.startswith("proto") or not line.strip():
                continue
            if "listen" in low or "udp" in low:
                rows.append(line.strip())
        label = str(len(rows))
        severity = "good" if len(rows) <= 8 else "warn"
        return label, "\n".join(rows[:80]) if rows else "No listening ports detected by available command", severity, rows

    def running_network_services(self):
        result = self.runner.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], timeout=8)
        text = self.command_text(result)
        if not result.available:
            return "Unknown", text, "warn", []
        keywords = ["ssh", "nginx", "apache", "http", "ftp", "smb", "nmb", "rpc", "docker", "podman", "postgres", "mysql", "mariadb", "redis", "tor", "openvpn", "wireguard", "vpn", "cups", "avahi"]
        rows = []
        for line in text.splitlines():
            low = line.lower()
            if any(k in low for k in keywords):
                rows.append(line.strip())
        severity = "warn" if rows else "good"
        return str(len(rows)), "\n".join(rows[:80]) if rows else "No common network-exposed services matched the safe filter", severity, rows

    def kernel_lockdown(self):
        text = self.read_file("/sys/kernel/security/lockdown", 1000)
        if not text:
            return "Unknown", "Kernel lockdown status is not exposed on this system", "info"
        low = text.lower()
        if "[none]" in low or low.strip() == "none":
            return "None", text, "warn"
        if "[integrity]" in low or "[confidentiality]" in low:
            return "Enabled", text, "good"
        return "Unknown", text, "info"

    def sysctl_hardening(self):
        checks = {
            "kernel.dmesg_restrict": {"good": ["1"], "why": "limits dmesg access"},
            "kernel.kptr_restrict": {"good": ["1", "2"], "why": "hides kernel pointer details"},
            "kernel.yama.ptrace_scope": {"good": ["1", "2", "3"], "why": "limits process tracing"},
            "net.ipv4.ip_forward": {"good": ["0"], "why": "avoids unintended routing"},
            "net.ipv4.conf.all.rp_filter": {"good": ["1", "2"], "why": "helps reject spoofed traffic"}
        }
        rows = []
        good = 0
        detected = 0
        for key, meta in checks.items():
            result = self.runner.run(["sysctl", "-n", key], timeout=3)
            value = self.safe_text(result.stdout or result.stderr or result.error, "Unknown") if result.available else "Unknown"
            status = "OK" if value in meta["good"] else "Review"
            severity = "good" if status == "OK" else "warn"
            if value != "Unknown":
                detected += 1
            if status == "OK":
                good += 1
            rows.append({"key": key, "value": value, "status": status, "severity": severity, "why": meta["why"]})
        if detected == 0:
            return "Unknown", "sysctl values could not be detected", "warn", rows
        score = int(good / len(checks) * 100)
        label = f"{good}/{len(checks)} OK"
        severity = "good" if score >= 80 else "warn" if score >= 50 else "bad"
        detail = "\n".join([f"{row['key']}={row['value']} ({row['status']})" for row in rows])
        return label, detail, severity, rows

    def package_service_status(self, name, units, binary=None):
        installed = self.runner.exists(binary or name)
        unit_details = []
        active = False
        found_unit = False
        for unit in units:
            state = self.systemctl_state(unit)
            enabled = self.systemctl_enabled(unit)
            if state != "Unknown" or enabled != "Unknown":
                found_unit = True
            if state == "active":
                active = True
            unit_details.append(f"{unit}: active={state}, enabled={enabled}")
        if active:
            return "Active", "installed=" + str(installed) + "\n" + "\n".join(unit_details), "good"
        if installed or found_unit:
            return "Installed", "installed=" + str(installed) + "\n" + "\n".join(unit_details), "warn"
        return "Not installed", "No installed binary or systemd unit detected", "info"

    def security_summary(self):
        failed_label, failed_detail, failed_sev, failed_rows = self.failed_units()
        ports_label, ports_detail, ports_sev, ports_rows = self.open_ports()
        services_label, services_detail, services_sev, services_rows = self.running_network_services()
        sysctl_label, sysctl_detail, sysctl_sev, sysctl_rows = self.sysctl_hardening()
        data = {
            "AppArmor status": self.apparmor_status(),
            "Firewall status": self.firewall_status(),
            "Disk encryption status": self.disk_encryption_status(),
            "Secure Boot status": self.secure_boot_status(),
            "APT automatic update timer status": self.apt_timer_status(),
            "DNS resolver information": self.dns_resolver_info(),
            "Sudo basic status": self.sudo_status(),
            "SSH service status": self.ssh_status(),
            "Failed systemd units": (failed_label, failed_detail, failed_sev),
            "Open listening ports": (ports_label, ports_detail, ports_sev),
            "Running network services": (services_label, services_detail, services_sev),
            "USBGuard status": self.package_service_status("usbguard", ["usbguard.service"], "usbguard"),
            "Fail2ban status": self.package_service_status("fail2ban", ["fail2ban.service"], "fail2ban-client"),
            "ClamAV status": self.package_service_status("clamav", ["clamav-daemon.service", "clamav-freshclam.service"], "clamscan"),
            "Kernel lockdown status": self.kernel_lockdown(),
            "Sysctl hardening checks": (sysctl_label, sysctl_detail, sysctl_sev)
        }
        data["_structured"] = {"failed_units": failed_rows, "open_ports": ports_rows, "network_services": services_rows, "sysctl": sysctl_rows}
        return redact_data(data)

    def anonsurf_status(self):
        installed = self.runner.exists("anonsurf")
        state = self.systemctl_state("anonsurf")
        result = self.runner.run(["anonsurf", "status"], timeout=6) if installed else CommandResult("anonsurf status", False, 127, "", "", False, "anonsurf is not installed")
        detail = self.command_text(result, f"systemctl anonsurf: {state}")
        if state == "active" or "active" in detail.lower() or "enabled" in detail.lower():
            return "Active", detail, "good"
        if installed:
            return "Installed", detail, "warn"
        return "Not installed", "AnonSurf command was not detected", "info"

    def tor_status(self):
        units = ["tor", "tor@default", "tor.service"]
        details = []
        active = False
        installed = self.runner.exists("tor")
        for unit in units:
            state = self.systemctl_state(unit)
            enabled = self.systemctl_enabled(unit)
            details.append(f"{unit}: active={state}, enabled={enabled}")
            if state == "active":
                active = True
        if active:
            return "Active", "\n".join(details), "good"
        if installed:
            return "Installed", "\n".join(details), "warn"
        return "Not installed", "Tor service and command were not detected", "info"

    def proxy_env(self):
        keys = ["http_proxy", "https_proxy", "ftp_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY"]
        rows = []
        for key in keys:
            value = os.environ.get(key)
            if value:
                rows.append(f"{key}={redact_text(value)}")
        if rows:
            return "Configured", "\n".join(rows), "good"
        return "Not set", "No proxy environment variables detected for the current process", "info"

    def networkmanager_status(self):
        state = self.systemctl_state("NetworkManager")
        enabled = self.systemctl_enabled("NetworkManager")
        if state == "active":
            return "Active", f"NetworkManager: active={state}, enabled={enabled}", "good"
        if state in ["inactive", "failed"]:
            return state.capitalize(), f"NetworkManager: active={state}, enabled={enabled}", "warn"
        return "Unknown", f"NetworkManager: active={state}, enabled={enabled}", "info"

    def vpn_interfaces(self):
        result = self.runner.first_output([["ip", "-brief", "addr"], ["ip", "addr"]], timeout=6)
        text = self.command_text(result)
        if not result.available:
            return "Unknown", text, "warn", []
        names = []
        details = []
        patterns = ["tun", "wg", "proton", "mullvad", "openvpn", "wireguard"]
        for line in text.splitlines():
            low = line.lower()
            first = line.split()[0].strip(":") if line.split() else ""
            if any(p in low for p in patterns):
                names.append(first)
                details.append(line.strip())
        if names:
            return "Detected", "\n".join(details), "good", names
        return "Not detected", "No tun, wg, proton, mullvad, openvpn, or wireguard interface detected", "warn", []

    def firefox_privacy(self):
        home = Path.home()
        firefox_dir = home / ".mozilla" / "firefox"
        profiles_ini = firefox_dir / "profiles.ini"
        if not profiles_ini.exists():
            return "Not detected", "No Firefox profiles.ini found for the current user", "info"
        profiles = []
        settings_hits = []
        try:
            text = profiles_ini.read_text(errors="replace")
            for line in text.splitlines():
                if line.startswith("Path="):
                    rel = line.split("=", 1)[1].strip()
                    profile_path = firefox_dir / rel
                    profiles.append(rel)
                    prefs = profile_path / "prefs.js"
                    if prefs.exists():
                        ptxt = prefs.read_text(errors="replace")[:50000]
                        for needle in ["privacy.resistFingerprinting", "network.trr.mode", "media.peerconnection.enabled", "dom.security.https_only_mode"]:
                            if needle in ptxt:
                                settings_hits.append(needle)
        except PermissionError:
            return "Unknown", "Permission denied while reading Firefox profile metadata", "warn"
        except Exception as exc:
            return "Unknown", redact_text(str(exc)), "warn"
        details = [f"Profiles detected: {len(profiles)}"]
        if settings_hits:
            details.append("Privacy-related settings found: " + ", ".join(sorted(set(settings_hits))))
            return "Detected", "\n".join(details), "good"
        return "Detected", "\n".join(details) + "\nNo common privacy-related Firefox prefs were detected by the safe local scan", "warn"

    def dns_leak_risk(self, dns_detail, vpn_label, tor_label, proxy_label):
        low = dns_detail.lower()
        real_signal = vpn_label == "Detected" or tor_label == "Active" or proxy_label == "Configured"
        public = any(x in low for x in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67."])
        local = any(x in low for x in ["127.0.0.", "::1", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."])
        if real_signal:
            return "Lower", "A privacy routing signal is active. Still confirm DNS behavior with tools you trust before sensitive work.", "good"
        if public:
            return "Review", "Public DNS resolver detected without VPN, Tor, proxy, or AnonSurf signal. This may be acceptable but is not a strong privacy signal.", "warn"
        if local:
            return "Review", "Local resolver detected without VPN, Tor, proxy, or AnonSurf signal. DNS may follow the current network provider.", "warn"
        return "Unknown", "DNS details are limited and no privacy routing signal is active.", "warn"

    def privacy_summary(self):
        anon = self.anonsurf_status()
        tor = self.tor_status()
        proxy = self.proxy_env()
        dns = self.dns_resolver_info()
        nm = self.networkmanager_status()
        vpn_label, vpn_detail, vpn_sev, vpn_names = self.vpn_interfaces()
        firefox = self.firefox_privacy()
        dns_risk = self.dns_leak_risk(dns[1], vpn_label, tor[0], proxy[0])
        signals = []
        if anon[0] == "Active":
            signals.append("AnonSurf")
        if tor[0] == "Active":
            signals.append("Tor")
        if proxy[0] == "Configured":
            signals.append("Proxy")
        if vpn_label == "Detected":
            signals.append("VPN interface")
        if signals:
            privacy_mode = ("Active", "Privacy routing signals detected: " + ", ".join(signals), "good")
        else:
            privacy_mode = ("Not active", "No VPN, Tor, AnonSurf, or proxy routing signal detected. This is normal for daily use but not a strong privacy mode.", "warn")
        data = {
            "AnonSurf status": anon,
            "Tor service status": tor,
            "Proxy environment variables": proxy,
            "DNS resolver": dns,
            "NetworkManager status": nm,
            "VPN interface detection": (vpn_label, vpn_detail, vpn_sev),
            "VPN interface details": (", ".join(vpn_names) if vpn_names else "None", vpn_detail, vpn_sev),
            "Firefox privacy detection": firefox,
            "DNS leak risk": dns_risk,
            "WebRTC warning note": ("Review", "Browsers may expose local network details through WebRTC unless browser settings or extensions control it. This app does not change browser settings.", "info"),
            "Privacy mode": privacy_mode,
            "Clipboard-safe privacy report": ("Available", "Use Copy Privacy Report to copy a redacted privacy-only summary.", "good")
        }
        return redact_data(data)

    def filesystem_type(self):
        result = self.runner.run(["findmnt", "-n", "-o", "FSTYPE,SOURCE,TARGET", "/"], timeout=5)
        text = self.command_text(result)
        if result.available and result.stdout:
            fs = result.stdout.split()[0] if result.stdout.split() else "Unknown"
            return fs, text, "good" if fs != "Unknown" else "warn"
        lsblk = self.runner.run(["lsblk", "-f"], timeout=5)
        text = self.command_text(lsblk)
        if "btrfs" in text.lower():
            return "btrfs", text, "good"
        return "Unknown", text, "warn"

    def btrfs_status(self):
        fs, detail, sev = self.filesystem_type()
        if fs.lower() == "btrfs" or "btrfs" in detail.lower():
            subvol = self.runner.run(["btrfs", "subvolume", "list", "/"], timeout=8)
            subvol_text = self.command_text(subvol, "No subvolume output")
            return "Detected", detail + "\n" + subvol_text, "good"
        return "Not detected", detail, "warn"

    def timeshift_status(self):
        installed = self.runner.exists("timeshift")
        if not installed:
            return "Not installed", "timeshift command was not detected", "info"
        result = self.runner.run(["timeshift", "--list"], timeout=10)
        text = self.command_text(result)
        if result.stdout and any(ch.isdigit() for ch in result.stdout):
            return "Installed", text, "good"
        return "Installed", text, "warn"

    def snapper_status(self):
        installed = self.runner.exists("snapper")
        if not installed:
            return "Not installed", "snapper command was not detected", "info"
        result = self.runner.run(["snapper", "list"], timeout=10)
        text = self.command_text(result)
        if result.stdout and len(result.stdout.splitlines()) > 2:
            return "Installed", text, "good"
        return "Installed", text, "warn"

    def snapshot_count(self, timeshift, snapper, btrfs):
        count = 0
        detail = []
        for name, item in [("Timeshift", timeshift), ("Snapper", snapper), ("Btrfs", btrfs)]:
            text = item[1]
            if item[0] in ["Installed", "Detected"] and any(ch.isdigit() for ch in text):
                lines = [line for line in text.splitlines() if line.strip()]
                detected = max(0, len(lines) - 1)
                count += detected
                detail.append(f"{name}: snapshot-like entries detected")
            else:
                detail.append(f"{name}: no snapshot entries detected")
        if count > 0:
            return "Detected", "\n".join(detail), "good"
        return "None detected", "\n".join(detail), "warn"

    def recovery_summary(self):
        fs = self.filesystem_type()
        btrfs = self.btrfs_status()
        timeshift = self.timeshift_status()
        snapper = self.snapper_status()
        snapshots = self.snapshot_count(timeshift, snapper, btrfs)
        disk = self.disk_usage()
        free_sev = "good" if disk["free"] >= 20 * 1024 * 1024 * 1024 else "warn"
        tool_ready = timeshift[0] == "Installed" or snapper[0] == "Installed" or btrfs[0] == "Detected"
        has_snapshots = snapshots[0] == "Detected"
        if tool_ready and has_snapshots:
            ready = ("Ready", "Snapshot tooling and snapshot-like entries were detected.", "good")
        elif tool_ready:
            ready = ("Partially ready", "Snapshot tooling or Btrfs was detected, but existing snapshots were not clearly detected.", "warn")
        else:
            ready = ("Not configured", "No Timeshift, Snapper, or Btrfs snapshot readiness signal detected.", "bad")
        setup = []
        if timeshift[0] != "Installed" and snapper[0] != "Installed":
            setup.append("Choose a snapshot workflow such as Timeshift or Snapper based on your filesystem and backup strategy.")
        if btrfs[0] != "Detected":
            setup.append("For Btrfs rollback workflows, use a Btrfs root filesystem designed for snapshots.")
        if disk["free"] < 20 * 1024 * 1024 * 1024:
            setup.append("Free additional root partition space before relying on local snapshots.")
        if not setup:
            setup.append("Confirm snapshot retention and test recovery in a safe maintenance window.")
        return redact_data({
            "Filesystem type": (fs[0], fs[1], fs[2]),
            "Root partition free space": (self.human_bytes(disk["free"]), disk["summary"], free_sev),
            "Timeshift installation": timeshift,
            "Snapper installation": snapper,
            "Btrfs filesystem": btrfs,
            "Existing snapshots": snapshots,
            "Snapshot readiness": ready,
            "Snapshot tool readiness": ("Ready" if tool_ready else "Not ready", "Timeshift, Snapper, or Btrfs signal is required for this MVP readiness check.", "good" if tool_ready else "bad"),
            "Btrfs readiness": ("Ready" if btrfs[0] == "Detected" else "Not ready", btrfs[1], "good" if btrfs[0] == "Detected" else "warn"),
            "Timeshift readiness": ("Ready" if timeshift[0] == "Installed" else "Not ready", timeshift[1], "good" if timeshift[0] == "Installed" else "warn"),
            "Snapper readiness": ("Ready" if snapper[0] == "Installed" else "Not ready", snapper[1], "good" if snapper[0] == "Installed" else "warn"),
            "Recovery readiness": ready,
            "Suggested recovery setup steps": ("Review", "\n".join(setup), "info")
        })

    def apt_update_age(self):
        candidates = [Path("/var/lib/apt/lists"), Path("/var/cache/apt/pkgcache.bin"), Path("/var/cache/apt/srcpkgcache.bin")]
        times = []
        for candidate in candidates:
            try:
                if candidate.exists():
                    if candidate.is_dir():
                        for child in candidate.iterdir():
                            try:
                                if child.is_file() and not child.name.endswith("lock"):
                                    times.append(child.stat().st_mtime)
                            except Exception:
                                pass
                    else:
                        times.append(candidate.stat().st_mtime)
            except PermissionError:
                return "Unknown", "Permission denied while checking APT metadata", "warn", None
            except Exception:
                pass
        if not times:
            return "Unknown", "APT metadata files were not detected", "warn", None
        latest = max(times)
        age_hours = max(0.0, (time.time() - latest) / 3600)
        age_days = max(0.0, age_hours / 24)
        stamp = datetime.fromtimestamp(latest).isoformat(timespec="seconds")
        label = "Less than 1 day" if age_days < 1 else f"{age_days:.1f} days"
        detail = f"Latest APT metadata timestamp: {stamp}"
        if age_days <= 2:
            return label, detail, "good", age_days
        if age_days <= 14:
            return label, detail, "warn", age_days
        return label, detail, "bad", age_days

    def upgradeable_packages(self):
        result = self.runner.run(["apt", "list", "--upgradable"], timeout=25)
        text = self.command_text(result)
        if not result.available:
            return "Unknown", text, "warn", None
        count = 0
        rows = []
        for line in text.splitlines():
            if not line.strip() or line.lower().startswith("listing"):
                continue
            if "/" in line:
                count += 1
                if len(rows) < 120:
                    rows.append(line.strip())
        severity = "good" if count == 0 else "warn" if count <= 20 else "bad"
        return str(count), "\n".join(rows) if rows else "No upgradeable packages reported", severity, count

    def broken_packages(self):
        result = self.runner.run(["dpkg", "--audit"], timeout=10)
        text = self.command_text(result, "No output")
        if not result.available:
            return "Unknown", text, "warn", None
        if text == "No output" or not result.stdout.strip():
            return "0", "dpkg --audit reported no broken packages", "good", 0
        items = [line for line in text.splitlines() if line.strip()]
        return str(len(items)), text, "bad", len(items)

    def held_packages(self):
        result = self.runner.run(["apt-mark", "showhold"], timeout=8)
        text = self.command_text(result, "No held packages reported")
        if not result.available:
            return "Unknown", text, "warn", None
        rows = [line.strip() for line in text.splitlines() if line.strip()]
        if not rows:
            return "0", "No held packages reported", "good", 0
        return str(len(rows)), "\n".join(rows), "warn", len(rows)

    def apt_sources(self):
        paths = [Path("/etc/apt/sources.list")]
        d = Path("/etc/apt/sources.list.d")
        try:
            if d.exists():
                paths.extend(sorted(d.glob("*.list")))
                paths.extend(sorted(d.glob("*.sources")))
        except Exception:
            pass
        chunks = []
        readable = 0
        enabled = 0
        for path in paths:
            try:
                if path.exists() and path.is_file():
                    readable += 1
                    text = safe_limit_text(path.read_text(errors="replace"), 12000)
                    active_lines = []
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            active_lines.append(redact_text(stripped))
                    enabled += len(active_lines)
                    if active_lines:
                        chunks.append(str(path) + "\n" + "\n".join(active_lines[:80]))
            except PermissionError:
                chunks.append(str(path) + "\nPermission denied")
            except Exception as exc:
                chunks.append(str(path) + "\n" + redact_text(str(exc)))
        if enabled > 0:
            return f"{enabled} active entries", safe_limit_text("\n\n".join(chunks), 50000), "good", enabled
        if readable > 0:
            return "No active entries", "APT source files were readable but no active source entries were detected", "warn", 0
        return "Unknown", "APT source files were not detected", "warn", None

    def updates_summary(self):
        age_label, age_detail, age_sev, age_days = self.apt_update_age()
        upgrades_label, upgrades_detail, upgrades_sev, upgrades_count = self.upgradeable_packages()
        broken_label, broken_detail, broken_sev, broken_count = self.broken_packages()
        held_label, held_detail, held_sev, held_count = self.held_packages()
        sources_label, sources_detail, sources_sev, sources_count = self.apt_sources()
        if broken_count and broken_count > 0:
            source_health = ("Needs attention", "Broken packages should be reviewed before normal upgrades.", "bad")
        elif sources_count == 0:
            source_health = ("Needs review", "No active APT source entries were detected.", "warn")
        elif age_days is not None and age_days > 14:
            source_health = ("Stale metadata", "APT metadata appears older than 14 days. This app does not run apt update.", "bad")
        else:
            source_health = ("Usable", "APT sources and metadata are detectable by read-only checks.", "good")
        if upgrades_count is None:
            rec = ("Unknown", "Upgradeable package count could not be detected.", "warn")
        elif upgrades_count == 0:
            rec = ("Good", "No upgradeable packages were reported by apt list --upgradable.", "good")
        elif upgrades_count <= 20:
            rec = ("Review updates", "Review available package upgrades during a normal maintenance window.", "warn")
        else:
            rec = ("Update soon", "A high number of upgrades may indicate a stale or behind system. Review updates carefully.", "bad")
        return redact_data({
            "APT update age": (age_label, age_detail, age_sev),
            "Upgradeable package count": (upgrades_label, upgrades_detail, upgrades_sev),
            "Broken package check": (broken_label, broken_detail, broken_sev),
            "Held packages": (held_label, held_detail, held_sev),
            "APT repository sources": (sources_label, sources_detail, sources_sev),
            "APT source health summary": source_health,
            "Held packages count": (held_label, held_detail, held_sev),
            "Broken packages count": (broken_label, broken_detail, broken_sev),
            "Last APT metadata update": (age_label, age_detail, age_sev),
            "Security recommendation text": rec,
            "_structured": {"age_days": age_days, "upgradeable_count": upgrades_count, "broken_count": broken_count, "held_count": held_count, "sources_count": sources_count}
        })

    def detect_tools(self):
        rows = []
        installed = []
        for tool, meta in self.tool_map.items():
            found_path = ""
            found_bin = ""
            for binary in meta["bins"]:
                path = shutil.which(binary)
                if path:
                    found_path = path
                    found_bin = binary
                    break
            status = "Installed" if found_path else "Not installed"
            if found_path:
                installed.append(tool)
            rows.append({"tool": tool, "category": meta["category"], "status": status, "binary": found_bin, "path": found_path})
        return rows, installed

    def privacy_signal_score(self, privacy):
        if not isinstance(privacy, dict):
            return 0, []
        signals = []
        def status(name):
            item = privacy.get(name, ("Unknown", "", "warn"))
            return item[0] if isinstance(item, (list, tuple)) and item else "Unknown"
        if status("Tor service status") in ["Active", "Installed"]:
            signals.append("Tor " + status("Tor service status"))
        if status("AnonSurf status") in ["Active", "Installed"]:
            signals.append("AnonSurf " + status("AnonSurf status"))
        if status("VPN interface detection") == "Detected":
            signals.append("VPN interface detected")
        if status("Proxy environment variables") == "Configured":
            signals.append("Proxy configured")
        firefox = status("Firefox privacy detection")
        if firefox in ["Detected", "Review"]:
            signals.append("Firefox privacy profile hints")
        dns = privacy.get("DNS leak risk", ("Unknown", "", "warn"))
        if isinstance(dns, (list, tuple)) and len(dns) >= 3 and dns[2] == "good":
            signals.append("DNS risk lower")
        score = 0
        for signal in signals:
            if signal.startswith("Tor Active") or signal.startswith("AnonSurf Active") or signal.startswith("VPN"):
                score += 28
            elif signal.startswith("Proxy"):
                score += 18
            elif signal.startswith("Tor Installed") or signal.startswith("AnonSurf Installed"):
                score += 14
            elif signal.startswith("Firefox"):
                score += 10
            elif signal.startswith("DNS"):
                score += 12
        return clamp_score(score), signals

    def profile_status(self, installed, privacy=None, preferred_role=None):
        installed_set = set(installed)
        rows = []
        privacy_score, privacy_signals = self.privacy_signal_score(privacy or {})
        for name, meta in self.profiles.items():
            tools = meta["tools"]
            detected = [tool for tool in tools if tool in installed_set]
            missing = [tool for tool in tools if tool not in installed_set]
            readiness = int(round((len(detected) / len(tools)) * 100)) if tools else 0
            signal_note = "Installed tool overlap"
            if name == "Privacy Mode":
                readiness = privacy_score
                signal_note = "Privacy readiness is based on Tor, AnonSurf, VPN, proxy, DNS, and Firefox privacy signals"
            if name == "Automation Security Research":
                has_python = "python3" in installed_set
                dev_count = len([t for t in ["python3", "pipx", "git", "code", "vim", "nvim"] if t in installed_set])
                container_count = len([t for t in ["docker", "podman"] if t in installed_set])
                readiness = clamp_score((dev_count / 6) * 55 + min(container_count, 1) * 25 + (20 if has_python else 0))
            rows.append({"name": name, "purpose": meta["purpose"], "tools": tools, "detected": detected, "missing": missing, "readiness": readiness, "next_step": meta["next"], "signal_note": signal_note, "privacy_signals": privacy_signals if name == "Privacy Mode" else []})
        def key(row):
            preferred_bonus = 1 if preferred_role and row["name"] == preferred_role else 0
            specialized_bonus = 0 if row["name"] == "Daily User" else 1
            return (-preferred_bonus, -row["readiness"], -len(row["detected"]), -specialized_bonus, row["name"])
        rows.sort(key=key)
        return rows

    def active_profile(self, installed, privacy=None, preferred_role=None):
        rows = self.profile_status(installed, privacy, preferred_role)
        if not rows:
            return {"name": "Unknown", "readiness": 0, "why": "No profile data available", "detected": [], "missing": []}
        if preferred_role:
            chosen = next((row for row in rows if row["name"] == preferred_role), None)
            if chosen:
                reason = "Selected role: " + preferred_role + ". " + chosen.get("signal_note", "Readiness based on detected local signals")
                if chosen["name"] == "Privacy Mode" and chosen.get("privacy_signals"):
                    reason += ": " + ", ".join(chosen["privacy_signals"])
                elif chosen.get("detected"):
                    reason += ": " + ", ".join(chosen.get("detected", []))
                return {"name": chosen["name"], "readiness": chosen["readiness"], "why": reason, "detected": chosen["detected"], "missing": chosen["missing"]}
        viable = []
        for row in rows:
            if row["name"] == "Daily User":
                viable.append((row["readiness"] - 8, row))
            elif row["name"] == "Privacy Mode":
                required = row.get("readiness", 0) >= 35 or bool(row.get("privacy_signals"))
                if required:
                    viable.append((row["readiness"] + 3, row))
            elif len(row.get("detected", [])) >= 2 or row.get("readiness", 0) >= 35:
                viable.append((row["readiness"], row))
        if not viable:
            best = next((row for row in rows if row["name"] == "Daily User"), rows[0])
        else:
            viable.sort(key=lambda x: (-x[0], -len(x[1].get("detected", [])), x[1]["name"]))
            best = viable[0][1]
        if best["name"] == "Privacy Mode":
            reason = "Selected from real privacy signals: " + (", ".join(best.get("privacy_signals", [])) if best.get("privacy_signals") else "privacy tools or settings partially detected")
        else:
            reason = "Selected from installed role tool overlap: " + (", ".join(best["detected"]) if best["detected"] else "no tracked tools matched strongly")
        return {"name": best["name"], "readiness": best["readiness"], "why": reason, "detected": best["detected"], "missing": best["missing"]}

    def logs_summary(self):
        failed = self.runner.run(["systemctl", "--failed", "--no-pager", "--plain"], timeout=8)
        journal = self.runner.run(["journalctl", "-p", "3", "-n", "80", "--no-pager"], timeout=10)
        dmesg = self.runner.first_output([["dmesg", "--level=err,warn", "--ctime"], ["dmesg"]], timeout=10)
        return redact_data({
            "systemctl failed units": safe_limit_text(self.command_text(failed), GUI_FIELD_LIMIT),
            "journalctl priority errors": safe_limit_text(limit_lines(self.command_text(journal), MAX_JOURNAL_LINES), GUI_FIELD_LIMIT),
            "dmesg errors": safe_limit_text(limit_lines(self.command_text(dmesg), MAX_DMESG_LINES), GUI_FIELD_LIMIT),
            "summary": "Diagnostics are redacted and read-only. Permission-denied outputs are normal on hardened systems."
        })

    def score_from_checks(self, items, weights=None):
        total = 0
        possible = 0
        weights = weights or {}
        for key, value in items.items():
            if key.startswith("_"):
                continue
            weight = weights.get(key, 1)
            possible += weight
            sev = value[2] if isinstance(value, (tuple, list)) and len(value) >= 3 else "info"
            if sev == "good":
                total += weight
            elif sev == "info":
                total += weight * 0.75
            elif sev == "warn":
                total += weight * 0.45
            elif sev == "bad":
                total += 0
        return clamp_score((total / possible * 100) if possible else 0)

    def score_weights_for_role(self, role):
        weights = {"system": 0.25, "security": 0.30, "privacy": 0.10, "recovery": 0.12, "tools": 0.10, "updates": 0.13}
        if role == "Privacy Mode":
            weights = {"system": 0.18, "security": 0.24, "privacy": 0.30, "recovery": 0.08, "tools": 0.08, "updates": 0.12}
        elif role == "Developer Workstation":
            weights = {"system": 0.24, "security": 0.22, "privacy": 0.08, "recovery": 0.10, "tools": 0.18, "updates": 0.18}
        elif role in ["Web Pentesting", "Red Team", "Cloud Security", "DFIR and Blue Team", "Malware Analysis and Reverse Engineering", "Automation Security Research", "HTB and CTF Lab"]:
            weights = {"system": 0.22, "security": 0.28, "privacy": 0.08, "recovery": 0.10, "tools": 0.18, "updates": 0.14}
        return weights

    def score_weight_summary(self, weights):
        return ", ".join(f"{key} {int(value * 100)}%" for key, value in weights.items())

    def compute_scores(self, security, privacy, recovery, updates, active_profile, selected_role=None):
        updates_struct = updates.get("_structured", {}) if isinstance(updates, dict) else {}
        failed = security.get("Failed systemd units", ("Unknown", "", "warn"))[2]
        broken_count = updates_struct.get("broken_count")
        age_days = updates_struct.get("age_days")
        upgradeable = updates_struct.get("upgradeable_count")
        system_points = 100
        if failed == "bad":
            system_points -= 35
        if broken_count and broken_count > 0:
            system_points -= 35
        if age_days is not None and age_days > 14:
            system_points -= 20
        elif age_days is not None and age_days > 2:
            system_points -= 10
        disk_percent = self.disk_usage().get("percent", 0)
        if disk_percent > 90:
            system_points -= 20
        elif disk_percent > 80:
            system_points -= 10
        if upgradeable and upgradeable > 80:
            system_points -= 15
        system_health = clamp_score(system_points)
        security_weights = {
            "AppArmor status": 2,
            "Firewall status": 2,
            "Disk encryption status": 2,
            "SSH service status": 2,
            "Sysctl hardening checks": 2,
            "Failed systemd units": 2,
            "Open listening ports": 1,
            "Secure Boot status": 1,
            "APT automatic update timer status": 1
        }
        security_score = self.score_from_checks(security, security_weights)
        privacy_weights = {"Privacy mode": 3, "VPN interface detection": 2, "Tor service status": 1, "AnonSurf status": 1, "Proxy environment variables": 1, "DNS leak risk": 2, "Firefox privacy detection": 1}
        privacy_score = self.score_from_checks(privacy, privacy_weights)
        recovery_weights = {"Recovery readiness": 3, "Snapshot readiness": 2, "Snapshot tool readiness": 2, "Root partition free space": 1, "Btrfs filesystem": 1, "Timeshift installation": 1, "Snapper installation": 1}
        recovery_score = self.score_from_checks(recovery, recovery_weights)
        tools_score = clamp_score(active_profile.get("readiness", 0))
        update_score = self.score_from_checks(updates, {"Upgradeable package count": 2, "Broken package check": 3, "APT update age": 2, "APT source health summary": 2})
        detected_role = active_profile.get("name", "Unknown") or "Unknown"
        selected_label = selected_role or "Auto-detect"
        scoring_profile = selected_role or detected_role
        weights = self.score_weights_for_role(scoring_profile)
        safety = clamp_score(system_health * weights["system"] + security_score * weights["security"] + privacy_score * weights["privacy"] + recovery_score * weights["recovery"] + tools_score * weights["tools"] + update_score * weights["updates"])
        weight_summary = self.score_weight_summary(weights)
        explanation = f"Scoring profile: {scoring_profile}. Weights: {weight_summary}."
        breakdown = {"System Health": system_health, "Security": security_score, "Privacy": privacy_score, "Recovery": recovery_score, "Tools": tools_score, "Updates": update_score}
        negatives = []
        positives = []
        for name, score in breakdown.items():
            if score < 50:
                negatives.append(f"{name} score is low at {score}/100")
            elif score >= 80:
                positives.append(f"{name} score is strong at {score}/100")
        if failed == "bad":
            negatives.append("Failed systemd units are present")
        if broken_count and broken_count > 0:
            negatives.append("Broken packages were detected")
        if upgradeable and upgradeable > 0:
            negatives.append(f"{upgradeable} upgradeable packages reported")
        if age_days is not None and age_days <= 2:
            positives.append("APT metadata appears recent")
        if security.get("Firewall status", ("", "", "warn"))[2] == "good":
            positives.append("Firewall signal detected")
        if security.get("AppArmor status", ("", "", "warn"))[2] == "good":
            positives.append("AppArmor signal detected")
        if recovery.get("Recovery readiness", ("", "", "warn"))[2] == "bad":
            negatives.append("Recovery workflow is not configured")
        if privacy.get("Privacy mode", ("", "", "warn"))[2] != "good" and scoring_profile == "Privacy Mode":
            negatives.append("Privacy Mode is the scoring profile but no strong routing signal is active")
        if not positives:
            positives.append("The score uses read-only local checks and separates categories to avoid over-penalizing one area")
        if not negatives:
            negatives.append("No major negative factor was detected by the current read-only checks")
        return {"Safety Score": safety, "System Health Score": system_health, "Security Score": security_score, "Privacy Score": privacy_score, "Recovery Score": recovery_score, "Tools Readiness Score": tools_score, "Updates Score": update_score, "Score Explanation": explanation, "Score Breakdown": breakdown, "Top Negative Factors": negatives[:8], "Top Positive Factors": positives[:8], "Selected Role": selected_label, "Detected Role": detected_role, "Scoring Profile": scoring_profile, "Score Weights": weights, "Score Weight Summary": weight_summary}

    def scoring_profile_name(self, scores=None, active=None):
        if isinstance(scores, dict) and scores.get("Scoring Profile"):
            return scores.get("Scoring Profile")
        if self.selected_role:
            return self.selected_role
        if isinstance(active, dict) and active.get("name"):
            return active.get("name")
        return "Daily User"

    def privacy_priority(self, issue_key, scores=None):
        role = self.scoring_profile_name(scores)
        privacy_focused = role == "Privacy Mode"
        if privacy_focused:
            if issue_key in {"privacy_routing_missing", "vpn_missing", "dns_review"}:
                return "High"
            return "Medium"
        if role == "Web Pentesting":
            if issue_key == "dns_review":
                return "Medium"
            return "Low"
        if role == "Daily User":
            if issue_key in {"dns_review", "firefox_privacy_review"}:
                return "Medium"
            return "Low"
        if issue_key in {"privacy_routing_missing", "vpn_missing", "proxy_missing", "tor_inactive", "anonsurf_inactive"}:
            return "Low"
        return "Medium"

    def make_recommendations(self, security, privacy, recovery, updates, profiles, tools, scores):
        recs = []
        def add(priority, category, problem, why, step, guide_key=None, issue_key=None):
            recs.append({"priority": priority, "category": category, "problem": problem, "why": why, "safe_next_step": step, "guide_key": guide_key or problem, "issue_key": issue_key or self.fix_item_key(problem, guide_key or problem, category)})
        failed = security.get("Failed systemd units", ("Unknown", "", "warn"))
        if failed[2] == "bad":
            add("Critical", "System Health", "Failed systemd units detected", "Failed services can indicate broken desktop components, security services, or update failures.", "Review the failed unit names and inspect their logs before changing configuration. This app never applies fixes automatically.", "Failed systemd units", "failed_systemd_units")
        broken = updates.get("Broken package check", ("Unknown", "", "warn"))
        if broken[2] == "bad":
            add("Critical", "Updates", "Broken packages detected", "Broken package states can block security updates and make system behavior unreliable.", "Review dpkg audit output and resolve package state during a maintenance window. This app never applies fixes automatically.", "Broken package check", "broken_packages")
        apparmor = security.get("AppArmor status", ("Unknown", "", "warn"))
        if apparmor[2] == "bad":
            add("High", "Security", "AppArmor is inactive", "Mandatory access control helps reduce damage from compromised applications.", "Review AppArmor service status and distribution documentation before enabling policies. This app never applies fixes automatically.", "AppArmor status", "apparmor_inactive")
        firewall = security.get("Firewall status", ("Unknown", "", "warn"))
        if firewall[2] == "bad":
            add("High", "Security", "No active firewall was detected", "A host firewall reduces exposure from local services and misconfiguration.", "Review the firewall state, confirm required local services, then apply a trusted host-firewall policy manually. This app never applies fixes automatically.", "Firewall status", "firewall_missing")
        ssh = security.get("SSH service status", ("Unknown", "", "info"))
        if ssh[0] == "Active":
            add("High", "Security", "SSH service is active", "Remote login increases attack surface if passwords, keys, or network exposure are weak.", "Confirm SSH is intentionally enabled, restrict access, and review authentication policy. This app never applies fixes automatically.", "SSH service status", "ssh_active")
        enc = security.get("Disk encryption status", ("Unknown", "", "warn"))
        if enc[0] == "Not detected":
            add("High", "Security", "Disk encryption was not detected", "Lost or stolen devices can expose local data without full-disk encryption.", "Plan encryption during installation or a carefully tested migration with verified backups. This app never applies fixes automatically.", "Disk encryption status", "disk_encryption_missing")
        upgrades = updates.get("Upgradeable package count", ("Unknown", "", "warn"))
        try:
            upgrades_count = int(upgrades[0])
        except Exception:
            upgrades_count = None
        if upgrades_count and upgrades_count > 0:
            add("Medium" if upgrades_count <= 20 else "High", "Updates", f"{upgrades_count} upgradeable packages", "Missing updates may include security fixes or important stability patches.", "Review package upgrades using your normal package manager after checking rollback readiness. This app never applies fixes automatically.", "Upgradeable package count", "missing_updates")
        age = updates.get("APT update age", ("Unknown", "", "warn"))
        if age[2] == "bad":
            add("High", "Updates", "APT metadata appears very old", "Old metadata can hide available security updates or show stale package information.", "Review package state and update readiness before running manual package maintenance. This app never applies fixes automatically.", "APT update age", "apt_metadata_old")
        recovery_ready = recovery.get("Recovery readiness", ("Unknown", "", "warn"))
        if recovery_ready[2] == "bad":
            add("Medium", "Recovery", "Recovery is not configured", "A rollback path helps recover after bad updates, driver issues, or lab mistakes.", "Review snapshot and backup readiness, then configure or test recovery manually before risky changes. This app never applies fixes automatically.", "Recovery readiness", "snapshot_missing")
        privacy_mode = privacy.get("Privacy mode", ("Unknown", "", "warn"))
        if privacy_mode[2] != "good":
            add(self.privacy_priority("privacy_routing_missing", scores), "Privacy", "No privacy routing signal is active", "Daily networking may expose your provider, DNS path, and local network context depending on your threat model.", "Review the privacy signal, confirm your threat model, then enable trusted privacy routing manually only when needed. This app never applies fixes automatically.", "Privacy mode", "privacy_routing_missing")
        profile = profiles[0] if profiles else None
        if profile and profile.get("readiness", 0) < 60:
            add("Low" if self.scoring_profile_name(scores) != profile.get("name") else "Medium", "Tools", "Scoring profile has limited tool readiness", "Missing tools may slow down labs or professional workflows.", "Install only the tools you actually need from trusted repositories outside this app. This app never applies fixes automatically.", "Missing tools for selected profile", "missing_role_tools")
        if not recs:
            add("Low", "General", "No urgent issue was detected by safe local checks", "Read-only checks look acceptable, but they are not a full audit.", "Keep reviewing updates, backups, firewall exposure, and privacy routing based on your role. This app never applies fixes automatically.", issue_key="general_review")
        return redact_data(self.deduplicate_fix_like_items(recs))

    def top_issues(self, recs):
        return [r["problem"] for r in recs[:5]]

    def top_actions(self, recs):
        return [r["safe_next_step"] for r in recs[:5]]

    def overview_summary(self, security, privacy, recovery, updates, tools_rows, installed, profiles, active, scores, recs):
        pretty, data = self.os_release()
        disk = self.disk_usage()
        status = "Healthy"
        sev = "good"
        if scores["Safety Score"] < 50:
            status = "Needs attention"
            sev = "bad"
        elif scores["Safety Score"] < 75:
            status = "Needs review"
            sev = "warn"
        update_count = updates.get("_structured", {}).get("upgradeable_count")
        update_label = "Unknown" if update_count is None else ("Up to date" if update_count == 0 else f"{update_count} upgrades available")
        return redact_data({
            "System status": (status, "Balanced score across system health, security, privacy, recovery, tools, and updates.", sev),
            "Update status": (update_label, updates.get("Upgradeable package count", ("Unknown", "", "warn"))[1], updates.get("Upgradeable package count", ("", "", "warn"))[2]),
            "Snapshot status": recovery.get("Snapshot readiness", ("Unknown", "", "warn")),
            "Privacy status": privacy.get("Privacy mode", ("Unknown", "", "warn")),
            "Active profile": (f"{active['name']} ({active['readiness']}%)", active["why"], "good" if active["readiness"] >= 70 else "warn" if active["readiness"] >= 35 else "bad"),
            "Installed tools count": (str(len(installed)), f"{len(installed)} of {len(self.tool_map)} tracked tools detected", "good" if installed else "warn"),
            "Parrot OS version": (pretty, data.get("VERSION", "Unknown"), "good" if "parrot" in pretty.lower() else "warn"),
            "Kernel version": (platform.uname().release or "Unknown", platform.uname().version or "Unknown", "good"),
            "Desktop environment": (self.desktop_environment(), "Detected from desktop session environment", "good" if self.desktop_environment() != "Unknown" else "warn"),
            "CPU": (self.cpu_name(), "CPU model from /proc/cpuinfo", "good"),
            "RAM": (self.ram_summary(), "Memory from /proc/meminfo", "good"),
            "Disk usage": (disk["summary"], "Root filesystem usage", "good" if disk["percent"] < 80 else "warn" if disk["percent"] < 90 else "bad"),
            "Uptime": (self.uptime_summary(), "System uptime from /proc/uptime", "good"),
            "Best Matching Profile": (active["name"], active["why"], "good" if active["readiness"] >= 70 else "warn"),
            "Top 5 Issues": ("; ".join(self.top_issues(recs)) if recs else "None", "Ranked from detected local checks", "warn" if recs else "good"),
            "Top 5 Recommended Actions": ("; ".join(self.top_actions(recs)) if recs else "Keep monitoring", "Safe manual actions only", "info")
        })

    def collect_all(self):
        tools_rows, installed = self.detect_tools()
        security = self.security_summary()
        privacy = self.privacy_summary()
        recovery = self.recovery_summary()
        updates = self.updates_summary()
        profiles = self.profile_status(installed, privacy, self.selected_role)
        active = self.active_profile(installed, privacy, self.selected_role)
        scores = self.compute_scores(security, privacy, recovery, updates, active, self.selected_role)
        self.current_detected_role = active.get("name", "Unknown")
        self.current_scoring_profile = scores.get("Scoring Profile", self.selected_role or self.current_detected_role)
        recs = self.make_recommendations(security, privacy, recovery, updates, profiles, tools_rows, scores)
        baseline = self.parrot_baseline(security, privacy, recovery, updates, profiles, active, scores)
        scores["Baseline Compliance Score"] = baseline.get("score", 0)
        update_guard = self.update_guard_summary(security, recovery, updates)
        fix_plan = self.fix_plan(baseline, recs, update_guard)
        overview = self.overview_summary(security, privacy, recovery, updates, tools_rows, installed, profiles, active, scores, recs)
        logs = self.logs_summary()
        workspaces = self.workspace_readiness(profiles, security, privacy, recovery, updates)
        timeline = self.timeline_summary(updates, recovery, logs, recs)
        return redact_data({
            "application": APP_NAME,
            "version": APP_VERSION,
            "title": APP_TITLE,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "screenshot_safe_mode": "ON",
            "overview": overview,
            "scores": scores,
            "security": security,
            "privacy": privacy,
            "recovery": recovery,
            "updates": updates,
            "profiles": profiles,
            "active_profile": active,
            "selected_role": self.selected_role or "Auto-detect",
            "detected_role": active.get("name", "Unknown"),
            "scoring_profile": scores.get("Scoring Profile", self.selected_role or active.get("name", "Unknown")),
            "score_weights": scores.get("Score Weights", {}),
            "score_weight_summary": scores.get("Score Weight Summary", ""),
            "tools": tools_rows,
            "logs": logs,
            "recommendations": recs,
            "parrot_baseline": baseline,
            "fix_plan": fix_plan,
            "update_guard": update_guard,
            "workspaces": workspaces,
            "timeline": timeline,
            "top_issues": self.top_issues(recs),
            "top_actions": self.top_actions(recs),
            "safety_statement": "Local read-only checks only. No telemetry, no online API calls, no package installation, and no system modification."
        })

    def format_text_report(self, report):
        report = redact_data(report)
        lines = []
        lines.append(f"{APP_TITLE} Redacted Report")
        lines.append("Created by CodeWithAmeer")
        lines.append("GitHub: https://github.com/CodeWithAmeer")
        lines.append("Version: " + str(report.get("version", APP_VERSION)))
        lines.append("License: Apache-2.0")
        lines.append("Created: " + str(report.get("created_at", "Unknown")))
        lines.append(report.get("safety_statement", ""))
        lines.append("")
        scores = report.get("scores", {})
        lines.append("Scores")
        for key, value in scores.items():
            if isinstance(value, (int, float)):
                lines.append(f"{key}: {value}/100")
            else:
                lines.append(f"{key}: {value}")
        lines.append("")
        active = report.get("active_profile", {})
        lines.append("Role Context")
        lines.append("Selected role: " + str(report.get("selected_role", "Auto-detect")))
        lines.append("Detected role: " + str(report.get("detected_role", active.get("name", "Unknown"))))
        lines.append("Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", active.get("name", "Unknown")))))
        lines.append("Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))))
        lines.append("Readiness: " + str(active.get("readiness", "Unknown")) + "%")
        lines.append("Why selected: " + str(active.get("why", "Unknown")))
        lines.append("")
        lines.append("Top Issues")
        for item in report.get("top_issues", []):
            lines.append("- " + str(item))
        lines.append("")
        lines.append("Recommendations")
        for rec in report.get("recommendations", []):
            lines.append(f"[{rec.get('priority', 'Unknown')}] {rec.get('category', 'General')}: {rec.get('problem', 'Unknown')}")
            lines.append("Why: " + str(rec.get("why", "")))
            lines.append("Safe next step: " + str(rec.get("safe_next_step", "")))
        lines.append("")
        for section in ["overview", "security", "privacy", "recovery", "updates"]:
            lines.append(section.title())
            data = report.get(section, {})
            if isinstance(data, dict):
                for key, value in data.items():
                    if str(key).startswith("_"):
                        continue
                    if isinstance(value, (list, tuple)) and len(value) >= 2:
                        lines.append(f"{key}: {value[0]}")
                        lines.append(f"  Details: {value[1]}")
                    else:
                        lines.append(f"{key}: {value}")
            lines.append("")
        lines.append("Profiles")
        for profile in report.get("profiles", []):
            lines.append(f"{profile.get('name', 'Unknown')}: {profile.get('readiness', 0)}%")
            lines.append("Detected: " + (", ".join(profile.get("detected", [])) if profile.get("detected") else "None"))
            lines.append("Missing: " + (", ".join(profile.get("missing", [])) if profile.get("missing") else "None"))
        lines.append("")
        lines.append("Tools")
        for tool in report.get("tools", []):
            path = tool.get("path") or ""
            suffix = f" ({path})" if path else ""
            lines.append(f"{tool.get('tool', 'Unknown')}: {tool.get('status', 'Unknown')}{suffix}")
        lines.append("")
        lines.append("Parrot Baseline")
        baseline = report.get("parrot_baseline", {})
        lines.append("Score: " + str(baseline.get("score", "Unknown")) + "/100")
        for item in baseline.get("items", [])[:40]:
            lines.append(f"[{item.get('severity', 'info').upper()}] {item.get('category')}: {item.get('title')} - {item.get('status')}")
            lines.append("Safe next step: " + str(item.get("next_step", "")))
        lines.append("")
        lines.append("Fix Plan")
        for item in report.get("fix_plan", {}).get("items", [])[:40]:
            lines.append(f"[{item.get('priority')}] {item.get('category')}: {item.get('problem')}")
            lines.append("Verification: " + str(item.get("manual_verification_command", "")))
            lines.append("Safe suggestion: " + str(item.get("safe_manual_fix_suggestion", "")))
        lines.append("")
        lines.append("Update Guard")
        guard = report.get("update_guard", {})
        lines.append("Risk: " + str(guard.get("risk_level", "Unknown")))
        for reason in guard.get("why", []):
            lines.append("- " + str(reason))
        lines.append("")
        lines.append("Workspace Readiness")
        for row in report.get("workspaces", [])[:20]:
            lines.append(f"{row.get('role')}: {row.get('role_score')}%")
        lines.append("")
        lines.append("Timeline Summary")
        for row in report.get("timeline", [])[:30]:
            lines.append(f"{row.get('time')} [{row.get('severity')}] {row.get('category')}: {row.get('event_summary')}")
        lines.append("")
        lines.append("Logs Summary")
        logs = report.get("logs", {})
        for key, value in logs.items():
            lines.append(str(key))
            lines.append(str(value))
            lines.append("")
        return "\n".join(safe_limit_text(line, REPORT_FIELD_LIMIT) for line in lines)



    def build_check_registry(self):
        rows = [
            ("apparmor", "Security Hardening", "AppArmor status", "Mandatory access control readiness", "apparmor_status", 3, "AppArmor status", "aa-status", "Active"),
            ("firewall", "Network Exposure", "Firewall status", "Host firewall readiness", "firewall_status", 3, "Firewall status", "ufw status; nft list ruleset", "Active firewall or nftables rules"),
            ("disk_encryption", "Security Hardening", "Disk encryption status", "Storage confidentiality posture", "disk_encryption_status", 2, "Disk encryption status", "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT", "LUKS or dm-crypt for sensitive devices"),
            ("secure_boot", "Security Hardening", "Secure Boot status", "Boot chain signal", "secure_boot_status", 1, "Secure Boot status", "mokutil --sb-state", "Enabled when compatible with your workflow"),
            ("apt_timer", "Updates", "APT automatic update timer status", "Update timer readiness", "apt_timer_status", 1, "APT automatic update timer status", "systemctl status apt-daily.timer", "Timer active or intentional manual process"),
            ("apt_age", "Updates", "APT update age", "APT metadata freshness", "apt_update_age", 2, "Old APT metadata", "stat /var/lib/apt/lists", "Recent metadata"),
            ("upgradeable", "Updates", "Upgradeable package count", "Pending package updates", "upgradeable_packages", 2, "Upgradeable package count", "apt list --upgradable", "Reviewed pending updates"),
            ("broken_packages", "Updates", "Broken package check", "Package database health", "broken_packages", 4, "Broken packages", "dpkg --audit", "No broken packages"),
            ("failed_units", "Logs and Stability", "Failed systemd units", "Systemd service failures", "failed_units", 3, "Failed systemd units", "systemctl --failed", "No failed units"),
            ("open_ports", "Network Exposure", "Open listening ports", "Local listening socket exposure", "open_ports", 2, "Open listening ports", "ss -tulpen", "Only intentional services listening"),
            ("network_services", "Network Exposure", "Running network services", "Active service exposure", "running_network_services", 2, "Running network services", "systemctl --type=service --state=running", "Only intentional network services"),
            ("sysctl", "Security Hardening", "Sysctl hardening checks", "Basic kernel hardening values", "sysctl_hardening", 2, "Sysctl hardening checks", "sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.yama.ptrace_scope", "Hardened values for daily use"),
            ("privacy_mode", "Privacy Readiness", "Privacy mode", "Privacy routing and browser signal", "privacy_summary", 3, "No privacy routing signal", "ip -brief addr; systemctl status tor", "Privacy signal appropriate for selected role"),
            ("snapshots", "Recovery Readiness", "Recovery readiness", "Rollback readiness", "recovery_summary", 3, "No recovery snapshots", "timeshift --list; snapper list", "Snapshot or tested backup workflow"),
            ("role_tools", "Role Fit", "Tool readiness for scoring profile", "Tools needed for scoring profile", "detect_tools", 2, "Missing tools for selected profile", "command -v toolname", "Scoring profile has the required tools")
        ]
        registry = []
        for check_id, category, title, description, runner, weight, guide, verify, recommended in rows:
            registry.append(CheckDefinition(check_id, category, title, description, runner, {"good": "OK", "warn": "Review", "bad": "Attention", "critical": "Critical"}, weight, self.role_weights_for_category(category), guide, verify, recommended))
        return registry

    def role_weights_for_category(self, category):
        base = {
            "Daily User": 1, "Privacy Mode": 1, "Developer Workstation": 1, "Web Pentesting": 1, "Red Team": 1,
            "Cloud Security": 1, "Malware Analysis and Reverse Engineering": 1, "DFIR and Blue Team": 1, "Automation Security Research": 1, "HTB and CTF Lab": 1
        }
        if category == "Privacy Readiness":
            base["Privacy Mode"] = 4
        if category == "Recovery Readiness":
            base["Daily User"] = 3
            base["Malware Analysis and Reverse Engineering"] = 4
            base["Red Team"] = 3
        if category == "Tool Readiness" or category == "Role Fit":
            for key in list(base):
                base[key] = 2 if key != "Daily User" else 1
        if category == "Network Exposure":
            base["Web Pentesting"] = 3
            base["Red Team"] = 3
        if category == "Updates":
            base["Developer Workstation"] = 3
            base["Daily User"] = 3
        return base

    def normalize_check(self, title, item, category, weight=1, fix_guide_key=None, recommended_state="Healthy or intentionally configured"):
        if isinstance(item, (tuple, list)) and len(item) >= 3:
            status, details, severity = item[0], item[1], item[2]
        else:
            status, details, severity = "Unknown", str(item), "unknown"
        impact = {"critical": -25, "bad": -18, "warn": -8, "unknown": -5, "info": 0, "good": 8}.get(str(severity), 0) * max(1, int(weight))
        severity_text = str(severity).lower()
        if severity_text == "good":
            next_step = "No action needed. Keep monitoring this item after major system changes."
        elif severity_text == "info":
            next_step = "Informational only. Review details if this affects your workflow."
        else:
            next_step = fix_guide_content(fix_guide_key or title).split("Safe next steps\n", 1)[-1]
        return {
            "status": str(status),
            "severity": str(severity),
            "summary": brief_detail(str(details), 220),
            "details": safe_limit_text(str(details), REPORT_FIELD_LIMIT),
            "evidence": safe_limit_text(str(details), REPORT_FIELD_LIMIT),
            "detected_state": str(status),
            "recommended_state": recommended_state,
            "next_step": next_step,
            "fix_guide_key": fix_guide_key or title,
            "score_impact": impact,
            "category": category,
            "title": title
        }

    def parrot_baseline(self, security, privacy, recovery, updates, profiles, active, scores):
        registry = self.build_check_registry()
        lookups = {}
        for name, source in [("Security Hardening", security), ("Network Exposure", security), ("Logs and Stability", security), ("Privacy Readiness", privacy), ("Recovery Readiness", recovery), ("Updates", updates)]:
            for key, value in source.items():
                if not str(key).startswith("_"):
                    lookups[key] = (name, value)
        items = []
        wanted = [
            ("AppArmor status", "Security Hardening"), ("Firewall status", "Network Exposure"), ("Disk encryption status", "Security Hardening"),
            ("Secure Boot status", "Security Hardening"), ("APT automatic update timer status", "Updates"), ("APT update age", "Updates"),
            ("Upgradeable package count", "Updates"), ("Broken package check", "Updates"), ("Held packages", "Updates"), ("Failed systemd units", "Logs and Stability"),
            ("Open listening ports", "Network Exposure"), ("Running network services", "Network Exposure"), ("Kernel lockdown status", "Security Hardening"),
            ("Sysctl hardening checks", "Security Hardening"), ("Privacy mode", "Privacy Readiness"), ("VPN interface detection", "Privacy Readiness"),
            ("Tor service status", "Privacy Readiness"), ("AnonSurf status", "Privacy Readiness"), ("Proxy environment variables", "Privacy Readiness"),
            ("DNS leak risk", "Privacy Readiness"), ("Firefox privacy detection", "Privacy Readiness"), ("Snapshot readiness", "Recovery Readiness"),
            ("Recovery readiness", "Recovery Readiness"), ("Root partition free space", "Recovery Readiness"), ("Snapshot tool readiness", "Recovery Readiness")
        ]
        defs = {d.title: d for d in registry}
        for title, category in wanted:
            source = security if title in security else privacy if title in privacy else recovery if title in recovery else updates
            if title not in source:
                continue
            definition = defs.get(title)
            weight = definition.score_weight if definition else 1
            verify = definition.safe_manual_verification_command if definition else "Use trusted local system tools"
            recommended = definition.recommended_state if definition else "Healthy or intentionally configured"
            item = self.normalize_check(title, source.get(title), category, weight, title, recommended)
            item["description"] = definition.description if definition else "Local read-only safety check"
            item["manual_verification_command"] = verify
            item["why_it_matters"] = fix_guide_content(title).split("Why it matters\n", 1)[-1].split("\n\nHow to verify", 1)[0]
            items.append(item)
        selected = active or {}
        tool_status = (str(selected.get("readiness", 0)) + "%", selected.get("why", "Tool readiness depends on role overlap."), "good" if selected.get("readiness", 0) >= 70 else "warn" if selected.get("readiness", 0) >= 40 else "bad")
        role_item = self.normalize_check("Tool readiness for scoring profile", tool_status, "Role Fit", 2, "Missing tools for selected profile", "Role-appropriate tools available")
        role_item["description"] = "Scoring profile readiness from tracked local tools and role signals"
        role_item["manual_verification_command"] = "command -v toolname"
        role_item["why_it_matters"] = "Role readiness helps decide whether the system is prepared for the current workflow."
        items.append(role_item)
        baseline_score = self.baseline_score(items)
        return {"title": "Community recommended baseline, unofficial", "score": baseline_score, "items": items, "registry_count": len(registry)}

    def baseline_score(self, baseline_or_items):
        items = baseline_or_items.get("items", baseline_or_items) if isinstance(baseline_or_items, dict) else baseline_or_items
        total = 0
        possible = 0
        for item in items or []:
            weight = max(1, abs(int(item.get("score_impact", 1))) // 8 or 1)
            possible += weight
            sev = item.get("severity", "unknown")
            if sev == "good":
                total += weight
            elif sev == "info":
                total += weight * 0.75
            elif sev == "warn":
                total += weight * 0.45
            elif sev == "unknown":
                total += weight * 0.30
        return clamp_score(total / possible * 100 if possible else 0)

    def update_guard_summary(self, security, recovery, updates):
        struct = updates.get("_structured", {}) if isinstance(updates, dict) else {}
        broken = struct.get("broken_count") or 0
        upgrades = struct.get("upgradeable_count") or 0
        age = struct.get("age_days")
        failed = security.get("Failed systemd units", ("Unknown", "", "warn"))[2]
        disk_text = recovery.get("Root partition free space", ("Unknown", "", "warn"))[0]
        recovery_ready = recovery.get("Recovery readiness", ("Unknown", "", "warn"))[2]
        snapshot_ready = recovery.get("Snapshot readiness", ("Unknown", "", "warn"))[2]
        reasons = []
        level = "Safe to review updates"
        severity = "good"
        if broken > 0:
            level = "Critical, fix package state first"
            severity = "critical"
            reasons.append("Broken packages were detected by dpkg audit.")
        if recovery_ready == "bad" and upgrades >= 30 and severity != "critical":
            level = "High risk, create backup first"
            severity = "bad"
            reasons.append("Many upgrades are pending and recovery is not configured.")
        if snapshot_ready != "good" and upgrades >= 50 and severity != "critical":
            level = "High risk, create backup first"
            severity = "bad"
            reasons.append("Snapshot readiness is weak before a large update review.")
        if recovery.get("Root partition free space", ("", "", "warn"))[2] != "good" and severity not in ["critical", "bad"]:
            level = "High risk, create backup first"
            severity = "bad"
            reasons.append("Root partition free space needs review.")
        if failed == "bad" and severity not in ["critical", "bad"]:
            level = "Review before updating"
            severity = "warn"
            reasons.append("Failed systemd units are present.")
        if age is not None and age > 14 and severity == "good":
            level = "Review before updating"
            severity = "warn"
            reasons.append("APT metadata appears old.")
        if not reasons:
            reasons.append("Package state and recovery signals do not show a major update blocker from read-only checks.")
        checklist = [
            "Confirm dpkg audit is clean before updates.",
            "Confirm snapshot or backup readiness before large updates.",
            "Review held packages and repository source health.",
            "Confirm adequate free disk space on root partition.",
            "Review failed systemd units before a maintenance window."
        ]
        rollback = [
            "Snapshot readiness: " + str(recovery.get("Snapshot readiness", ("Unknown",))[0]),
            "Recovery readiness: " + str(recovery.get("Recovery readiness", ("Unknown",))[0]),
            "Root free space: " + str(disk_text)
        ]
        return redact_data({
            "risk_level": level,
            "severity": severity,
            "why": reasons,
            "pre_update_safety_checklist": checklist,
            "rollback_readiness_checklist": rollback,
            "safe_manual_next_steps": ["Review updates manually in your normal package manager only after checking rollback readiness.", "This app does not run apt update or apt upgrade."],
            "details": {"upgradeable_count": upgrades, "broken_count": broken, "apt_metadata_age_days": age, "failed_units_severity": failed}
        })

    def fix_item_key(self, problem, guide_key=None, category=None):
        text = " ".join(str(x or "") for x in [problem, guide_key, category]).lower()
        rules = [
            ("failed_systemd_units", ["failed systemd", "failed units"]),
            ("firewall_missing", ["firewall", "no active firewall"]),
            ("disk_encryption_missing", ["disk encryption", "encryption was not detected"]),
            ("apparmor_inactive", ["apparmor"]),
            ("secure_boot_review", ["secure boot"]),
            ("apt_timer_missing", ["apt automatic", "apt-daily"]),
            ("apt_metadata_old", ["apt metadata", "apt update age"]),
            ("missing_updates", ["upgradeable", "missing updates"]),
            ("broken_packages", ["broken package", "dpkg"]),
            ("held_packages", ["held package"]),
            ("snapshot_missing", ["snapshot", "recovery readiness", "recovery is not configured"]),
            ("privacy_routing_missing", ["privacy mode", "privacy routing", "no privacy routing"]),
            ("vpn_missing", ["vpn interface"]),
            ("tor_inactive", ["tor service", "tor inactive"]),
            ("anonsurf_inactive", ["anonsurf"]),
            ("proxy_missing", ["proxy environment"]),
            ("dns_review", ["dns leak", "dns resolver", "dns review"]),
            ("firefox_privacy_review", ["firefox privacy", "browser privacy"]),
            ("kernel_lockdown_review", ["kernel lockdown"]),
            ("sysctl_hardening_review", ["sysctl"]),
            ("network_services_review", ["running network services"]),
            ("open_ports_review", ["open listening ports", "listening port"]),
            ("ssh_active", ["ssh service"]),
            ("missing_role_tools", ["selected profile", "tool readiness", "role tools", "missing tools"])
        ]
        for key, terms in rules:
            if any(term in text for term in terms):
                return key
        return re.sub(r"[^a-z0-9]+", "_", text).strip("_")[:80] or "general_review"

    def strongest_priority(self, a, b):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return a if order.get(a, 9) <= order.get(b, 9) else b

    def strongest_category(self, a, b):
        rank = {"System Health": 0, "Updates": 1, "Security": 2, "Network Exposure": 3, "Security Hardening": 4, "Recovery": 5, "Recovery Readiness": 5, "Privacy": 6, "Privacy Readiness": 6, "Logs and Stability": 7, "Tools": 8, "Tool Readiness": 8, "Role Fit": 8, "General": 9}
        return a if rank.get(a, 9) <= rank.get(b, 9) else b

    def category_next_step(self, category, key=None):
        category = str(category or "General")
        steps = {
            "General": "Review the detected value, compare it with the recommended state, then apply changes manually using trusted system tools. This app never applies fixes automatically.",
            "Security": "Review the hardening value, verify it with the command shown, then change it manually only if it matches your workflow. This app never applies fixes automatically.",
            "Security Hardening": "Review the hardening value, verify it with the command shown, then change it manually only if it matches your workflow. This app never applies fixes automatically.",
            "Network Exposure": "Review the exposed service or port, confirm it is intentional, then restrict or disable it manually if it is not needed. This app never applies fixes automatically.",
            "Privacy": "Review the privacy signal, confirm your threat model, then enable trusted privacy routing manually only when needed. This app never applies fixes automatically.",
            "Privacy Readiness": "Review the privacy signal, confirm your threat model, then enable trusted privacy routing manually only when needed. This app never applies fixes automatically.",
            "Recovery": "Review snapshot and backup readiness, then configure or test recovery manually before risky changes. This app never applies fixes automatically.",
            "Recovery Readiness": "Review snapshot and backup readiness, then configure or test recovery manually before risky changes. This app never applies fixes automatically.",
            "Updates": "Review package state and update readiness before running manual package maintenance. This app never applies fixes automatically.",
            "Logs and Stability": "Inspect the related logs first, then resolve the underlying service or kernel issue manually. This app never applies fixes automatically.",
            "Tools": "Install only the tools you actually need from trusted repositories outside this app. This app never applies fixes automatically.",
            "Tool Readiness": "Install only the tools you actually need from trusted repositories outside this app. This app never applies fixes automatically.",
            "Role Fit": "Install only the tools you actually need from trusted repositories outside this app. This app never applies fixes automatically."
        }
        return steps.get(category, steps["General"])

    def adjust_privacy_priority_for_role(self, item):
        if item.get("category") not in ["Privacy", "Privacy Readiness"]:
            return item
        role = getattr(self, "current_scoring_profile", None) or self.selected_role or "Daily User"
        key = item.get("issue_key") or self.fix_item_key(item.get("problem"), item.get("fix_guide_key"), item.get("category"))
        if role == "Privacy Mode":
            if key in {"privacy_routing_missing", "vpn_missing", "dns_review"}:
                item["priority"] = self.strongest_priority(item.get("priority", "Medium"), "High")
            elif item.get("priority") == "Low":
                item["priority"] = "Medium"
        elif role == "Web Pentesting":
            item["priority"] = "Medium" if key in {"dns_review"} else "Low"
        elif role == "Daily User":
            item["priority"] = "Medium" if key in {"dns_review", "firefox_privacy_review"} else "Low"
        elif key in {"privacy_routing_missing", "vpn_missing", "proxy_missing", "tor_inactive", "anonsurf_inactive"}:
            item["priority"] = "Low"
        return item

    def deduplicate_fix_like_items(self, items):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        merged = {}
        for raw in items or []:
            item = dict(raw)
            key = item.get("issue_key") or self.fix_item_key(item.get("problem"), item.get("fix_guide_key") or item.get("guide_key"), item.get("category"))
            item["issue_key"] = key
            item = self.adjust_privacy_priority_for_role(item)
            if key not in merged:
                merged[key] = item
                continue
            old = merged[key]
            stronger_priority = self.strongest_priority(old.get("priority", "Low"), item.get("priority", "Low"))
            generic_titles = {"Firewall status", "Disk encryption status", "Failed systemd units", "Recovery readiness", "Snapshot readiness", "Privacy mode", "VPN interface detection", "Tor service status", "AnonSurf status", "Proxy environment variables", "DNS leak risk", "Firefox privacy detection", "Tool readiness for scoring profile"}
            if stronger_priority == item.get("priority") and item.get("problem"):
                old["problem"] = item.get("problem")
            elif old.get("problem") in generic_titles and item.get("problem") not in generic_titles and item.get("problem"):
                old["problem"] = item.get("problem")
            old["priority"] = stronger_priority
            old["category"] = self.strongest_category(old.get("category", "General"), item.get("category", "General"))
            for field in ["risk", "why_it_matters", "why", "details"]:
                if item.get(field) and item.get(field) not in str(old.get(field, "")):
                    old[field] = (str(old.get(field, "")).rstrip() + "\n" + str(item.get(field))).strip() if old.get(field) else item.get(field)
            for field in ["manual_verification_command", "safe_manual_fix_suggestion", "safe_next_step", "expected_improvement", "fix_guide_key", "guide_key"]:
                if not old.get(field) and item.get(field):
                    old[field] = item.get(field)
        result = list(merged.values())
        result.sort(key=lambda x: (order.get(x.get("priority"), 9), x.get("category", ""), x.get("problem", "")))
        return result

    def fix_plan(self, baseline, recommendations, update_guard):
        items = []
        priority_map = {"critical": "Critical", "bad": "High", "warn": "Medium", "unknown": "Medium", "info": "Low", "good": "Low"}
        for row in baseline.get("items", []):
            sev = row.get("severity", "info")
            if sev == "good":
                continue
            issue_key = self.fix_item_key(row.get("title"), row.get("fix_guide_key"), row.get("category"))
            priority = priority_map.get(sev, "Medium")
            if row.get("title") == "Broken package check" and sev in ["bad", "critical"]:
                priority = "Critical"
            if row.get("title") == "Recovery readiness" and update_guard.get("severity") in ["bad", "critical"]:
                priority = "High"
            if row.get("category") == "Privacy Readiness":
                priority = self.privacy_priority(issue_key, {"Scoring Profile": getattr(self, "current_scoring_profile", None)})
            suggestion = row.get("next_step") or self.category_next_step(row.get("category"), issue_key)
            if suggestion.strip() in {"Review this item manually using trusted system tools.", "Review manually. No action is run by this app.", "No action needed. Keep monitoring this item after major system changes."}:
                suggestion = self.category_next_step(row.get("category"), issue_key)
            if row.get("category") in ["Privacy", "Privacy Readiness"] and priority == "Low":
                suggestion = "Optional for this role. Enable privacy routing only when your workflow requires it. This app never applies fixes automatically."
            problem_titles = {
                "failed_systemd_units": "Failed systemd units detected",
                "firewall_missing": "No active firewall was detected",
                "disk_encryption_missing": "Disk encryption was not detected",
                "apparmor_inactive": "AppArmor is inactive",
                "secure_boot_review": "Secure Boot needs review",
                "apt_timer_missing": "APT automatic update timers need review",
                "apt_metadata_old": "APT metadata appears very old",
                "broken_packages": "Broken packages detected",
                "held_packages": "Held packages need review",
                "snapshot_missing": "Recovery snapshots are not ready",
                "privacy_routing_missing": "No privacy routing signal is active",
                "vpn_missing": "VPN interface detection needs review",
                "dns_review": "DNS privacy needs review",
                "firefox_privacy_review": "Firefox privacy hints need review",
                "sysctl_hardening_review": "Sysctl hardening needs review",
                "network_services_review": "Running network services need review",
                "open_ports_review": "Open listening ports need review",
                "missing_role_tools": "Scoring profile has limited tool readiness"
            }
            item = {
                "priority": priority,
                "category": row.get("category", "General"),
                "problem": problem_titles.get(issue_key, row.get("title", "Detected issue")),
                "risk": row.get("summary", "Local check needs review."),
                "why_it_matters": row.get("why_it_matters", "This can affect system safety or readiness."),
                "manual_verification_command": row.get("manual_verification_command", "Use trusted local tools to verify."),
                "safe_manual_fix_suggestion": suggestion,
                "expected_improvement": "Improves " + row.get("category", "system") + " readiness and can raise the safety score.",
                "fix_guide_key": row.get("fix_guide_key", row.get("title", "Recommendation")),
                "details": row.get("details", ""),
                "issue_key": issue_key
            }
            items.append(item)
        for rec in recommendations:
            issue_key = rec.get("issue_key") or self.fix_item_key(rec.get("problem"), rec.get("guide_key"), rec.get("category"))
            suggestion = rec.get("safe_next_step") or self.category_next_step(rec.get("category"), issue_key)
            rec_priority = rec.get("priority", "Low")
            if rec.get("category") in ["Privacy", "Privacy Readiness"] and rec_priority == "Low":
                suggestion = "Optional for this role. Enable privacy routing only when your workflow requires it. This app never applies fixes automatically."
            items.append({
                "priority": rec_priority,
                "category": rec.get("category", "General"),
                "problem": rec.get("problem", "Recommendation"),
                "risk": rec.get("why", ""),
                "why_it_matters": rec.get("why", ""),
                "manual_verification_command": fix_guide_content(rec.get("guide_key", rec.get("problem", "Recommendation"))).split("How to verify manually\n", 1)[-1].split("\n\nSafe next steps", 1)[0],
                "safe_manual_fix_suggestion": suggestion,
                "expected_improvement": "Improves the related readiness category.",
                "fix_guide_key": rec.get("guide_key", rec.get("problem", "Recommendation")),
                "details": rec.get("safe_next_step", ""),
                "issue_key": issue_key
            })
        items = self.deduplicate_fix_like_items(items)
        return redact_data({"items": items, "summary": "Ranked safe next steps built from local read-only checks", "count": len(items)})

    def workspace_readiness(self, profiles, security, privacy, recovery, updates):
        rows = []
        profile_map = {p.get("name"): p for p in profiles}
        names = list(self.profiles.keys()) + ["HTB and CTF Lab"]
        for name in names:
            profile = profile_map.get(name)
            if name == "HTB and CTF Lab":
                web = profile_map.get("Web Pentesting", {})
                red = profile_map.get("Red Team", {})
                readiness = clamp_score((web.get("readiness", 0) + red.get("readiness", 0)) / 2)
                installed = sorted(set(web.get("detected", []) + red.get("detected", [])))
                missing = sorted(set(web.get("missing", []) + red.get("missing", [])))[:12]
                purpose = "Hands-on lab workflow for Hack The Box, CTFs, web testing, enumeration, and safe isolated practice."
            else:
                readiness = profile.get("readiness", 0) if profile else 0
                installed = profile.get("detected", []) if profile else []
                missing = profile.get("missing", []) if profile else []
                purpose = profile.get("purpose", self.profiles.get(name, {}).get("purpose", "Role readiness")) if profile else self.profiles.get(name, {}).get("purpose", "Role readiness")
            sec_risks = []
            if security.get("Firewall status", ("", "", "warn"))[2] != "good":
                sec_risks.append("Firewall posture needs review")
            if security.get("SSH service status", ("", "", "info"))[0] == "Active":
                sec_risks.append("SSH is active")
            privacy_risks = []
            if name == "Privacy Mode" and privacy.get("Privacy mode", ("", "", "warn"))[2] != "good":
                privacy_risks.append("No strong privacy routing signal")
            recovery_state = recovery.get("Recovery readiness", ("Unknown", "", "warn"))[0]
            checklist = [
                "Confirm authorization and scope before security testing.",
                "Use snapshots or tested backups before risky labs.",
                "Keep secrets out of terminal history and project folders.",
                "Review network exposure before connecting to untrusted networks."
            ]
            rows.append({
                "role": name,
                "purpose": purpose,
                "role_score": readiness,
                "installed_tools": installed,
                "missing_tools": missing,
                "security_risks": sec_risks or ["No major role-specific security risk highlighted by read-only checks"],
                "privacy_risks": privacy_risks or ["Privacy risk depends on threat model and network path"],
                "recovery_readiness": recovery_state,
                "recommended_setup": self.profiles.get(name, {}).get("next", "Use isolated workspaces and keep updates, backups, and logs review in the workflow."),
                "safe_workflow_checklist": checklist
            })
        return redact_data(rows)

    def timeline_summary(self, updates, recovery, logs, recommendations):
        now = datetime.now().isoformat(timespec="seconds")
        items = []
        def add(category, summary, severity="info", details=""):
            items.append({"time": now, "category": category, "event_summary": summary, "severity": severity, "details": safe_limit_text(details, REPORT_FIELD_LIMIT)})
        add("Refresh", "Safe local checks completed", "good", "Refresh-based timeline only. No continuous monitoring or daemon is used.")
        age = updates.get("APT update age", ("Unknown", "", "warn"))
        add("Updates", "APT metadata age: " + str(age[0]), age[2], age[1])
        up = updates.get("Upgradeable package count", ("Unknown", "", "warn"))
        add("Updates", "Upgradeable packages: " + str(up[0]), up[2], up[1])
        broken = updates.get("Broken package check", ("Unknown", "", "warn"))
        add("Updates", "Broken package status: " + str(broken[0]), broken[2], broken[1])
        held = updates.get("Held packages", ("Unknown", "", "info"))
        add("Updates", "Held packages: " + str(held[0]), held[2], held[1])
        snap = recovery.get("Snapshot readiness", ("Unknown", "", "warn"))
        add("Recovery", "Snapshot readiness: " + str(snap[0]), snap[2], snap[1])
        rec = recovery.get("Recovery readiness", ("Unknown", "", "warn"))
        add("Recovery", "Recovery readiness: " + str(rec[0]), rec[2], rec[1])
        add("Logs", "Journal and kernel diagnostic summaries refreshed", "info", json.dumps(logs, indent=2))
        add("Recommendations", f"{len(recommendations)} ranked recommendation items available", "info", "Use Fix Plan for prioritized manual actions.")
        return redact_data(items)

    def format_fix_plan_text(self, report):
        plan = report.get("fix_plan", {}).get("items", [])
        lines = [f"{APP_TITLE} Fix Plan", "Created by CodeWithAmeer", "GitHub: https://github.com/CodeWithAmeer", "Version: " + APP_VERSION, "License: Apache-2.0", "Selected role: " + str(report.get("selected_role", "Auto-detect")), "Detected role: " + str(report.get("detected_role", report.get("active_profile", {}).get("name", "Unknown"))), "Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", "Unknown"))), "Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))), ""]
        for idx, item in enumerate(plan, 1):
            lines.append(f"{idx}. {item.get('priority')} {item.get('category')}: {item.get('problem')}")
            lines.append("Next step: " + str(item.get("safe_manual_fix_suggestion", "")))
            lines.append("Verify: " + str(item.get("manual_verification_command", "")))
            lines.append("Why: " + str(item.get("why_it_matters", "")))
            lines.append("")
        return "\n".join(safe_limit_text(line, REPORT_FIELD_LIMIT) for line in lines)

    def format_baseline_text(self, report):
        baseline = report.get("parrot_baseline", {})
        lines = [f"{APP_TITLE} Parrot Baseline Report", "Community recommended baseline, unofficial", "Created by CodeWithAmeer", "GitHub: https://github.com/CodeWithAmeer", "Version: " + APP_VERSION, "Score: " + str(baseline.get("score", "Unknown")), "Selected role: " + str(report.get("selected_role", "Auto-detect")), "Detected role: " + str(report.get("detected_role", report.get("active_profile", {}).get("name", "Unknown"))), "Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", "Unknown"))), "Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))), ""]
        for item in baseline.get("items", []):
            lines.append(f"[{item.get('severity', 'info').upper()}] {item.get('category')}: {item.get('title')} - {item.get('status')}")
            lines.append("Why: " + str(item.get("why_it_matters", "")))
            lines.append("Detected state: " + str(item.get("detected_state", "")))
            lines.append("Recommended state: " + str(item.get("recommended_state", "")))
            lines.append("Safe next step: " + str(item.get("next_step", "")))
            lines.append("")
        return "\n".join(safe_limit_text(line, REPORT_FIELD_LIMIT) for line in lines)

    def format_workspace_text(self, report):
        lines = [f"{APP_TITLE} Workspace Readiness Report", "Created by CodeWithAmeer", "GitHub: https://github.com/CodeWithAmeer", "Version: " + APP_VERSION, "Selected role: " + str(report.get("selected_role", "Auto-detect")), "Detected role: " + str(report.get("detected_role", report.get("active_profile", {}).get("name", "Unknown"))), "Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", "Unknown"))), "Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))), ""]
        for row in report.get("workspaces", []):
            lines.append(f"{row.get('role')}: {row.get('role_score')}%")
            lines.append("Installed tools: " + (", ".join(row.get("installed_tools", [])) if row.get("installed_tools") else "None"))
            lines.append("Missing tools: " + (", ".join(row.get("missing_tools", [])) if row.get("missing_tools") else "None"))
            lines.append("Recovery readiness: " + str(row.get("recovery_readiness", "Unknown")))
            lines.append("Recommended setup: " + str(row.get("recommended_setup", "")))
            lines.append("")
        return "\n".join(safe_limit_text(line, REPORT_FIELD_LIMIT) for line in lines)

    def format_update_guard_text(self, report):
        guard = report.get("update_guard", {})
        lines = [f"{APP_TITLE} Update Guard Report", "Created by CodeWithAmeer", "GitHub: https://github.com/CodeWithAmeer", "Version: " + APP_VERSION, "Risk: " + str(guard.get("risk_level", "Unknown")), "Selected role: " + str(report.get("selected_role", "Auto-detect")), "Detected role: " + str(report.get("detected_role", report.get("active_profile", {}).get("name", "Unknown"))), "Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", "Unknown"))), "Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))), ""]
        lines.append("Why this risk level")
        for row in guard.get("why", []):
            lines.append("- " + str(row))
        lines.append("")
        lines.append("Pre-update safety checklist")
        for row in guard.get("pre_update_safety_checklist", []):
            lines.append("- " + str(row))
        lines.append("")
        lines.append("Rollback readiness checklist")
        for row in guard.get("rollback_readiness_checklist", []):
            lines.append("- " + str(row))
        lines.append("")
        lines.append("Safe manual next steps")
        for row in guard.get("safe_manual_next_steps", []):
            lines.append("- " + str(row))
        return "\n".join(safe_limit_text(line, REPORT_FIELD_LIMIT) for line in lines)

    def format_html_report(self, report):
        report = redact_data(report)
        def esc(value):
            return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        scores = report.get("scores", {})
        sections = []
        def card(title, body):
            sections.append(f"<section class='card'><h2>{esc(title)}</h2>{body}</section>")
        score_html = "".join(f"<div class='metric'><span>{esc(k)}</span><b>{esc(v)}/100</b></div>" for k, v in scores.items() if isinstance(v, (int, float)))
        card("Scores", score_html)
        card("Why this score", "<p>" + esc(scores.get("Score Explanation", "Unknown")) + "</p>")
        rec_html = "<ol>" + "".join(f"<li><b>{esc(i.get('priority'))}</b> {esc(i.get('category'))}: {esc(i.get('problem'))}<br><small>{esc(i.get('safe_next_step', i.get('safe_manual_fix_suggestion', '')))}</small></li>" for i in report.get("fix_plan", {}).get("items", [])[:20]) + "</ol>"
        card("Fix Plan", rec_html)
        base_html = "<table><tr><th>Category</th><th>Item</th><th>Status</th><th>Severity</th><th>Next step</th></tr>" + "".join(f"<tr><td>{esc(i.get('category'))}</td><td>{esc(i.get('title'))}</td><td>{esc(i.get('status'))}</td><td>{esc(i.get('severity'))}</td><td>{esc(i.get('next_step'))}</td></tr>" for i in report.get("parrot_baseline", {}).get("items", [])) + "</table>"
        card("Parrot Baseline", base_html)
        guard = report.get("update_guard", {})
        card("Update Guard", f"<p><b>{esc(guard.get('risk_level', 'Unknown'))}</b></p><ul>" + "".join(f"<li>{esc(x)}</li>" for x in guard.get("why", [])) + "</ul>")
        tools = report.get("tools", [])
        tool_html = "<table><tr><th>Tool</th><th>Category</th><th>Status</th></tr>" + "".join(f"<tr><td>{esc(t.get('tool'))}</td><td>{esc(t.get('category'))}</td><td>{esc(t.get('status'))}</td></tr>" for t in tools) + "</table>"
        card("Tools", tool_html)
        html = f"""<!doctype html><html><head><meta charset='utf-8'><title>{esc(APP_TITLE)} Report</title><style>body{{margin:0;background:#071114;color:#e6edf3;font-family:Inter,Segoe UI,Arial,sans-serif}}header{{padding:28px;background:linear-gradient(135deg,#102a34,#111d36,#26183c);border-bottom:1px solid #1f3b43}}h1{{margin:0;font-size:34px}}.sub{{color:#9fb3bd}}main{{padding:22px;display:grid;gap:18px}}.card{{background:#0d1b20;border:1px solid #1f3b43;border-radius:18px;padding:18px}}h2{{color:#22d3c5;margin-top:0}}.metric{{display:inline-flex;gap:12px;align-items:center;margin:8px;padding:10px 14px;background:#10252b;border-radius:12px;border:1px solid #1f3b43}}.metric b{{color:#7ee787}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #1f3b43;padding:9px;text-align:left;vertical-align:top}}th{{color:#22d3c5;background:#102a32}}small{{color:#9fb3bd}}footer{{padding:20px;color:#9fb3bd}}</style></head><body><header><h1>{esc(APP_TITLE)}</h1><div class='sub'>Unofficial project for Parrot OS | Created by CodeWithAmeer | GitHub: https://github.com/CodeWithAmeer | License: Apache-2.0</div><div class='sub'>Screenshot Safe Mode: {esc(report.get('screenshot_safe_mode', 'Unknown'))} | Selected role: {esc(report.get('selected_role','Auto-detect'))} | Detected role: {esc(report.get('detected_role', report.get('active_profile', {}).get('name', 'Unknown')))} | Scoring profile: {esc(report.get('scoring_profile', report.get('scores', {}).get('Scoring Profile', 'Unknown')))}</div></header><main>{''.join(sections)}</main><footer>No telemetry. No online API calls. No system modification. Read-only local report.</footer></body></html>"""
        return html
