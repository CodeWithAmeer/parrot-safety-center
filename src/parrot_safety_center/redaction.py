from .common import *

def redact_text(value):
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?<![\w.-])([^\s:/@]+):([^\s@/]+)@([A-Za-z0-9._-]+\.[A-Za-z]{2,}|localhost|[0-9.]+)", r"[REDACTED]@\3", text)
    text = re.sub(r"(?i)\b(" + SENSITIVE_KEYS + r")\b\s*([=:])\s*([^\s'\"<>;&,]+)", lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:" + SENSITIVE_KEYS + r")=)([^\s&#]+)", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b(" + SENSITIVE_KEYS + r")\b\s+([^\s'\"<>;&,]+)", lambda m: f"{m.group(1)} [REDACTED]", text)
    text = re.sub(r"(?i)(authorization\s*:\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", r"\1\2 [REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(basic\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(proxy\s*=?\s*[a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?i)((?:" + SENSITIVE_KEYS + r")[^\n]{0,40})([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", r"\1[REDACTED_EMAIL]", text)
    return text


def redact_data(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {redact_text(k): redact_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_data(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_data(v) for v in value)
    return value


def limit_lines(text, max_lines):
    value = redact_text(text)
    lines = value.splitlines()
    try:
        limit = int(max_lines)
    except Exception:
        limit = 200
    if len(lines) <= limit:
        return value
    return "\n".join(lines[:limit]) + f"\n\n[Output limited. {len(lines)-limit} lines omitted.]"


def safe_limit_text(text, max_chars):
    value = redact_text(text)
    try:
        limit = int(max_chars)
    except Exception:
        limit = 20000
    if limit <= 0:
        limit = 20000
    if len(value) <= limit:
        return value
    omitted = len(value) - limit
    return value[:limit].rstrip() + f"\n\n[Output limited. {omitted} characters omitted.]"


def limit_data(value, max_chars):
    if isinstance(value, str):
        return safe_limit_text(value, max_chars)
    if isinstance(value, dict):
        return {safe_limit_text(k, 500): limit_data(v, max_chars) for k, v in value.items()}
    if isinstance(value, list):
        return [limit_data(v, max_chars) for v in value]
    if isinstance(value, tuple):
        return tuple(limit_data(v, max_chars) for v in value)
    return value


def screenshot_redact_text(value):
    text = redact_text(value)
    try:
        user = getpass.getuser()
        if user:
            text = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(user)}(?![A-Za-z0-9_.-])", "[USER]", text)
    except Exception:
        pass
    try:
        hostnames = {socket.gethostname()}
        for host in list(hostnames):
            if host and host not in {"localhost", "localhost.localdomain"}:
                text = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(host)}(?![A-Za-z0-9_.-])", "[HOST]", text)
    except Exception:
        pass
    text = re.sub(r"/home/[^/\s:;]+", "/home/[USER]", text)
    text = re.sub(r'''(?i)\b(?:https?|ftp|ssh|git)://[^\s\'"<>]+''', "[URL_REDACTED]", text)
    text = re.sub(r"(?i)\b(?:git@|hg@|svn@)[^\s:]+:[^\s]+", "[REPO_REDACTED]", text)
    text = re.sub(r"(?i)\b(?:http_proxy|https_proxy|ftp_proxy|all_proxy|no_proxy|proxy)\s*=\s*[^\s]+", lambda m: m.group(0).split("=", 1)[0] + "=[REDACTED]" if "=" in m.group(0) else "proxy=[REDACTED]", text)
    text = re.sub(r"(?i)\b(nameserver|DNS Servers?|Current DNS Server)\s*[:=]?\s*((?:\d{1,3}\.){3}\d{1,3})", r"\1 [IP_REDACTED]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_REDACTED]", text)
    text = re.sub(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b", "[IP_REDACTED]", text)
    text = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "[MAC_REDACTED]", text)
    text = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "[UUID_REDACTED]", text)
    text = re.sub(r"(?i)\b(serial|uuid|wwn|machine-id|duid|id_serial|device id|id_path)\s*[:=]?\s*[A-Za-z0-9._:-]{8,}", r"\1 [DEVICE_ID_REDACTED]", text)
    def _interface_redact(match):
        label = match.group(1)
        token = match.group(2)
        if token.lower() in {"detection", "details", "status", "review", "readiness", "summary"}:
            return match.group(0)
        return label + " [INTERFACE_REDACTED]"
    text = re.sub(r"(?i)\b(interface|dev|ifname)\s+([a-zA-Z0-9_.:-]{2,})", _interface_redact, text)
    text = re.sub(r"(?i)\b(deb|deb-src)\s+\[?[^\n]*", r"\1 [APT_SOURCE_REDACTED]", text)
    return text


def screenshot_redact_data(value):
    if isinstance(value, str):
        return screenshot_redact_text(value)
    if isinstance(value, dict):
        return {screenshot_redact_text(k): screenshot_redact_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [screenshot_redact_data(v) for v in value]
    if isinstance(value, tuple):
        return tuple(screenshot_redact_data(v) for v in value)
    return value


def clamp_score(value):
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return 0


def severity_label(severity):
    labels = {"good": "OK", "warn": "Review", "bad": "Attention", "info": "Info", "critical": "Critical", "unknown": "Unknown"}
    return labels.get(severity, "Info")


def severity_color(severity):
    return {"good": GREEN, "warn": YELLOW, "bad": RED, "critical": RED, "info": BLUE, "unknown": MUTED}.get(severity, BLUE)
