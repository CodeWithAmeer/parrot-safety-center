from .common import *
from .models import CommandResult
from .redaction import redact_text, safe_limit_text

class CommandRunner:
    def exists(self, command):
        try:
            return shutil.which(command) is not None
        except Exception:
            return False

    def is_blocked(self, command):
        label = command if isinstance(command, str) else " ".join(str(x) for x in command)
        low = re.sub(r"\s+", " ", label.strip().lower())
        if not low:
            return False
        for pattern in FORBIDDEN_COMMAND_PATTERNS:
            if pattern in low:
                return True
        return False

    def run(self, command, timeout=5, shell=False):
        label = command if isinstance(command, str) else " ".join(str(x) for x in command)
        if shell:
            return CommandResult(label, False, 126, "", "", False, "Blocked: shell execution is disabled by Parrot Safety Center")
        if self.is_blocked(command):
            return CommandResult(label, False, 126, "", "", False, "Blocked by read-only safety guard")
        if not command:
            return CommandResult(label, False, 127, "", "", False, "Empty command")
        if not self.exists(command[0]):
            return CommandResult(label, False, 127, "", "", False, f"{command[0]} is not installed")
        try:
            completed = subprocess.run(command, shell=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=os.environ.copy())
            return CommandResult(label, True, completed.returncode, safe_limit_text(completed.stdout.strip(), REPORT_FIELD_LIMIT), safe_limit_text(completed.stderr.strip(), REPORT_FIELD_LIMIT), False, "")
        except subprocess.TimeoutExpired:
            return CommandResult(label, True, 124, "", "", True, "Command timed out")
        except PermissionError as exc:
            return CommandResult(label, True, 126, "", "", False, redact_text(f"Permission denied: {exc}"))
        except FileNotFoundError as exc:
            return CommandResult(label, False, 127, "", "", False, redact_text(str(exc)))
        except Exception as exc:
            return CommandResult(label, True, 1, "", "", False, redact_text(str(exc)))

    def first_output(self, commands, timeout=5):
        last = None
        for command in commands:
            result = self.run(command, timeout=timeout)
            last = result
            if result.available and (result.stdout or result.stderr or result.error):
                return result
        return last if last else CommandResult("", False, 127, "", "", False, "No commands supplied")
