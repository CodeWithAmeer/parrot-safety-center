from .common import dataclass


@dataclass
class CommandResult:
    command: str
    available: bool
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str = ""


@dataclass
class CheckDefinition:
    check_id: str
    category: str
    title: str
    description: str
    runner_function: str
    severity_mapping: dict
    score_weight: int
    role_weights: dict
    fix_guide_key: str
    safe_manual_verification_command: str
    recommended_state: str


@dataclass
class NormalizedCheckResult:
    status: str
    severity: str
    summary: str
    details: str
    evidence: str
    detected_state: str
    recommended_state: str
    next_step: str
    fix_guide_key: str
    score_impact: int
