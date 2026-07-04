from .common import *
from .redaction import redact_data, redact_text

class WorkerSignals(QObject):
    result = Signal(str, object)
    error = Signal(str, str)


class CheckWorker(QRunnable):
    def __init__(self, task_id, func):
        super().__init__()
        self.task_id = task_id
        self.func = func
        self.signals = WorkerSignals()

    def run(self):
        try:
            self.signals.result.emit(self.task_id, redact_data(self.func()))
        except Exception as exc:
            self.signals.error.emit(self.task_id, redact_text(str(exc)))
