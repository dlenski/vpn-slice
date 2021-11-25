import os
from signal import SIGTERM

from .provider import ProcessProvider


class PythonOsProcessProvider(ProcessProvider):
    def kill(self, pid, signal=SIGTERM):
        os.kill(pid, signal)

    def pid(self):
        return os.getpid()

    def is_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
