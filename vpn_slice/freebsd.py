import os

from .posix import PosixProcessProvider


class ProcfsProvider(PosixProcessProvider):
    def pid2exe(self, pid):
        try:
            return os.readlink(f'/proc/{pid}/file')
        except OSError:
            return None

    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        try:
            return int(next(open(f'/proc/{pid}/status')).split()[3])
        except (OSError, ValueError):
            return None
