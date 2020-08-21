import os

from .posix import PosixProcessProvider


class ProcfsProvider(PosixProcessProvider):
    def pid2exe(self, pid):
        try:
            return os.readlink('/proc/%d/file' % pid)
        except (OSError, IOError):
            return None

    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        try:
            return int(next(open('/proc/%d/status' % pid)).split()[3])
        except (OSError, ValueError, IOError):
            return None
