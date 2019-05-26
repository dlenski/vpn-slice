import os
import os.path
from shutil import which


def get_executable(path):
    path = which(os.path.basename(path)) or path
    if not os.access(path, os.X_OK):
        raise OSError('cannot execute {}'.format(path))
    return path


class slurpy(dict):
    """Quacks like a dict and an object"""
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError as e:
            raise AttributeError(*e.args)

    def __setattr__(self, k, v):
        self[k] = v
