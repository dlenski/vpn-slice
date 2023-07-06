import os
import os.path
from shutil import which


def get_executable(*paths, fallback_to_which=True):
    bn = os.path.basename(paths[0])
    for path in paths:
        if os.access(path, os.X_OK):
            return path
    if fallback_to_which:
        path = which(bn)
        if path and os.access(path, os.X_OK):
            return path
    raise OSError('cannot find executable {} (tried {}{})'.format(
        bn, ', '.join(paths), (', $PATH' if fallback_to_which else '')))


class slurpy(dict):
    """Quacks like a dict and an object"""
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError as e:
            raise AttributeError(*e.args)

    def __setattr__(self, k, v):
        self[k] = v
