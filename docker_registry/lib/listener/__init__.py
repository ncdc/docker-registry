# -*- coding: utf-8 -*-

"""Listener implementation
"""

import importlib
import logging
import traceback

from .. import config
from .. import signals

logger = logging.getLogger(__name__)
__all__ = ['load']
_listeners = None  # hold a references to the listener


class BaseListener (object):
    """A listener to changes in the registry

    """
    def __init__(self, cfg=None, signals=None):
        for key in dir(signals):
            if hasattr(self, key) and callable(getattr(self, key)):
                getattr(signals, key).connect(getattr(self, key))


def load():
    """Initializes all Listener instances according to the configuration."""

    global _listeners
    if _listeners is not None:
        return
    _listeners = []

    cfg = config.load()
    if cfg.listeners is None:
        return
    for listener in cfg.listeners:
        kind = listener.backend.lower()
        logger.debug("Registering listener {0}".format(kind))

        if kind == "example":
            from . import example
            _listeners.append(example.Listener(listener, signals))
            continue
        try:
            module = importlib.import_module(kind)
        except ImportError:
            logger.exception("unable to load module {0!r}".format(kind))
            pass
        else:
            _listeners.append(module.Listener(listener, signals))
            continue
        raise NotImplementedError('Unknown listener type {0!r}'.format(kind))
