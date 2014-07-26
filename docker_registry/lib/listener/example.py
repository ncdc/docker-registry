# -*- coding: utf-8 -*-

"""An example listener implementation
"""

import logging

from . import BaseListener

logger = logging.getLogger(__name__)


class Listener (BaseListener):
    def repository_created(
            self, sender, namespace, repository, value, **extra):
        logger.debug("[listen] namespace={0}; repository={1}".format(
            namespace, repository))

    def repository_updated(
            self, sender, namespace, repository, value, **extra):
        logger.debug("[listen] namespace={0}; repository={1}".format(
            namespace, repository))

    def repository_deleted(
            self, sender, namespace, repository, **extra):
        logger.debug("[listen] namespace={0}; repository={1}".format(
            namespace, repository))

    def tag_created(
            self, sender, namespace, repository, tag, value, **extra):
        logger.debug(
            "[listen] namespace={0}; repository={1} tag={2} value={3}".format(
                namespace, repository, tag, value))

    def tag_deleted(
            self, sender, namespace, repository, tag, **extra):
        logger.debug("[listen] namespace={0}; repository={1} tag={2}".format(
            namespace, repository, tag))
