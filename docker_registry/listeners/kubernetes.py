# -*- coding: utf-8 -*-
"""
docker_registry.listeners.kubernetes
~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a listener for registering tagged images with Kubernetes

"""

import logging
import json


import requests
from docker_registry.lib.listener import BaseListener
from .. import storage

logger = logging.getLogger(__name__)
store = storage.load()


class Listener(BaseListener):
    url = "http://localhost:8080/api"
    name_prefix = "localhost"
    authorization = ""

    def __init__(self, cfg=None, signals=None):
        if cfg.url is not None:
            self.url = cfg.url
        self.url.strip('/')
        super(Listener, self).__init__(cfg, signals)

    def tag_created(self, sender, namespace, repository, tag, value, **extra):
        logger.debug("[kubernetes] namespace={0}; repository={1} tag={2} value={3}".format(namespace, repository, tag, value))
        try:
            if tag != value:
                store.put_content(store.tag_path(namespace, repository, tag), value)
            data = store.get_content(store.image_json_path(value))
            image = json.loads(data)
            self._post_repository_binding(namespace, repository, tag, value, image)
        except:
            logger.exception("unable to update repository")

    def _post_repository_binding(self, namespace, repository, tag, image_id, image):
        url = '{0}/v1beta1/imagesByRepository'.format(self.url)
        params = {"sync": "true"}
        headers = {'Authorization': self.authorization}

        name = '{0}/{1}/{2}'.format(self.name_prefix, namespace, repository).strip('/')
        body = {
            "repositoryName": name,
            "image": {
                "id": image_id,
                "reference": image_id,
                "metadata": image,
            },
            "tags": [{
                tag: image_id,
            }]
        }
        logger.debug("saving\n"+json.dumps(body))

        resp = requests.post(url, params=params, verify=True, headers=headers, data=json.dumps(body))
        if resp.status_code == 404:
            logger.debug('kubernetes#_post_repository_binding: no such repository')
            return False
        if resp.status_code != 200:
            logger.debug('kubernetes#_post_repository_binding: update returns status {0}\n{1}'.format(
                resp.status_code,
                resp.text,
            ))
            return False
        return True
