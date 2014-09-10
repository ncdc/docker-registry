import json
import logging

import requests

from docker_registry.lib import config
import docker_registry.lib.signals
from docker_registry import storage

logger = logging.getLogger(__name__)

cfg = config.load()
store = storage.load()

openshift_url = 'http://localhost:8080/osapi'
registry_url = 'localhost:5000'

if cfg.openshift_url is not None:
    openshift_url = cfg.openshift_url

if cfg.registry_url is not None:
    registry_url = cfg.registry_url


def tag_created(sender, namespace, repository, tag, value):
    logger.debug("[openshift] namespace={0}; repository={1} tag={2} value={3}".
                 format(namespace, repository, tag, value))
    try:
        if tag != value:
            store.put_content(
                store.tag_path(namespace, repository, value), value)
        data = store.get_content(store.image_json_path(value))
        image = json.loads(data)
        _post_repository_binding(namespace, repository, tag, value, image)
    except Exception:
        logger.exception("unable to create openshift ImageRepositoryMapping")


def _post_repository_binding(namespace, repository, tag, image_id, image):
    url = '{0}/v1beta1/imageRepositoryMappings'.format(openshift_url)
    params = {"sync": "true"}
    headers = {}
    # headers = {'Authorization': self.authorization}

    name = "{0}/{1}/{2}".format(registry_url, namespace, repository).strip('/')
    ref = "{0}:{1}".format(name, image_id)
    body = {
        "kind": "ImageRepositoryMapping",
        "version": "v1beta1",
        "dockerImageRepository": name,
        "image": {
            "id": image_id,
            "dockerImageReference": ref,
            "metadata": image,
        },
        "tag": tag
    }
    logger.debug("saving\n" + json.dumps(body))

    resp = requests.post(url, params=params, verify=True, headers=headers,
                         data=json.dumps(body))

    if resp.status_code == 422:
        logger.debug('openshift#_post_repository_binding: invalid request: %s' % resp.text)
        return False

    if resp.status_code != 200:
        logger.debug('openshift#_post_repository_binding: update returns status {0}\n{1}'.  # nopep8
                     format(resp.status_code, resp.text))
        return False

    return True

docker_registry.lib.signals.tag_created.connect(tag_created)
