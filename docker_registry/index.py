# -*- coding: utf-8 -*-

from docker_registry.core import compat
json = compat.json

from . import toolkit
from .lib import config
from .lib import mirroring

from .app import app  # noqa


cfg = config.load()
if cfg.index_delegate is None:
    import docker_registry.fakeindex
    cfg.index_delegate = docker_registry.fakeindex


"""Those routes are loaded only when `standalone' is enabled in the config
   file. The goal is to make the Registry working without the central Index
   It's then possible to push images from Docker without talking to any other
   entities. This module mimics the Index.
"""


@app.route('/v1/users', methods=['GET'])
@app.route('/v1/users/', methods=['GET'])
def get_users():
    return cfg.index_delegate.get_users()


@app.route('/v1/users', methods=['POST'])
@app.route('/v1/users/', methods=['POST'])
def post_users():
    return cfg.index_delegate.post_users()


@app.route('/v1/users/<username>/', methods=['PUT'])
def put_username(username):
    return cfg.index_delegate.put_username(username)


@app.route('/v1/repositories/<path:repository>', methods=['PUT'])
@app.route('/v1/repositories/<path:repository>/images',
           defaults={'images': True},
           methods=['PUT'])
@toolkit.parse_repository_name
@toolkit.requires_auth
def put_repository(namespace, repository, images=False):
    return cfg.index_delegate.put_repository(namespace, repository, images)


@app.route('/v1/repositories/<path:repository>/images', methods=['GET'])
@toolkit.parse_repository_name
@toolkit.requires_auth
@mirroring.source_lookup(index_route=True)
def get_repository_images(namespace, repository):
    return cfg.index_delegate.get_repository_images(namespace, repository)


@app.route('/v1/repositories/<path:repository>/images', methods=['DELETE'])
@toolkit.parse_repository_name
@toolkit.requires_auth
def delete_repository_images(namespace, repository):
    return cfg.index_delegate.delete_repository_images(namespace, repository)


@app.route('/v1/repositories/<path:repository>/auth', methods=['PUT'])
@toolkit.parse_repository_name
def put_repository_auth(namespace, repository):
    return cfg.index_delegate.put_repository_auth(namespace, repository)
