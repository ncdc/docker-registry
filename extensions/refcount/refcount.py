# -*- coding: utf-8 -*-

import json
import logging
import sys

from docker_registry.core import exceptions
from docker_registry.lib import config
import docker_registry.lib.signals
from docker_registry import storage


def tag_created(sender, namespace, repository, tag, image):
    """Update image reference data for the current tag and image

    """
    logger.debug(
        "[tag_created] namespace={0} repository={1} tag={2} image={3}".
        format(namespace, repository, tag, image))
    try:
        add_references(namespace=namespace,
                       repository=repository,
                       tag=tag,
                       image_id=image)
    except Exception as e:
        logger.exception("Error adding references: %s" % e)


def tag_deleted(sender, namespace, repository, tag, image):
    """Update image reference data for the deleted tag and image

    Removes any images that are no longer referenced by a tag.
    """
    logger.debug(
        "[tag_deleted] namespace={0} repository={1} tag={2} image={3}".
        format(namespace, repository, tag, image))
    try:
        remove_references(image)
    except Exception as e:
        logger.exception("Error removing references: %s" % e)


def extension_info_path():
    """Path where information about this extension is stored

    """
    return 'extensions/refcount'


def get_extension_info():
    """Get information about this extension

    Currently just stores a '1' to indicate that the image references have
    been initialized
    """
    try:
        info = store.get_json(extension_info_path())
    except exceptions.FileNotFoundError:
        info = {}

    return info


def init_references():
    """Initialize image reference data

    Walks all repositories and tags and initializes the image reference data
    for the entire registry.
    """
    for namespace, repository in get_repositories():
        for tag, image_id in get_tags(namespace=namespace,
                                      repository=repository):
                add_references(namespace=namespace,
                               repository=repository,
                               tag=tag,
                               image_id=image_id)
    for image_id in get_images():
        _check_references(image_id=image_id)


def get_images():
    """Iterate through images in storage

    This helper is useful for upgrades and other storage
    maintenance.  Yields image ids.
    """
    try:
        image_paths = list(
            store.list_directory(path=store.images))
    except exceptions.FileNotFoundError:
        image_paths = []
    for image_path in image_paths:
        image_id = image_path.rsplit('/', 1)[-1]
        yield image_id


def get_repositories():
    """Iterate through repositories in storage

    This helper is useful for upgrades and other storage
    maintenance.  Yields tuples:

        (namespace, repository)
    """
    try:
        namespace_paths = list(
            store.list_directory(path=store.repositories))
    except exceptions.FileNotFoundError:
        namespace_paths = []
    for namespace_path in namespace_paths:
        namespace = namespace_path.rsplit('/', 1)[-1]
        try:
            repository_paths = list(
                store.list_directory(path=namespace_path))
        except exceptions.FileNotFoundError:
            repository_paths = []
        for path in repository_paths:
            repository = path.rsplit('/', 1)[-1]
            yield (namespace, repository)


def get_tags(namespace, repository):
    """Iterate through a repository's tags

    This helper is useful for upgrades and other storage
    maintenance.  Yields tuples:

        (tag_name, image_id)
    """
    tag_path = store.tag_path(namespace, repository)
    for path in store.list_directory(tag_path):
        full_tag_name = path.split('/').pop()
        if not full_tag_name.startswith('tag_'):
            continue
        tag_name = full_tag_name[4:]
        tag_content = store.get_content(path=path)
        yield (tag_name, tag_content)


def image_references_path(image_id):
    """Path where image references are stored

    """
    return '{0}/{1}/_references'.format(store.images, image_id)


def _add_reference(image_id, descendant_id, namespace, repository,
                   tag):
    """Increment the refcount for a particular image

    Record the fact that we're needed for a particular image
    (descendant_id) which is tagged, so we know which images are safe
    to remove (e.g. any images that have no referring tags).
    """
    references_path = image_references_path(image_id=image_id)
    try:
        references = store.get_json(path=references_path)
    except exceptions.FileNotFoundError:
        references = {}
    key = json.dumps([namespace, repository, tag])
    references[key] = descendant_id
    store.put_json(path=references_path, content=references)


def _check_references(image_id):
    """Check for image references.  If orphaned, remove the image

    Checks the existence of all the descendant images that (at one
    point) referenced this image.  If any of those descendant
    images are gone (or if they are no longer tagged with the
    listed tag), then remove that entry from the references list.
    If no references remain, remove this image.
    """
    references_path = image_references_path(image_id=image_id)
    try:
        references = store.get_json(path=references_path)
    except exceptions.FileNotFoundError:
        references = {}
    changed = False
    for namespace_repository_tag, descendant_id in list(
            references.items()):
        namespace, repository, tag = json.loads(namespace_repository_tag)
        descendant_layer_path = store.image_layer_path(
            image_id=descendant_id)
        if store.exists(path=descendant_layer_path):
            tag_path = store.tag_path(
                namespace=namespace, repository=repository, tagname=tag)
            try:
                tagged_image = store.get_content(path=tag_path)
            except exceptions.FileNotFoundError:
                tagged_image = None
            if tagged_image != descendant_id:
                # the listed descendant is no longer tagged with this tag
                references.pop(namespace_repository_tag)
                changed = True
        else:
            # the listed descendant no longer exists
            references.pop(namespace_repository_tag)
            changed = True
    if changed and references:
        store.put_json(path=references_path, content=references)
    if not references:
        image_path = '{0}/{1}'.format(store.images, image_id)
        logger.info('Image {0} no longer referenced - removing'
                    .format(image_id))
        store.remove(image_path)


def add_references(namespace, repository, tag, image_id):
    """Increment ancestor refcounts

    """
    ancestry_path = store.image_ancestry_path(image_id=image_id)
    ancestry = store.get_json(path=ancestry_path)
    for id in ancestry:
        _add_reference(
            image_id=id, descendant_id=image_id, namespace=namespace,
            repository=repository, tag=tag)


def remove_references(image_id):
    """Decrement ancestor refcounts and remove orphaned images

    """
    ancestry_path = store.image_ancestry_path(image_id=image_id)
    ancestry = store.get_json(path=ancestry_path)
    for id in ancestry:
        _check_references(image_id=id)


def _apply_version_1():
    logger.info("Initializing image references")
    init_references()


def init_extension(current_version):
    """Initialize the refcount extension

    Initializes the image reference data if this is the first time this
    extension is loaded.

    Wires up the signal handlers for tag_created and tag_deleted.
    """
    info = get_extension_info()
    version = info.get('version', 0)
    if version < current_version:
        upgrade_start = version + 1
        upgrade_end = current_version + 1
        for version in range(upgrade_start, upgrade_end):
            logger.info("Applying version {0}".format(version))
            current_module = sys.modules[__name__]
            upgrader = getattr(current_module,
                               '_apply_version_{0}'.format(version))
            upgrader()

        info['version'] = current_version
        store.put_json(extension_info_path(), info)

    docker_registry.lib.signals.tag_created.connect(tag_created)
    docker_registry.lib.signals.tag_deleted.connect(tag_deleted)


#
# main entrypoint
#
CURRENT_VERSION = 1

logger = logging.getLogger(__name__)

logger.info("Loading config")
cfg = config.load()

enabled = True

if cfg.extensions is not None and cfg.extensions.refcount is not None:
    cfg = cfg.extensions.refcount
    if cfg.disabled:
        logger.info("Extension is disabled")
        enabled = False

if enabled:
    logger.info("Extension is enabled")

    store = storage.load()

    logger.info("initializing extension")
    init_extension(CURRENT_VERSION)
