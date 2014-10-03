#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import setuptools
except ImportError:
    import distutils.core as setuptools

setuptools.setup(
    name  = "refcount-docker-registry-extension",
    version = "0.1",
    description = "Refcount Docker Registry Extension",
    long_description = open('./README.md').read(),
    author = "W. Trevor King",
    author_email = "TODO",
    url = "TODO",
    license = open('./LICENSE').read(),

    classifiers = [
        'Development Status :: 3 - Alpha',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License'
    ],

    entry_points = {
        'docker_registry.extensions': [
            'refcount = refcount'
        ]
    },

    install_requires=['docker-registry-core>=2,<3'],
)
