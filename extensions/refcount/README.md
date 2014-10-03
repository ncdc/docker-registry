Refcount Extension
==================

This extension keeps track of images and the (namespace, repository, tag)s that point to them. When an image is no longer referenced by a tag, either directly or indirectly, it is deleted.

Installation
------------
Run `python setup.py install` from within this extension's directory. Once installed, the extension is automatically enabled, unless you explicitly disable it (see below).

Configuration
-------------
The only configuration option available is one that disables this extension. In your registry configuration file, in whatever settings flavor you're using, do this (the example below is using the `dev` settings flavor):

```
dev:
    extensions:
        refcount:
            disabled: true
```
