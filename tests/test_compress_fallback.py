# -*- coding: utf-8 -*-

import builtins
import importlib

from flask import Flask

import app.extensions as extensions


def test_compress_fallback_when_flask_compress_import_fails(monkeypatch):
    original_import = builtins.__import__

    def _guarded_import(name, *args, **kwargs):
        if name == 'flask_compress':
            raise ModuleNotFoundError("No module named 'flask_compress'")
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as local_patch:
        local_patch.setattr(builtins, '__import__', _guarded_import)
        reloaded = importlib.reload(extensions)
        app = Flask(__name__)
        reloaded.compress.init_app(app)
        assert hasattr(reloaded.compress, 'init_app')

    # Restore normal module state for the rest of the test session.
    importlib.reload(extensions)
