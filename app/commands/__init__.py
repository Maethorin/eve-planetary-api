# -*- coding: utf-8 -*-

from app.commands import types_manager


def register(web_app):
    types_manager.resgister_commands(web_app)
