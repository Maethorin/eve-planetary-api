# -*- coding: utf-8 -*-


from importlib import import_module

from app import config as config_module, ClassProperty

config = config_module.get_config()


class Service(object):
    _domain = None

    class InvalidDomain(Exception):
        pass

    @ClassProperty
    def domain(cls):
        if cls._domain is None:
            raise cls.InvalidDomain('You should use a specific service implementation')
        return import_module(cls._domain)


class SampleService(Service):
    _domain = 'app.domain'


