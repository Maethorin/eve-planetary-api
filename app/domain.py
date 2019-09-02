# -*- coding: utf-8 -*-
import random
import string
from datetime import timedelta, datetime

import jwt
from passlib.apps import custom_app_context

from app import repositories, exceptions, config as config_module, mr_postman

config = config_module.get_config()


class Entity(object):
    repository = None

    @classmethod
    def list_all(cls):
        return [cls.create_with_instance(instance) for instance in cls.repository.list_all()]

    @classmethod
    def create_new(cls, dict_data):
        try:
            return cls(cls.repository.create_from_json(dict_data))
        except cls.repository.RepositoryError as ex:
            if 'already exists' in str(ex).lower():
                raise exceptions.AlreadyExist('Entity already exists in repository')

    @classmethod
    def create_with_id(cls, entity_id):
        instance = cls.repository.get(entity_id)
        return cls.create_with_instance(instance)

    @classmethod
    def create_with_instance(cls, instance):
        if instance is None:
            raise exceptions.NotExist('Tryed to create entity with instance None. Check the stack trace to see the origin')
        return cls(instance)

    def __init__(self, instance):
        self.instance = instance
        if getattr(instance, 'id', None) is not None:
            self.id = instance.id

    def __repr__(self):
        return self.name

    @property
    def name(self):
        return self.instance.name

    def save(self):
        self.instance.save_db()

    @staticmethod
    def remove_unused_json_data_key(key, dict_data):
        if key in dict_data:
            del dict_data[key]

    def update_me(self, dict_data):
        self.instance.update_from_json(dict_data)

    def as_dict(self, compact=False):
        return {
            'id': self.id,
            'name': self.name
        }


class User(Entity):
    repository = repositories.User

    @classmethod
    def create_with_token(cls, token):
        try:
            data = jwt.decode(token, config.SECRET_KEY)
        except Exception as ex:
            return None
        if not data.get('id', None):
            return None
        return cls.create_with_id(data['id'])

    @classmethod
    def create_with_logged(cls, logged_user):
        return cls.create_with_email(logged_user['email'])

    @classmethod
    def create_for_login(cls, login_data):
        user = cls.create_with_email(login_data['username'])
        user.temp_password = login_data['password']
        return user

    @classmethod
    def create_with_email(cls, email):
        instance = cls.repository.get_by_email(email)
        return cls.create_with_instance(instance)

    @classmethod
    def create_validate_token(cls):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(40))

    @classmethod
    def create_new(cls, dict_data):
        password = dict_data.pop('password')
        password_hash = custom_app_context.encrypt(password)
        dict_data['password_hash'] = password_hash
        dict_data['validate_token'] = cls.create_validate_token()
        user = super(User, cls).create_new(dict_data)
        token_url = "{}/#!/me/confirm/{}".format(config.APP_URL, user.validate_token)
        if config.DEVELOPMENT:
            print('\nVALIDA AE DESENVOLVEDOR\n{}\n'.format(token_url))
        else:
            mr_postman.MrPostman.send_confirm_mail(user.email, token_url)
        return user

    def __init__(self, instance):
        super(User, self).__init__(instance)
        self.temp_password = None
        self.entity_key = None
        self.resource_key = None
        self.__kanbans = None
        self.__sprints = None
        self.__planned_sprints = None
        self.__teams = None
        self.__modules = None

    @property
    def email(self):
        return self.instance.email

    @property
    def confirmed(self):
        return self.instance.confirmed

    @property
    def is_admin(self):
        return self.instance.is_admin

    @property
    def validate_token(self):
        return self.instance.validate_token

    @property
    def password_hash(self):
        return self.instance.password_hash

    @property
    def is_correct(self):
        return custom_app_context.verify(self.temp_password, self.password_hash)

    def as_dict(self, compact=False):
        as_dict = super(User, self).as_dict()
        as_dict['email'] = self.email
        if compact:
            return as_dict

        as_dict.update({
            'is_admin': self.is_admin
        })
        return as_dict

    def is_validate_token_valid(self, token):
        return self.validate_token == token

    def confirm_my_register(self, token, json_data):
        if not self.is_validate_token_valid(token):
            raise exceptions.InvalidToken('You do not pass a correct token')
        self.instance.validate_token = None
        self.instance.confirmed = True

    def generate_auth_token(self, expiration=600):
        return jwt.encode({'id': self.id, 'email': self.email, 'exp': datetime.utcnow() + timedelta(minutes=expiration)}, config.SECRET_KEY, algorithm='HS256')

    def get_item(self, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__get_raw_resource(kwargs['raw_resource_id'])
        if self.entity_key == 'processed_material':
            return self.__get_processed_material(kwargs['processed_material_id'])
        if self.entity_key == 'refined_commodity':
            return self.__get_refined_commodity(kwargs['refined_commodity_id'])
        if self.entity_key == 'colony':
            if self.resource_key == 'calculate':
                return self.__calculate_colony_production_target(**kwargs)
            return self.__get_colony(kwargs['colony_id'])
        return None

    def get_list(self, payload, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__get_raw_resources_list()
        if self.entity_key == 'processed_material':
            return self.__get_processed_materials_list()
        if self.entity_key == 'refined_commodity':
            return self.__get_refined_commodities_list()
        if self.entity_key == 'colony':
            return self.__get_colonies_list(**kwargs)
        return []

    def create_new_entity(self, dict_data):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__create_raw_resource(dict_data)
        if self.entity_key == 'processed_material':
            return self.__create_processed_material(dict_data)
        if self.entity_key == 'refined_commodity':
            return self.__create_refined_commodity(dict_data)
        if self.entity_key == 'colony':
            return self.__create_colony(dict_data)
        return None

    def __get_raw_resources_list(self):
        return RawResource.list_all()
    
    def __get_raw_resource(self, raw_resource_id):
        return RawResource.create_with_id(raw_resource_id)

    def __create_raw_resource(self, dict_data):
        return RawResource.create_new(dict_data)

    def __update_raw_resource(self, raw_resource_id, dict_data):
        raw_resource = RawResource.create_with_id(raw_resource_id)
        raw_resource.update_me(dict_data)
        return raw_resource

    def __get_processed_materials_list(self):
        return ProcessedMaterial.list_all()

    def __get_processed_material(self, processed_material_id):
        return ProcessedMaterial.create_with_id(processed_material_id)

    def __create_processed_material(self, dict_data):
        return ProcessedMaterial.create_new(dict_data)

    def __update_processed_material(self, processed_material_id, dict_data):
        processed_material = ProcessedMaterial.create_with_id(processed_material_id)
        processed_material.update_me(dict_data)
        return processed_material

    def __get_refined_commodities_list(self):
        return RefinedCommodity.list_all()

    def __get_refined_commodity(self, refined_commodity_id):
        return RefinedCommodity.create_with_id(refined_commodity_id)

    def __create_refined_commodity(self, dict_data):
        return RefinedCommodity.create_new(dict_data)

    def __update_refined_commodity(self, refined_commodity_id, dict_data):
        refined_commodity = RefinedCommodity.create_with_id(refined_commodity_id)
        refined_commodity.update_me(dict_data)
        return refined_commodity

    def __get_colonies_list(self, **kwargs):
        if kwargs.get('system_name') is not None:
            if kwargs.get('planet_name') is not None:
                return Colony.list_for_system_planet(kwargs['system_name'], kwargs['planet_name'])
            return Colony.list_for_system(kwargs['system_name'])
        return Colony.list_all()

    def __get_colony(self, colony_id):
        return Colony.create_with_id(colony_id)

    def __create_colony(self, dict_data):
        return Colony.create_new(dict_data)

    def __update_colony(self, colony_id, dict_data):
        colony = Colony.create_with_id(colony_id)
        colony.update_me(dict_data)
        return colony

    def __calculate_colony_production_target(self, colony_id, production_target=None):
        colony = self.__get_colony(colony_id)
        return colony.calculate_raw_resources_extraction(production_target)


class RawResource(Entity):
    repository = repositories.RawResource

    def __init__(self, instance):
        super(RawResource, self).__init__(instance)
        self.__processed_material = None
        self.__colonies = None

    @property
    def name(self):
        return self.instance.name

    @property
    def processed_material(self):
        if self.__processed_material is None:
            self.__processed_material = ProcessedMaterial.create_with_instance(self.instance.processed_material)
        return self.__processed_material

    @property
    def colonies(self):
        return self.__colonies

    def as_dict(self, compact=False):
        as_dict = super(RawResource, self).as_dict(compact)
        if compact:
            return as_dict
        as_dict.update({
            'processed_material': self.processed_material.as_dict()
        })
        return as_dict


class ProcessedMaterial(Entity):
    repository = repositories.ProcessedMaterial

    def __init__(self, instance):
        super(ProcessedMaterial, self).__init__(instance)
        self.__input = None
        self.__colonies = None

    @property
    def name(self):
        return self.instance.name

    @property
    def input_id(self):
        return self.instance.input_id

    @property
    def input(self):
        if self.__input is None:
            self.__input = RawResource.create_with_id(self.instance.input_id)
        return self.__input

    @property
    def input_quantity(self):
        return self.instance.input_quantity

    @property
    def output_quantity(self):
        return self.instance.output_quantity

    @property
    def colonies(self):
        return self.__colonies

    def as_dict(self, compact=False):
        as_dict = super(ProcessedMaterial, self).as_dict(compact)
        as_dict.update({
            'input': self.input.as_dict(compact=True),
            'input_quantity': self.input_quantity,
            'output_quantity': self.output_quantity,
        })
        return as_dict


class RefinedCommodity(Entity):
    repository = repositories.RefinedCommodity

    def __init__(self, instance):
        super(RefinedCommodity, self).__init__(instance)
        self.__first_input = None
        self.__second_input = None
        self.__colonies = None

    @property
    def name(self):
        return self.instance.name

    @property
    def first_input(self):
        if self.__first_input is None:
            self.__first_input = ProcessedMaterial.create_with_id(self.instance.first_input_id)
        return self.__first_input

    @property
    def second_input(self):
        if self.__second_input is None:
            self.__second_input = ProcessedMaterial.create_with_id(self.instance.second_input_id)
        return self.__second_input

    @property
    def first_input_quantity(self):
        return self.instance.first_input_quantity

    @property
    def second_input_quantity(self):
        return self.instance.second_input_quantity

    @property
    def output_quantity(self):
        return self.instance.output_quantity

    @property
    def colonies(self):
        return self.__colonies

    def as_dict(self, compact=False):
        as_dict = super(RefinedCommodity, self).as_dict(compact)
        as_dict.update({
            'first_input': self.first_input.as_dict(compact),
            'first_input_quantity': self.first_input_quantity,
            'second_input': self.second_input.as_dict(compact),
            'second_input_quantity': self.second_input_quantity,
            'output_quantity': self.output_quantity,
        })
        return as_dict


class ColonyRawResource(Entity):
    repository = repositories.ColonyRawResource

    def __init__(self, instance):
        super(ColonyRawResource, self).__init__(instance)
        self.__raw_resource = None

    def __repr__(self):
        return '{}: {}'.format(self.raw_resource.name, self.quantity)

    @property
    def raw_resource(self):
        if self.__raw_resource is None:
            self.__raw_resource = RawResource.create_with_instance(self.instance.raw_resource)
        return self.__raw_resource

    @property
    def quantity(self):
        return self.instance.quantity

    def as_dict(self, compact=False):
        as_dict = {
            'raw_resource': self.raw_resource.as_dict(compact),
            'quantity': self.quantity
        }
        return as_dict


class ColonyProcessedMaterial(Entity):
    repository = repositories.ColonyProcessedMaterial

    def __init__(self, instance):
        super(ColonyProcessedMaterial, self).__init__(instance)
        self.__processed_material = None

    def __repr__(self):
        return '{}: {}'.format(self.processed_material.name, self.quantity)

    @property
    def processed_material(self):
        if self.__processed_material is None:
            self.__processed_material = ProcessedMaterial.create_with_instance(self.instance.processed_material)
        return self.__processed_material

    @property
    def quantity(self):
        return self.instance.quantity

    def as_dict(self, compact=False):
        as_dict = {
            'processed_material': self.processed_material.as_dict(compact),
            'quantity': self.quantity
        }
        return as_dict


class ColonyRefinedCommodity(Entity):
    repository = repositories.ColonyRefinedCommodity

    def __init__(self, instance):
        super(ColonyRefinedCommodity, self).__init__(instance)
        self.__refined_commodity = None

    def __repr__(self):
        return '{}: {}'.format(self.refined_commodity.name, self.quantity)

    @property
    def refined_commodity(self):
        if self.__refined_commodity is None:
            self.__refined_commodity = RefinedCommodity.create_with_instance(self.instance.refined_commodity)
        return self.__refined_commodity

    @property
    def quantity(self):
        return self.instance.quantity

    def as_dict(self, compact=False):
        as_dict = {
            'refined_commodity': self.refined_commodity.as_dict(compact),
            'quantity': self.quantity
        }
        return as_dict


class Colony(Entity):
    repository = repositories.Colony

    @classmethod
    def list_for_system(cls, system_name):
        return [cls(instance) for instance in cls.repository.find_for_system(system_name)]

    @classmethod
    def list_for_system_planet(cls, system_name, planet_name):
        return [cls(instance) for instance in cls.repository.find_for_system_planet(system_name, planet_name)]

    def __init__(self, instance):
        super(Colony, self).__init__(instance)
        self.__raw_resources = None
        self.__processed_materials = None
        self.__refined_commodities = None
        self.__calcule_result = None

    @property
    def system_name(self):
        return self.instance.system_name

    @property
    def planet_name(self):
        return self.instance.planet_name

    @property
    def player_name(self):
        return self.instance.player_name

    @property
    def raw_resources(self):
        if self.__raw_resources is None:
            return [ColonyRawResource.create_with_instance(db_raw_resource) for db_raw_resource in self.instance.raw_resources]
        return self.__raw_resources

    @property
    def processed_materials(self):
        if self.__processed_materials is None:
            return [ColonyProcessedMaterial.create_with_instance(db_processed_materials) for db_processed_materials in self.instance.processed_materials]
        return self.__processed_materials

    @property
    def refined_commodities(self):
        if self.__refined_commodities is None:
            return [ColonyRefinedCommodity.create_with_instance(db_refined_commodities) for db_refined_commodities in self.instance.refined_commodities]
        return self.__refined_commodities

    def select_raw_resource_material(self, colony_raw_resource):
        for colony_processed_material in self.processed_materials:
            if colony_processed_material.processed_material.input.id == colony_raw_resource.raw_resource.id:
                return colony_processed_material
        raise exceptions.ColonyProcessedMaterialNotFound('Check your data for invalid input')

    def select_processed_material_resource(self, colony_processed_material):
        for colony_raw_resource in self.raw_resources:
            if colony_processed_material.processed_material.input.id == colony_raw_resource.raw_resource.id:
                return colony_raw_resource
        raise exceptions.ColonyRawResourceNotFound('Check your data for invalid input')

    def __total_processed_materials_in_colony(self):
        result = []
        for colony_raw_resource in self.raw_resources:
            colony_processed_material = self.select_raw_resource_material(colony_raw_resource)
            total_processed_material = self.calculate_total_processed_material(colony_raw_resource, colony_processed_material)
            result.append(total_processed_material)
        return result

    def calculate_total_processed_material(self, colony_raw_resource, colony_processed_material):
        cicles = colony_raw_resource.quantity / colony_processed_material.processed_material.input_quantity
        processed_material_productil = cicles * colony_processed_material.processed_material.output_quantity
        return processed_material_productil + colony_processed_material.quantity

    def calculate_raw_resource(self, colony_raw_resource, colony_processed_material, production_target):
        processed_material_quantity = colony_processed_material.quantity
        if processed_material_quantity == production_target:
            return 0
        total_processed_material = self.calculate_total_processed_material(colony_raw_resource, colony_processed_material)
        needed_processed_material = production_target - total_processed_material
        cicles_needed = needed_processed_material / colony_processed_material.processed_material.output_quantity
        return cicles_needed * colony_processed_material.processed_material.input_quantity

    def calculate_raw_resources_extraction(self, production_target=None):
        if production_target is None:
            production_target = max(self.__total_processed_materials_in_colony())
        self.__calcule_result = {
            'calcule_result': [],
            'production_target': production_target
        }
        for colony_raw_resource in self.raw_resources:
            colony_processed_material = self.select_raw_resource_material(colony_raw_resource)
            raw_resource_dict = {
                'raw_resource': {'id': colony_raw_resource.raw_resource.id, 'name': colony_raw_resource.raw_resource.name, 'quantity': colony_raw_resource.quantity},
                'processed_material': {'id': colony_processed_material.processed_material.id, 'name': colony_processed_material.processed_material.name, 'quantity': colony_processed_material.quantity},
                'extraction_needed': self.calculate_raw_resource(colony_raw_resource, colony_processed_material, production_target)
            }
            self.__calcule_result['calcule_result'].append(raw_resource_dict)
        return self

    def list_processed_materials(self):
        result = []
        for colony_processed_material in self.processed_materials:
            colony_raw_processed = self.select_processed_material_resource(colony_processed_material)
            result.append({
                'processed_material_id': colony_processed_material.processed_material.id,
                'name': colony_processed_material.processed_material.name,
                'quantity': colony_processed_material.quantity,
                'raw_resource': {
                    'raw_resource_id': colony_raw_processed.raw_resource.id,
                    'name': colony_raw_processed.raw_resource.name,
                    'quantity': colony_raw_processed.quantity,
                }
            })
        return result

    def list_refined_commodity(self):
        result = []
        for colony_refined_commodity in self.refined_commodities:
            result.append({
                'refined_commodity_id': colony_refined_commodity.refined_commodity.id,
                'name': colony_refined_commodity.refined_commodity.name,
                'quantity': colony_refined_commodity.quantity,
                'processed_materials': self.list_processed_materials()
            })
        return result

    def as_dict(self, compact=False):
        as_dict = {
            'id': self.id,
            'system_name': self.system_name,
            'planet_name': self.planet_name,
            'player_name': self.player_name
        }
        if compact:
            return as_dict

        if self.__calcule_result is not None:
            as_dict.update(self.__calcule_result)
            return as_dict

        as_dict.update({
            'refined_commodities': self.list_refined_commodity()
        })
        return as_dict
