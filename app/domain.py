# -*- coding: utf-8 -*-
import random
import string
import time
from datetime import timedelta, datetime

from jose import jwt
from passlib.apps import custom_app_context

from app import repositories, exceptions, config as config_module, mr_postman, eve

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
            'id': self.id
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

    def __repr__(self):
        return self.name

    @property
    def name(self):
        return self.instance.name

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
        as_dict.update({'email': self.email, 'name': self.name})
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

    def create_account(self, account_data):
        account_data['user_id'] = self.id
        return Account.create_new(account_data)

    def get_item(self, payload, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__get_raw_resource(kwargs['raw_resource_id'])
        if self.entity_key == 'processed_material':
            return self.__get_processed_material(kwargs['processed_material_id'])
        if self.entity_key == 'refined_commodity':
            return self.__get_refined_commodity(kwargs['refined_commodity_id'])
        if self.entity_key == 'colony':
            if payload.get('calculate') is not None:
                return self.__calculate_account_character_colony_production_target(kwargs['account_id'], kwargs['character_id'], kwargs['colony_id'], production_target=payload.get('production_target'))
            return self.__get_account_character_colony(kwargs['account_id'], kwargs['character_id'], kwargs['colony_id'])
        return None

    def get_list(self, payload, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__get_raw_resources()
        if self.entity_key == 'processed_material':
            return self.__get_processed_materials()
        if self.entity_key == 'refined_commodity':
            return self.__get_refined_commodities()
        if self.entity_key == 'colony':
            return self.__get_account_character_colonies(**kwargs)
        if self.entity_key == 'account':
            return self.__get_accounts()
        return []

    def create_new_entity(self, dict_data, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__create_raw_resource(dict_data)
        if self.entity_key == 'processed_material':
            return self.__create_processed_material(dict_data)
        if self.entity_key == 'refined_commodity':
            return self.__create_refined_commodity(dict_data)
        if self.entity_key == 'colony':
            return self.__create_account_character_colonies(kwargs['account_id'], kwargs['character_id'])
        return None

    def update_entity(self, dict_data, **kwargs):
        if not self.is_admin:
            raise exceptions.WhoDaHellYouThinkYouAre('Not now!')
        if self.entity_key == 'raw_resource':
            return self.__update_raw_resource(kwargs['raw_resource_id'], dict_data)
        if self.entity_key == 'processed_material':
            return self.__update_processed_material(kwargs['processed_material_id'], dict_data)
        if self.entity_key == 'refined_commodity':
            return self.__update_refined_commodity(kwargs['refined_commodity_id'], dict_data)
        return None

    def __get_raw_resources(self):
        return RawResource.list_all()
    
    def __get_raw_resource(self, raw_resource_id):
        return RawResource.create_with_id(raw_resource_id)

    def __create_raw_resource(self, dict_data):
        return RawResource.create_new(dict_data)

    def __update_raw_resource(self, raw_resource_id, dict_data):
        raw_resource = RawResource.create_with_id(raw_resource_id)
        raw_resource.update_me(dict_data)
        return raw_resource

    def __get_processed_materials(self):
        return ProcessedMaterial.list_all()

    def __get_processed_material(self, processed_material_id):
        return ProcessedMaterial.create_with_id(processed_material_id)

    def __create_processed_material(self, dict_data):
        return ProcessedMaterial.create_new(dict_data)

    def __update_processed_material(self, processed_material_id, dict_data):
        processed_material = ProcessedMaterial.create_with_id(processed_material_id)
        processed_material.update_me(dict_data)
        return processed_material

    def __get_refined_commodities(self):
        return RefinedCommodity.list_all()

    def __get_refined_commodity(self, refined_commodity_id):
        return RefinedCommodity.create_with_id(refined_commodity_id)

    def __create_refined_commodity(self, dict_data):
        return RefinedCommodity.create_new(dict_data)

    def __update_refined_commodity(self, refined_commodity_id, dict_data):
        refined_commodity = RefinedCommodity.create_with_id(refined_commodity_id)
        refined_commodity.update_me(dict_data)
        return refined_commodity

    def __get_accounts(self):
        return Account.list_user_accounts(self.id)

    def __get_account(self, account_id):
        return Account.create_with_user_and_id(self.id, account_id)

    def __get_account_character_colonies(self, account_id, character_id):
        account = self.__get_account(account_id)
        character = account.get_character(character_id)
        return character.colonies

    def __get_account_character_colony(self, account_id, character_id, colony_id):
        account = self.__get_account(account_id)
        character = account.get_character(character_id)
        return character.get_colony(colony_id)

    def __create_account_character_colonies(self, account_id, character_id):
        account = self.__get_account(account_id)
        return account.create_character_colonies(character_id)

    def __calculate_account_character_colony_production_target(self, account_id, character_id, colony_id, production_target=None):
        colony = self.__get_account_character_colony(account_id, character_id, colony_id)
        return colony.calculate_raw_resources_extraction(production_target)


class Account(Entity):
    repository = repositories.Account

    @classmethod
    def list_user_accounts(cls, user_id):
        return [cls(instance) for instance in cls.repository.list_with_filter(user_id=user_id)]

    @classmethod
    def create_with_user_and_id(cls, user_id, account_id):
        return cls(cls.repository.get_with_filter(id=account_id, user_id=user_id))

    @classmethod
    def create_new(cls, dict_data):
        aura = eve.Aura.create_for_auth(dict_data.pop('auth_code'))
        account_info = aura.get_account()
        account_info['access_token_expires'] = datetime.fromtimestamp(
            time.time() + account_info['access_token_expires'],
        )
        dict_data.update(account_info)
        account = super(Account, cls).create_new(dict_data)
        account.create_new_character(aura.get_character(account_info['access_token']))
        return account

    def __init__(self, instance):
        super(Account, self).__init__(instance)
        self.__characters = None

    def __repr__(self):
        return self.username

    @property
    def username(self):
        return self.instance.username

    @property
    def access_token(self):
        return self.instance.access_token

    @property
    def refresh_token(self):
        return self.instance.refresh_token

    @property
    def access_token_expires(self):
        return self.instance.access_token_expires

    @property
    def characters(self):
        if self.__characters is None:
            self.__characters = [Character.create_with_account(instance, self) for instance in self.instance.characters]
        return self.__characters

    def get_character(self, character_id):
        return [_character for _character in self.characters if _character.id == character_id][0]

    def create_new_character(self, character_info):
        character_info['account_id'] = self.id
        Character.create_new(character_info)

    def create_character_colonies(self, character_id):
        character = self.get_character(character_id)
        character.create_colonies_from_eve()
        return character

    def update_tokens(self, token_data):
        token_data['access_token_expires'] = datetime.fromtimestamp(time.time() + token_data['access_token_expires'])
        self.update_me(dict_data=token_data)

    def as_dict(self, compact=False):
        as_dict = super(Account, self).as_dict(compact)
        as_dict.update({
            'username': self.username,
            'access_token_expires': self.access_token_expires.strftime('%Y-%m-%d %H:%M'),
            'characters': [character.as_dict(compact) for character in self.characters]
        })
        return as_dict


class Character(Entity):
    repository = repositories.Character

    @classmethod
    def create_with_account(cls, instance, account):
        return cls(instance, account)

    def __init__(self, instance, account=None):
        super(Character, self).__init__(instance)
        self.__colonies = None
        self.__account = account

    def __repr__(self):
        return self.name

    @property
    def name(self):
        return self.instance.name

    @property
    def character_id(self):
        return self.instance.character_id

    @property
    def account(self):
        if self.__account is None:
            self.__account = Account.create_with_instance(self.instance.account)
        return self.__account

    @property
    def colonies(self):
        if self.__colonies is None:
            self.__colonies = [Colony.create_with_character(instance, self) for instance in self.instance.colonies]
        return self.__colonies

    def get_colony(self, colony_id):
        return [colony for colony in self.colonies if colony.id == colony_id][0]

    def create_colonies_from_eve(self):
        aura = eve.Aura.create_with_character(self)
        character_planets = {{'upgrade_level': 4, 'num_pins': 7, 'solar_system_id': 30005308, 'owner_id': 90832503, 'last_update': '2019-09-02T09:46:20Z', 'planet_type': 'oceanic', 'planet_id': 40335748}}
        # for character_planet in aura.get_character_planets():
        for character_planet in character_planets:
            # solar_system = aura.get_solar_system(character_planet['solar_system_id'])
            solar_system = {'system_id': 30005308, 'system_name': 'Jufvitte'}
            # planet = aura.get_planet(character_planet['planet_id'])
            planet = {'planet_name': 'Jufvitte IX', 'planet_id': 40335748, 'planet_type_id': 2014}
            # colony_data = aura.get_colony(character_planet['planet_id'])

            colony_data = {
                'pins': [
                    {'latitude': 0.698319551306, 'contents': [{'amount': 4005, 'type_id': 2319}], 'longitude': 5.14793946887, 'pin_id': 1031275339546, 'type_id': 2542},
                    {'latitude': 0.713551961614, 'longitude': 5.02560058358, 'pin_id': 1027825608864, 'type_id': 2525},
                    {
                        'extractor_details': {
                            'product_type_id': 2268,
                            'cycle_time': 1800,
                            'heads': [
                                {'latitude': 0.872196928005, 'longitude': 5.19956185029, 'head_id': 0},
                                {'latitude': 0.870772395826, 'longitude': 5.16207878149, 'head_id': 1},
                                {'latitude': 0.678887742845, 'longitude': 5.25793378853, 'head_id': 2},
                                {'latitude': 0.831544067174, 'longitude': 5.19451271739, 'head_id': 3},
                                {'latitude': 0.842302098815, 'longitude': 5.15228835616, 'head_id': 4},
                                {'latitude': 0.808919036053, 'longitude': 5.15911908006, 'head_id': 5},
                                {'latitude': 0.657428541077, 'longitude': 5.29748646519, 'head_id': 6},
                                {'latitude': 0.7065854645, 'longitude': 5.22873677112, 'head_id': 7},
                                {'latitude': 0.775435544216, 'longitude': 5.16910258904, 'head_id': 8},
                                {'latitude': 0.745321706019, 'longitude': 5.18526295195, 'head_id': 9}
                            ],
                            'qty_per_cycle': 5200,
                            'head_radius': 0.0136296823621
                        }, 'latitude': 0.894761096558,
                        'pin_id': 1027959862978,
                        'expiry_time': '2019-09-03T16:46:20Z',
                        'last_cycle_start': '2019-09-02T09:46:20Z',
                        'longitude': 5.52693211772,
                        'install_time': '2019-09-02T09:46:20Z',
                        'type_id': 3063
                    },
                    {'latitude': 0.712387405109, 'contents': [{'amount': 305310, 'type_id': 2073}, {'amount': 349572, 'type_id': 2268}, {'amount': 1127, 'type_id': 2393}, {'amount': 405, 'type_id': 2319}], 'pin_id': 1027825706917, 'last_cycle_start': '2019-08-30T04:56:34Z', 'longitude': 5.15126936226, 'type_id': 2535},
                    {'latitude': 0.712935975025, 'contents': [{'amount': 3000, 'type_id': 2073}], 'pin_id': 1027825706918, 'type_id': 2490, 'last_cycle_start': '2019-09-02T09:39:33Z', 'longitude': 5.13290451836, 'schematic_id': 131},
                    {'latitude': 0.712018078817, 'contents': [{'amount': 3000, 'type_id': 2268}], 'pin_id': 1027825706919, 'type_id': 2490, 'last_cycle_start': '2019-09-02T09:19:37Z', 'longitude': 5.16993681213, 'schematic_id': 121},
                    {'latitude': 0.724671672065, 'contents': [{'amount': 40, 'type_id': 2393}, {'amount': 20, 'type_id': 3645}], 'pin_id': 1027825706922, 'type_id': 2485, 'last_cycle_start': '2019-09-02T08:49:37Z', 'longitude': 5.15147699191, 'schematic_id': 86}
                ]
            }

            colony_data.update({
                'character_id': self.id,
                'planet_type': character_planet['planet_type']
            })
            colony_data.update(planet)
            colony_data.update(solar_system)
            Colony.create_new(colony_data)

    def as_dict(self, compact=False):
        as_dict = super(Character, self).as_dict(compact)
        as_dict.update({
            'name': self.name
        })
        if compact:
            return as_dict

        as_dict.update({
            'colonies': [colony.as_dict() for colony in self.colonies]
        })
        return as_dict


class RawResource(Entity):
    repository = repositories.RawResource

    def __init__(self, instance):
        super(RawResource, self).__init__(instance)
        self.__processed_material = None
        self.__colonies = None

    def __repr__(self):
        return self.name

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
        as_dict.update({
            'name': self.name,
            'image_url': eve.Aura.get_type_image_url(self.instance.type_id, 64)
        })
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

    def __repr__(self):
        return self.name

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
            'name': self.name,
            'image_url': eve.Aura.get_type_image_url(self.instance.type_id, 64),
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

    def __repr__(self):
        return self.name

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
            'name': self.name,
            'image_url': eve.Aura.get_type_image_url(self.instance.type_id, 64),
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

    def set_quantity(self, value):
        self.instance.quantity = value
        self.save()

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

    def set_quantity(self, value):
        self.instance.quantity = value
        self.save()

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

    def set_quantity(self, value):
        self.instance.quantity = value
        self.save()

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

    @classmethod
    def create_with_character(cls, instance, character):
        return cls(instance, character)

    def __init__(self, instance, character=None):
        super(Colony, self).__init__(instance)
        self.__raw_resources = None
        self.__processed_materials = None
        self.__refined_commodities = None
        self.__calcule_result = None
        self.__character = character

    def __repr__(self):
        return '{} {}'.format(self.system_name, self.planet_name)

    @property
    def system_name(self):
        return self.instance.system_name

    @property
    def planet_name(self):
        return self.instance.planet_name

    @property
    def planet_type(self):
        return self.instance.planet_type

    @property
    def character(self):
        if self.__character is None:
            self.__character = Character.create_with_instance(self.instance.character)
        return self.__character

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

    def update_me(self, dict_data):
        for refined_commodity_data in dict_data['refined_commodities']:
            colony_refined_commodity = [_colony_refined_commodity for _colony_refined_commodity in self.refined_commodities if _colony_refined_commodity.refined_commodity.id == refined_commodity_data['refined_commodity_id']][0]
            colony_refined_commodity.set_quantity(refined_commodity_data['quantity'])
            for processed_material_data in refined_commodity_data['processed_materials']:
                colony_processed_material = [_colony_processed_material for _colony_processed_material in self.processed_materials if _colony_processed_material.processed_material.id == processed_material_data['processed_material_id']][0]
                colony_processed_material.set_quantity(processed_material_data['quantity'])
                colony_raw_resource = [_colony_raw_resource for _colony_raw_resource in self.raw_resources if _colony_raw_resource.raw_resource.id == processed_material_data['raw_resource']['raw_resource_id']][0]
                colony_raw_resource.set_quantity(processed_material_data['raw_resource']['quantity'])

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
        else:
            production_target = int(production_target)
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
            'planet_name': self.planet_name
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
