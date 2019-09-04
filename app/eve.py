# -*- coding: utf-8 -*-
import base64

import requests

from jose import jwt

from app import config, exceptions

_config = config.get_config()


class Aura(object):
    issuer = 'login.eveonline.com'
    login_url = 'https://{}'.format(issuer)
    esi_url = 'https://esi.evetech.net/latest'
    image_url = 'https://imageserver.eveonline.com/Type/{type_id}_{width}.png'
    character_portrat_url = 'https://imageserver.eveonline.com/Character/{character_id}_{width}.jpg'

    @classmethod
    def create_for_public(cls):
        return cls()

    @classmethod
    def create_for_auth(cls, auth_code):
        return cls(auth_code=auth_code)

    @classmethod
    def create_with_character(cls, character):
        return cls(character=character)

    @classmethod
    def get_type_image_url(cls, type_id, width):
        return cls.image_url.format(**{'type_id': type_id, 'width': width})

    @classmethod
    def get_character_portrat(cls, character_id, width):
        return cls.character_portrat_url.format(**{'character_id': character_id, 'width': width})

    def __init__(self, character=None, auth_code=None):
        self.character = character
        self.auth_code = auth_code

    @property
    def public_headers(self):
        return {
            'Content-Type': 'application/json',
        }

    @property
    def access_headers(self):
        return {
            'Authorization': 'Bearer {}'.format(self.character.account.access_token),
        }

    @property
    def secure_headers(self):
        user_pass = '{}:{}'.format(_config.EVE_CLIENT_ID, _config.EVE_SECRET_KEY)
        basic_auth = base64.urlsafe_b64encode(user_pass.encode('utf-8')).decode()
        auth_header = 'Basic {}'.format(basic_auth)
        return {
            'Authorization': auth_header,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'login.eveonline.com',
        }

    def refresh_token(self):
        sso_response = requests.post(
            '{}/v2/oauth/token'.format(self.login_url),
            data={'grant_type': 'refresh_token', 'refresh_token': self.character.account.refresh_token},
            headers=self.secure_headers,
        )
        if sso_response.status_code == 200:
            data = sso_response.json()
            self.character.account.update_tokens({
                'access_token': data['access_token'],
                'refresh_token': data['refresh_token'],
                'access_token_expires': data['expires_in'],
            })
            return
        raise exceptions.EVEAuthorizationFailed('Could not authorized EVE: {}'.format(sso_response.text))

    def get_account(self):
        sso_response = requests.post(
            '{}/v2/oauth/token'.format(self.login_url),
            data={'grant_type': 'authorization_code', 'code': self.auth_code},
            headers=self.secure_headers,
        )
        if sso_response.status_code == 200:
            data = sso_response.json()
            return {
                'access_token': data['access_token'],
                'refresh_token': data['refresh_token'],
                'access_token_expires': data['expires_in'],
            }
        raise exceptions.EVEAuthorizationFailed('Could not authorized EVE: {}'.format(sso_response.text))

    def get_solar_system(self, solar_system_id):
        url = '{}/universe/systems/{}/'.format(self.esi_url, solar_system_id)
        solar_system_data = self.__get_public_url(url)
        return {
            'system_id': solar_system_data['system_id'],
            'system_name': solar_system_data['name']
        }

    def get_planet(self, planet_id):
        url = '{}/universe/planets/{}/'.format(self.esi_url, planet_id)
        response = requests.get(url, headers=self.public_headers)
        if response.status_code == 200:
            planet_data = response.json()
            planet = {
                'planet_id': planet_data['planet_id'],
                'planet_type_id': planet_data['type_id'],
                'planet_name': planet_data['name']
            }
            return planet
        raise exceptions.EVEConnectionFailed('Could not connect to EVE to get planet: {}'.format(response.text))

    def get_character(self, access_token):
        jwk_set_url = '{}/oauth/jwks'.format(self.login_url)
        res = requests.get(jwk_set_url)
        data = res.json()
        try:
            jwk_sets = data['keys']
        except KeyError as ex:
            raise exceptions.EVEAuthorizationFailed('Could not authorized EVE: {}'.format(ex))
        jwk_set = next((item for item in jwk_sets if item['alg'] == 'RS256'))
        decoded = jwt.decode(
            access_token,
            jwk_set,
            algorithms=jwk_set['alg'],
            issuer=self.issuer
        )
        return {
            'character_id': decoded['sub'].split(':')[2],
            'name': decoded['name'],
            'owner_hash': decoded['owner'],
        }

    def __get_public_url(self, url):
        response = requests.get(url, headers=self.public_headers)
        if response.status_code == 200:
            return response.json()
        raise exceptions.EVEConnectionFailed('Could not connect to EVE: {}'.format(response.text))

    def __post_public_url(self, url, data):
        response = requests.post(url, headers=self.public_headers, data=data)
        if response.status_code == 200:
            return response.json()
        raise exceptions.EVEConnectionFailed('Could not connect to EVE: {}'.format(response.text))

    def __get_with_refresh(self, url):
        response = requests.get(url, headers=self.access_headers)
        if response.status_code == 200:
            return response.json()
        if response.status_code == 403:
            self.refresh_token()
            response = requests.get(url, headers=self.access_headers)
            if response.status_code == 200:
                return response.json()
        raise exceptions.EVEConnectionFailed('Could not connect to EVE to get character planets: {}'.format(response.text))

    def get_character_planets(self):
        url = '{}/characters/{}/planets/'.format(self.esi_url, self.character.character_id)
        return self.__get_with_refresh(url)

    def get_colony(self, planet_id):
        url = '{}/characters/{}/planets/{}'.format(self.esi_url, self.character.character_id, planet_id)
        return self.__get_with_refresh(url)

    def get_type_id(self, type_name):
        url = '{}/search/?categories=inventory_type&search={}&strict=true'.format(self.esi_url, type_name.replace(' ', '%20'))
        type_data = self.__get_public_url(url)
        return {'type_id': type_data['inventory_type']}

    def get_types_id(self, types_names):
        url = '{}/universe/ids'.format(self.esi_url)
        types_data = self.__post_public_url(url, types_names)
        return types_data['inventory_types']

    def get_schematic_name(self, schematic_id):
        url = '{}/universe/schematics/{}'.format(self.esi_url, schematic_id)
        schematic_data = self.__get_public_url(url)
        return schematic_data['schematic_name']
