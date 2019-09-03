# -*- coding: utf-8 -*-

from flask_restful import Api


def create_api(app):
    from app import resources
    api = Api(app)

    api.add_resource(resources.LoginResource, '/api/login')
    api.add_resource(resources.AdminResource, '/api/admins', '/api/admins/me')
    api.add_resource(resources.AdminAccount, '/api/admins/me/accounts', '/api/admins/me/accounts/<int:account_id>')
    api.add_resource(resources.AdminConfirmResource, '/api/admins/me/confirm/<string:validate_token>')

    api.add_resource(resources.AdminAccountCharacterColony, '/api/admins/me/accounts/<int:account_id>/characters/<int:character_id>/colonies', '/api/admins/me/accounts/<int:account_id>/characters/<int:character_id>/colonies/<int:colony_id>')

    api.add_resource(resources.RawResourceResource, '/api/admins/me/raw-resources', '/api/admins/me/raw-resources/<int:raw_resource_id>')
    api.add_resource(resources.ProcessedMaterialResource, '/api/admins/me/processed-materials', '/api/admins/me/processed-materials/<int:processed_material_id>')
    api.add_resource(resources.RefinedCommodityResource, '/api/admins/me/refined-commodities', '/api/admins/me/refined-commodities/<int:refined_commodity_id>')

    api.add_resource(resources.HealthcheckResource,
                     '/api/healthcheck',
                     '/api/healthcheck/<string:service>')


def authenticate_api(token):
    from app import config
    return token == config.get_config().API_TOKEN
