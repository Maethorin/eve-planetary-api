# -*- coding: utf-8 -*-

from flask_restful import Api


def create_api(app):
    from app import resources
    api = Api(app)

    api.add_resource(resources.LoginResource, '/api/login')
    api.add_resource(resources.AdminResource, '/api/admins', '/api/admins/me')
    api.add_resource(resources.AdminConfirmResource, '/api/admins/me/confirm/<string:validate_token>')

    api.add_resource(resources.RawResourceResource, '/api/admins/me/raw-resources', '/api/admins/me/raw-resources/<int:raw_resource_id>')
    api.add_resource(resources.ProcessedMaterialResource, '/api/admins/me/processed-materials', '/api/admins/me/processed-materials/<int:processed_material_id>')
    api.add_resource(resources.RefinedCommodityResource, '/api/admins/me/refined-commodities', '/api/admins/me/refined-commodities/<int:refined_commodity_id>')
    api.add_resource(resources.ColonyCalculateResource, '/api/admins/me/colonies/<int:colony_id>/caculate', '/api/admins/me/colonies/<int:colony_id>/caculate/<int:production_target>')
    api.add_resource(resources.ColonyResource, '/api/admins/me/colonies', '/api/admins/me/colonies/<int:colony_id>')
    api.add_resource(resources.SystemColonyResource, '/api/admins/me/systems/<string:system_name>/colonies')
    api.add_resource(resources.SystemPlanetColonyResource, '/api/admins/me/systems/<string:system_name>/planets/<string:planet_name>/colonies')

    api.add_resource(resources.HealthcheckResource,
                     '/api/healthcheck',
                     '/api/healthcheck/<string:service>')


def authenticate_api(token):
    from app import config
    return token == config.get_config().API_TOKEN
