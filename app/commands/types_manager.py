# -*- coding: utf-8 -*-

import click

from app import config as config_module

config = config_module.get_config()


def resgister_commands(app):

    def __update(repository):
        from app import eve
        click.echo("INITIALIZE")
        instances = repository.list_with_filter(type_id=None)
        aura = eve.Aura.create_for_public()
        for instance in instances:
            type_data = aura.get_type_id(instance.name)
            click.echo("{} {} IS TYPE_ID {}".format(repository.__class__.__name__, instance.name, type_data['type_id']))
            instance.type_id = type_data['type_id'][0]
            instance.save_db()

    @app.cli.command()
    def update_raw_resources():
        from app import repositories
        __update(repositories.RawResource)

    @app.cli.command()
    def update_processed_materials():
        from app import repositories
        __update(repositories.ProcessedMaterial)

    @app.cli.command()
    def update_refined_commodities():
        from app import repositories
        __update(repositories.RefinedCommodity)
