# -*- coding: utf-8 -*-

from sqlalchemy import exc, text, or_, and_
from sqlalchemy.orm import backref

from app import database, config as config_module

config = config_module.get_config()
db = database.AppRepository.db


class AbstractModel(object):
    class NotExist(Exception):
        pass

    class RepositoryError(Exception):
        pass

    @classmethod
    def create_from_json(cls, json_data):
        try:
            instance = cls()
            instance.set_values(json_data)
            instance.save_db()
            return instance
        except exc.IntegrityError as ex:
            raise cls.RepositoryError(str(ex))

    @classmethod
    def list_with_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()

    @classmethod
    def list_all(cls):
        return cls.query.all()

    @classmethod
    def get_with_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).one_or_none()

    @classmethod
    def get(cls, item_id):
        item = cls.query.get(item_id)
        if not item:
            raise cls.NotExist
        else:
            return item

    @classmethod
    def rollback_db(cls):
        db.session.rollback()

    def save_db(self):
        db.session.add(self)
        db.session.flush()
        db.session.refresh(self)

    def delete_db(self):
        try:
            db.session.delete(self)
            db.session.flush()
        except exc.IntegrityError as ex:
            raise self.RepositoryError(str(ex))

    def update_from_json(self, json_data):
        try:
            self.set_values(json_data)
            self.save_db()
            return self
        except exc.IntegrityError as ex:
            raise self.RepositoryError(str(ex))

    def set_values(self, json_data):
        for key, value in json_data.items():
            setattr(self, key, json_data.get(key, getattr(self, key)))


class User(db.Model, AbstractModel):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    validate_token = db.Column(db.String)
    confirmed = db.Column(db.Boolean, nullable=False, default=False, server_default='FALSE')
    name = db.Column(db.String)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, server_default='FALSE')

    @classmethod
    def get_by_email(cls, email):
        return cls.get_with_filter(email=email)


class RawResource(db.Model, AbstractModel):
    __tablename__ = 'raw_resources'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    colonies = db.relationship("ColonyRawResource", back_populates='raw_resource')


class ProcessedMaterial(db.Model, AbstractModel):
    __tablename__ = 'processed_materials'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    input_id = db.Column(db.Integer, db.ForeignKey('raw_resources.id'), nullable=False)
    input = db.relationship("RawResource", backref=backref("processed_material", uselist=False), lazy='joined')
    input_quantity = db.Column(db.Integer, nullable=False, default=3000, server_default='3000')
    output_quantity = db.Column(db.Integer, nullable=False, default=20, server_default='20')
    colonies = db.relationship("ColonyProcessedMaterial", back_populates='processed_material')


class RefinedCommodity(db.Model, AbstractModel):
    __tablename__ = 'refined_commodities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    first_input_id = db.Column(db.Integer, db.ForeignKey('processed_materials.id'), nullable=False)
    first_input = db.relationship("ProcessedMaterial", foreign_keys=[first_input_id], backref=backref("first_refined_commodity", uselist=False), lazy='joined')
    first_input_quantity = db.Column(db.Integer, nullable=False, default=40, server_default='40')
    second_input_id = db.Column(db.Integer, db.ForeignKey('processed_materials.id'), nullable=False)
    second_input = db.relationship("ProcessedMaterial", foreign_keys=[second_input_id], backref=backref("second_refined_commodity", uselist=False), lazy='joined')
    second_input_quantity = db.Column(db.Integer, nullable=False, default=40, server_default='40')
    output_quantity = db.Column(db.Integer, nullable=False, default=5, server_default='5')
    colonies = db.relationship("ColonyRefinedCommodity", back_populates='refined_commodity')


class Colony(db.Model, AbstractModel):
    __tablename__ = 'colonies'
    id = db.Column(db.Integer, primary_key=True)
    system_name = db.Column(db.String, nullable=False)
    planet_name = db.Column(db.String, nullable=False)
    player_name = db.Column(db.String, nullable=False)
    raw_resources = db.relationship("ColonyRawResource", back_populates='colony')
    processed_materials = db.relationship("ColonyProcessedMaterial", back_populates='colony')
    refined_commodities = db.relationship("ColonyRefinedCommodity", back_populates='colony')

    @classmethod
    def find_for_system(cls, system_name):
        return cls.list_with_filter(system_name=system_name)

    @classmethod
    def find_for_system_planet(cls, system_name, planet_name):
        return cls.list_with_filter(system_name=system_name, planet_name=planet_name)


class ColonyRawResource(db.Model, AbstractModel):
    __tablename__ = 'colonies_raw_resources'
    raw_resource_id = db.Column(db.Integer, db.ForeignKey('raw_resources.id'), primary_key=True)
    raw_resource = db.relationship("RawResource", back_populates='colonies')

    colony_id = db.Column(db.Integer, db.ForeignKey('colonies.id'), primary_key=True)
    colony = db.relationship("Colony", back_populates='raw_resources')

    quantity = db.Column(db.Integer, nullable=False, default=0)


class ColonyProcessedMaterial(db.Model, AbstractModel):
    __tablename__ = 'colonies_processed_materials'
    processed_material_id = db.Column(db.Integer, db.ForeignKey('processed_materials.id'), primary_key=True)
    processed_material = db.relationship("ProcessedMaterial", back_populates='colonies')

    colony_id = db.Column(db.Integer, db.ForeignKey('colonies.id'), primary_key=True)
    colony = db.relationship("Colony", back_populates='processed_materials')

    quantity = db.Column(db.Integer, nullable=False, default=0)


class ColonyRefinedCommodity(db.Model, AbstractModel):
    __tablename__ = 'colonies_refined_commodities'
    refined_commodity_id = db.Column(db.Integer, db.ForeignKey('refined_commodities.id'), primary_key=True)
    refined_commodity = db.relationship("RefinedCommodity", back_populates='colonies')

    colony_id = db.Column(db.Integer, db.ForeignKey('colonies.id'), primary_key=True)
    colony = db.relationship("Colony", back_populates='refined_commodities')

    quantity = db.Column(db.Integer, nullable=False, default=0)
