from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.ext.hybrid import hybrid_property


app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_volunteer = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def is_adotante(self):
        return not self.is_volunteer

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    species = db.Column(db.String(100), nullable=False)
    breed = db.Column(db.String(100), nullable=False)
    size = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(100), nullable=False)
    temperament = db.Column(db.String(100), nullable=False)
    sex = db.Column(db.String(100), nullable=False)

    def __init__(self, name, age, birthdate, species, breed, size, color, temperament, sex):
        self.name = name
        self.age = age
        self.birthdate = birthdate
        self.species = species
        self.breed = breed
        self.size = size
        self.color = color
        self.temperament = temperament
        self.sex = sex

class AdoptionProcess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    kit_cuidados = db.Column(db.Boolean, default=False)
    visita_marcada = db.Column(db.Date)
    entrevista_marcada = db.Column(db.Date)
    status = db.Column(db.String(50), default='Em andamento')

    animal = db.relationship('Animal', backref='adoption_processes')
    user = db.relationship('User', backref='adoption_processes')

    @property
    def animal_name(self):
        return self.animal.name if self.animal else "N/A"

    @property
    def user_name(self):
        return self.user.name if self.user else "N/A"