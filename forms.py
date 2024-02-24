from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, RadioField,IntegerField, DateField
from wtforms.validators import DataRequired, Email, EqualTo,InputRequired

class RegistrationForm(FlaskForm):
    name = StringField('Nome')
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Senha')
    confirm_password = PasswordField('Confirmar senha', validators=[EqualTo('password')])
    is_volunteer = BooleanField('Desejo me tornar um voluntário')
    auth_password = PasswordField('Senha de autorização para se tornar voluntário')
    submit = SubmitField('CADASTRAR')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class AddPetForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired()])
    age = IntegerField('Idade', validators=[DataRequired()])
    birthdate = DateField('Data de Nascimento', format='%Y-%m-%d', validators=[DataRequired()])
    species = StringField('Espécie', validators=[DataRequired()])
    breed = StringField('Raça', validators=[DataRequired()])
    size = StringField('Porte', validators=[DataRequired()])
    color = StringField('Cor', validators=[DataRequired()])
    temperament = StringField('Temperamento', validators=[DataRequired()])
    sex = RadioField('Sexo', choices=[('Feminino'), ('Masculino')], validators=[InputRequired()])