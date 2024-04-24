from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, URLField, validators
from wtforms.validators import EqualTo
from ..auth.validator import *

class ProfileForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True, "class": "custom-input"})
    password = PasswordField('Password', [EqualTo('password_again', message='Passwords must match')], render_kw={"class": "custom-input"})
    password_again = PasswordField('Repeat Password', render_kw={"class": "custom-input"})
    birthdate = DateField('Birth date', render_kw={"class": "custom-input"}, validators=[check_age])
    color = StringField('Favourite color', render_kw={"class": "custom-input"}, validators=[check_color])
    picture_url = URLField('Picture URL', [validators.url(), validators.optional()], render_kw={"class": "custom-input"})
    about = TextAreaField('About', render_kw={"class": "custom-input"}, validators=[check_about])
    save = SubmitField('Save changes', render_kw={"class": "button"})
