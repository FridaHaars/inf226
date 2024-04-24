from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField


class LoginForm(FlaskForm):
    
    username = StringField('Username', render_kw={"class": "custom-input"})
    password = PasswordField('Password', render_kw={"class": "custom-input"})
    login = SubmitField('Login', render_kw={"class": "button"})
    next = HiddenField()

