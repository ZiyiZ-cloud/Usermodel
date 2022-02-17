
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, EmailField, PasswordField
from wtforms.validators import InputRequired, Optional, URL, NumberRange, AnyOf

class RegisterForm(FlaskForm):
    
    username = StringField('Username',
                       validators = [InputRequired()])
    password = PasswordField('Password',
                         validators = [InputRequired()])
    email = EmailField('Email',
                      validators = [InputRequired()])
    first_name = StringField('First Name',
                       validators = [InputRequired()])
    last_name = StringField('Last Name',
                        validators = [InputRequired()])
    
    
    
    
class LoginForm(FlaskForm):
    
    username = StringField('Username',
                       validators = [InputRequired()])
    password = PasswordField('Password',
                         validators = [InputRequired()])
    