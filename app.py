from http.client import UNAUTHORIZED
from sqlalchemy import null
from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.exceptions import Unauthorized

from model import connect_db, db, User
from forms import RegisterForm, LoginForm


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql:///cakes'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = True
app.config["SECRET_KEY"] = 'abc123'
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config.update(dict(
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key"
))

connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)

@app.route('/')
def home_page():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register_page():
    
    #if logged in already, direct page to user profile
    if "username" in session:
        return redirect(f"/user/{session['username']}")
    
    
    form = RegisterForm()
    
    if form.validate_on_submit():
         username = form.username.data
         password = form.password.data
         email = form.email.data
         first_name = form.first_name.data
         last_name = form.last_name.data
         
         new_user = User.register(username,password,email,first_name,last_name)
         db.session.add(new_user)
         db.session.commit()
         session['username'] = new_user.username
         
         flash('Welcome! Successfully Created Your Account!')
         return redirect(f'/user/{user.username}')
     
    return render_template('register.html', form = form)


@app.route('/login', methods=['GET','POST'])
def login_page():
    
    #if logged in already, direct page to user profile
    if "username" in session:
        return redirect(f"/user/{session['username']}")
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username=form.username.data
        password = form.password.data
        
        user = User.authenticate(username,password)
        
        if user:
            flash(f'Welcome Back, {user.username}!')
            session['username']=user.username
            return redirect(f'/user/{user.username}') 
        else:
            form.username.errors = ['Invlaid username/password.']
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    
    session.pop('username')
    flash('Goodbye!')
    return redirect('/')

@app.route('/user/<username>')
def secret_page(username):
    try:
        if username == session['username']:
            user = User.query.get(username)
            return render_template('userprofile.html',user=user)
    except:
        flash('You Need To Log In First.')
        return redirect('/login')

   