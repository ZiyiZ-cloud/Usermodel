from http.client import UNAUTHORIZED
from sqlalchemy import null
from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.exceptions import Unauthorized

from model import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm


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
    try:
        userprofile = session['username']
        return render_template('index.html',userprofile=userprofile)
    except:
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
         
         try:
            user = User.register(username,password,email,first_name,last_name)
            db.session.add(user)
            db.session.commit()
            session['username'] = user.username
         
            flash('Welcome! Successfully Created Your Account!', 'primary')
            return redirect(f'/user/{user.username}')
         except:
            flash('You need to change your username/email in order to register.', 'danger')
            return render_template('register.html', form = form)
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
            flash(f'Welcome Back, {user.username}!','info')
            session['username']=user.username
            return redirect(f'/user/{user.username}') 
        else:
            form.username.errors = ['Invlaid username/password.']
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    
    session.pop('username')
    flash('Goodbye!','info')
    return redirect('/')

@app.route('/user/<username>')
def secret_page(username):
    try:
        if username == session['username']:
            user = User.query.get(username)
            feedback = Feedback.query.all()
            return render_template('userprofile.html',user=user,feedback=feedback,userprofile = username)
    except:
        flash('You Need To Log In First.','danger')
        return redirect('/login')
    
@app.route('/user/<username>/delete', methods=['POST'])
def delete_user(username):
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        session.pop('username')
        db.session.delete(user)
        db.session.commit()
        flash('User Deleted!','success')
        return redirect('/')
    return redirect(f'/user/{username}')

  
@app.route('/feedbacks', methods=['GET','POST'])
def feedback_page():
    if 'username' not in session:
        flash('Please log in first!','danger')
        return redirect('/login')
    userprofile = session['username']
    form = FeedbackForm()
    feedback = Feedback.query.all()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_post = Feedback(title=title,content=content,username=session['username'])
        db.session.add(new_post)
        db.session.commit()
        flash('Feedback Created!', 'success')
        return redirect('/feedbacks')
        
    return render_template('feedback.html', form = form,userprofile = userprofile,feedback=feedback)
   
@app.route('/feedbacks/<int:id>', methods=['POST'])
def delete_feedback(id):
    """Delete feedback"""
    feedback = Feedback.query.get_or_404(id)
    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback Deleted!','success')
        return redirect('/feedbacks')
    flash("You don't have permission to do that!")
    return redirect('/feedbacks')

@app.route('/feedbacks/<int:id>/edit', methods=['GET','POST'])
def edit_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    form = FeedbackForm(obj = feedback)
    if feedback.username ==session['username']:
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            
            db.session.commit()
            return redirect('/feedbacks')
        else:
            return render_template('feedbackedit.html',form = form,feedback = feedback)
        
    
        
           
        
        