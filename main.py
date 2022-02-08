#!/usr/bin/env python
# this is just a test string for git

import os
#from pprint import pprint
from flask import Flask, render_template,redirect, url_for, request, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'myauth.db')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


class User(UserMixin, db.Model):
  __tablename__= 'users'
  id = db.Column(db.Integer, primary_key = True)
  email = db.Column(db.String(100), unique=True)
  password = db.Column(db.String(100))
  name = db.Column(db.String(100))
  def __init__(self,email,password,name):
    self.email = email
    self.password = password
    self.name = name


@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))



@app.route('/')
def index():
   if not os.path.exists(os.path.join(basedir,'myauth.db')):
     db.create_all()
   return render_template('index.html')
@app.route('/login')
def login():
   return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
   email = request.form.get('email')
   password = request.form.get('password')
   if request.form.get('remember'):
      remember = True
   else:
      remember = False
   print ("remember=", remember)
   user = User.query.filter_by(email=email).first()
   if not user or not check_password_hash(user.password,password):
      flash('Please check your login details and try again', category='error')
      return redirect(url_for('login'))
   login_user(user, remember)
   return redirect(url_for('profile'))

#   return render_template('profile.html')
@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('index'))

@app.route('/signup')
def signup():
   return render_template('signup.html')
@app.route('/signup', methods=['POST'])
def signup_post():
   email = request.form.get('email')
   password = request.form.get('password')
   name = request.form.get('name')
   user = User.query.filter_by(email=email).first()
   if user:
      return redirect(url_for('signup'))
   new_user = User(email,generate_password_hash(password,method='sha256'),name)
   db.session.add(new_user)
   db.session.commit()
   return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
   return render_template('profile.html',name=current_user.name)

if __name__ == "__main__":
  app.run(host='0.0.0.0',debug=True)
  