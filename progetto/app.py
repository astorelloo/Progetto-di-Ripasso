from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User
import requests
from flask_bcrypt import Bcrypt
from flask_bcrypt import generate_password_hash
#pip install Flask Flask-Login Flask-Bcrypt requests Flask-SQLAlchemy
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'key_sessione_user'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET','POST'])
def register(): 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Questo username è già in uso.")
        new_user = User(username=username, password=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', error=None)



@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):  # Confronta la password hashata
            login_user(user)
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Credenziali non valide.")



if __name__ == "__main__":
    app.run(debug=True)