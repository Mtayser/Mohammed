from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # Replace with your database URI
db = SQLAlchemy(app)

# Define User model for SQLAlchemy


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Route to render the main page
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    else:
        return redirect(url_for('login'))


# Route to render the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('chat'))

        return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')


# Route to handle logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)