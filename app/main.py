from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,EmailField
from wtforms.validators import DataRequired, Length, EqualTo
from database_operations import user_auth
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from database_operations import connect
from database_operations.user_auth import User, UserAuth,PasswordVerificationFailedError,UserNotFoundError
from wtforms.validators import DataRequired, Email
from database_operations.password_vault import PasswordVault, Password
from dotenv import load_dotenv
import os

load_dotenv("app/database_operations/.env")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect users to login page if not authenticated


c=connect.Connection()
c.connect()
u = UserAuth(c.get_collection())
p=PasswordVault(c.get_collection())

# User model for Flask-Login
class LoginUser(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        user = u.get_user_by_id(user_id)  # Replace with your actual data source
        if user is None:
            print(f"No user found with ID: {user_id}")
            return None  # Or handle this case as appropriate

        print(f"Retrieved user data: {user}")  # Inspect the returned user data
        return LoginUser(id=user.get('id'), username=user.get('username', 'Unknown'))

@login_manager.user_loader
def load_user(user_id):
    """Loads user from the session using user ID."""
    return LoginUser.get(user_id)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email=EmailField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    website = StringField('Website', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Routes
@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Route triggered")
    form = LoginForm()
    
    if request.method == 'POST':
        print("Form data received")
        
    if form.validate_on_submit():
        print("Form validated")
        username = form.username.data
        password = form.password.data

        try:
            print(f"Verified username: {username}")
            user = u.verify_user_login(username, password)
            login_user(LoginUser(id=user['id'], username=user['username']))  # Log in the user
            return redirect(url_for('dashboard'))
        except PasswordVerificationFailedError:
            flash('Invalid password. Please try again.', 'danger')
        except UserNotFoundError:
            flash('Username not found. Please register or try again.', 'danger')
    else:
        if request.method == 'POST':
            print("Form validation failed")
        
    return render_template('loginpage.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    print("hi")
    if request.method == 'POST':
        print("Form data received")
        

    if form.validate_on_submit():
        print("bye")
        username = form.username.data
        email = form.email.data
        password = form.password.data
        print(username)

        try:
            u.add_user(User(username, email, password))
            print("add")
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))
        except user_auth.UsernameNotAvailableError:
            flash('Username is already taken. Please choose a different one.', 'danger')
        except Exception as e:
            flash(f'An error occurred during registration: {e}', 'danger')

    else:
        # Print errors if form validation fails
        print(f'Form errors: {form.errors}')  # Add this line to log form errors

    return render_template('registerpage.html', form=form)

@app.route('/dashboard')
@login_required  # User must be logged in to access this route
def dashboard():
    print(current_user.username)
    print(p.retrieve_all_passwords(current_user.username))
    return render_template('password.html', username=current_user.username, passwords = p.retrieve_all_passwords(current_user.username))

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log out the user
    PasswordVault.clear_encryption_key()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route("/add-password", methods=['GET', 'POST'])
@login_required
def create_p():
    form = UserForm()
    if request.method == 'POST':
        print("Form data received")

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        website = form.website.data
        password1 = form.password.data
        # Implement password creation logic here (e.g., save to database)
        print(f'Username: {username}, Email: {email}, Website: {website}, Password: {password1}')
        p.add_password(current_user.username,Password(username,website,password1)) 
        flash('Password entry created successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_password.html', form=form)

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)