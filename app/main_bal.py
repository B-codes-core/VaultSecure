from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from database_operations import user_auth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

# Routes
@app.route('/')
def home():
    return render_template('about.html')  # HTML file should be in templates folder

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            user_auth.verify_login(username, password)
            return redirect(url_for('dashboard'))
        except user_auth.PasswordVerificationError:
            flash('Invalid password. Please try again.', 'danger')
        except user_auth.UserNotFoundError:
            flash('Username not found. Please register or try again.', 'danger')
    return render_template('indexl.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            user_auth.add_user(username, password)
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))
        except user_auth.UsernameNotAvailableError:
            flash('Username is already taken. Please choose a different one.', 'danger')
    return render_template('wel.html', form=form)

@app.route('/dashboard')
def dashboard():
    # Placeholder for dashboard logic, which you'll handle
    return render_template('index.html')

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
