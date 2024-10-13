#This is the initial code only for reference

# from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
# from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, Email, URL

# class UserForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     email = StringField('Email', validators=[DataRequired(), Email()])
#     website = StringField('Website', validators=[URL()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Submit')

# app = Flask(__name__)
# app.secret_key = 'your_secret_key_here'

# # Set up Flask-Login
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'gg'  # Redirect to this route if user is not logged in

# class User(UserMixin):
#     def __init__(self, id):
#         self.id = id

# # Simulated user database
# users = {'vivek': User(id='vivek')}

# @login_manager.user_loader
# def load_user(user_id):
#     return users.get(user_id)

# @app.route("/")
# def h():
#     return render_template('about.html')

# @app.route("/ab/<name>")
# @login_required
# def rii(name):
#     return render_template("index.html", n=name,nop=5)

# @app.route("/contact.html")
# def gg():
#     return render_template('indexl.html')

# @app.route("/login", methods=['POST'])
# def hello():
#     nq = request.form["usn"]
#     if nq in users:  # Check if the user exists in our simulated database
#         login_user(users[nq])  # Log in the user
#         return redirect(url_for('rii', name=nq))  # Redirect to the protected route
#     return render_template('np.html', name='10', l=nq)

# @app.route("/logout")
# @login_required
# def logout():
#     logout_user()  # Log out the user
#     return redirect(url_for('h'))  # Redirect to the login page



# @app.route('/request_otp', methods=['POST'])
# def request_otp():
#     email = request.form['email']
#     return redirect(url_for('ree'))

# @app.route("/reg")
# def ree():
#     return render_template('wel.html')


# @app.route("/register", methods=['POST'])
# def register():
#     username = request.form['username']
#     password = request.form['password']
#     otp = request.form['otp']

#     # Validate and save the user information as per your logic
#     # Example: Save username, email, and password in the database

#     return redirect(url_for('rii', name=username))  # Redirect after registration




# @app.route('/create-p', methods=['GET', 'POST'])
# def create_p():
#     form = UserForm()  # Create an instance of the form
#     if form.validate_on_submit():
#         username = form.username.data
#         email = form.email.data
#         website = form.website.data
#         password = form.password.data
#         print(f'Username: {username}, Email: {email}, Website: {website}, Password: {password}')
#         return redirect(url_for('rii',name=username))
#     return render_template('add_password.html', form=form)


# if __name__ == "__main__":
#     app.run(debug=True)





from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from database_operations import user_auth
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect users to login page if not authenticated

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        """Fetch user by ID from your database."""
        user = user_auth.get_user_by_id(user_id)
        if user:
            return User(id=user['id'], username=user['username'])
        return None

@login_manager.user_loader
def load_user(user_id):
    """Loads user from the session using user ID."""
    return User.get(user_id)

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
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            user = user_auth.verify_login(username, password)
            login_user(User(id=user['id'], username=user['username']))  # Log in the user
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
@login_required  # User must be logged in to access this route
def dashboard():
    return render_template('index.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log out the user
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



@app.route("/create-p", methods=['GET', 'POST'])
@login_required
def create_p():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        website = form.website.data
        password = form.password.data
        # Implement password creation logic here (e.g., save to database)
        print(f'Username: {username}, Email: {email}, Website: {website}, Password: {password}')
        flash('Password entry created successfully.', 'success')
        return redirect(url_for('rii', name=username))
    return render_template('add_password.html', form=form)




# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)




