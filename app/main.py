from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, URL

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    website = StringField('Website', validators=[URL()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'gg'  # Redirect to this route if user is not logged in

class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Simulated user database
users = {'vivek': User(id='vivek')}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route("/")
def h():
    return render_template('about.html')

@app.route("/ab/<name>")
@login_required
def rii(name):
    return render_template("index.html", n=name,nop=5)

@app.route("/contact.html")
def gg():
    return render_template('indexl.html')

@app.route("/login", methods=['POST'])
def hello():
    nq = request.form["usn"]
    if nq in users:  # Check if the user exists in our simulated database
        login_user(users[nq])  # Log in the user
        return redirect(url_for('rii', name=nq))  # Redirect to the protected route
    return render_template('np.html', name='10', l=nq)

@app.route("/logout")
@login_required
def logout():
    logout_user()  # Log out the user
    return redirect(url_for('h'))  # Redirect to the login page



@app.route('/request_otp', methods=['POST'])
def request_otp():
    email = request.form['email']
    return redirect(url_for('ree'))

@app.route("/reg")
def ree():
    return render_template('wel.html')


@app.route("/register", methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    otp = request.form['otp']

    # Validate and save the user information as per your logic
    # Example: Save username, email, and password in the database

    return redirect(url_for('rii', name=username))  # Redirect after registration




@app.route('/create-p', methods=['GET', 'POST'])
def create_p():
    form = UserForm()  # Create an instance of the form
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        website = form.website.data
        password = form.password.data
        print(f'Username: {username}, Email: {email}, Website: {website}, Password: {password}')
        return redirect(url_for('rii',name=username))
    return render_template('add_password.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
