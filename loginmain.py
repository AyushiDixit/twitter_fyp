import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session
import re
import bcrypt

conn_str = ("Driver={ODBC Driver 17 for SQL Server};"
            "Server=DESKTOP-H17S9H6;"
            "Database=FYPtwitter;"
            "Trusted_Connection=yes;")
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

app = Flask(__name__)
app.secret_key = 'your secret key'

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password'].encode()
        cursor.execute("SELECT * FROM user_details WHERE username = ?" , (username, ))

        # Compare the hashed password
        account = cursor.fetchall()

        if account:
            stored_password = account[0][1]
            print(stored_password)
            if bcrypt.checkpw(password, stored_password):
                print("Authentication successful")
                session['logged_in'] = True
                session['username'] = account[0][0]

                if session['username'] == 'riya':
                    return redirect(url_for('adminhome'))

                return redirect(url_for('home'))



            else:
                print("Authentication failed")
        else: 
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/home')
def home():
    # Check if user is loggedin
    if 'logged_in' in session:
        # User is loggedin show them the home page
        return render_template('dashboard.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/adminhome')
def adminhome():
    msg = ''
    if session['username'] == 'riya':
        return render_template('adminHome.html', username= session['username'])
    else :
        msg = 'unauthorised access'
        return render_template('index.html', msg=msg)
        
# http://localhost:5000/python/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'logged_in' in session:
        username = session['username']
        # We need all the account info for the user so we can display it on the profile page
        cursor.execute('SELECT * FROM user_details WHERE username = ?', (username,))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/record')
def record():
    # Check if user is loggedin
    if 'logged_in' in session:
        username = session['username']
        # We need all the account info for the user so we can display it on the profile page
        cursor.execute('SELECT * FROM user_details WHERE username = ?', (username,))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('record.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:

        password = request.form['password'].encode()
        salt = bcrypt.gensalt()
        global hashed 
        hashed = bcrypt.hashpw(password, salt)

        # Create variables for easy access
        username = request.form['username']
        #password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        twit_user = request.form['twitter_user_txt']


                # Check if account exists using MySQL
        
        cursor.execute('SELECT * FROM user_details WHERE username = ?', (username,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO user_details VALUES (?, ?, ?, ?, ?)', (username, hashed, email,phone,twit_user))
            conn.commit()
            msg = 'You have successfully registered! Proceed to sign in'
            return redirect(url_for('login'))
            

    else: 
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


 