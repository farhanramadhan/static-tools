from flask import Flask, session, redirect, url_for, escape, request, render_template
from datetime import timedelta
import mysql.connector
import hashlib

app = Flask(__name__)
app.secret_key = 'any random string'
# SESSION TIMEOUT
# app.permanent_session_lifetime = timedelta(minutes=30)

mydb = mysql.connector.connect(
   host="localhost",
   user="root",
   password="",
   database="ta2"
)

mycursor = mydb.cursor()

@app.route('/')
def index():
   if 'username' in session:
      username = session['username']
      return 'Logged in as ' + username + '<br>' + \
      "<b><a href = '/logout'>click here to log out</a></b>"
   return render_template('index.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
   if request.method == 'POST':
      username = request.form['username']
      password = request.form['password']
      # PASSWORD NOT HASHED
      # password = hashlib.md5(password.encode()).hexdigest()

      mycursor.execute("SELECT username FROM users WHERE username = %s AND password = %s", (username, password))

      user = mycursor.fetchone()

      # Username/Password Enumeration (return generic error for login)
      if user == None:
         return render_template('invalidLogin.html')

      # CREATE SESSION
      session.permanent = True
      session['username'] = user[0]

      return redirect(url_for('index'))
   return render_template('login.html')

@app.route('/register', methods = ['GET', 'POST'])
def register():
   if request.method == 'POST':
      username = request.form['username']
      password = request.form['password']

      mycursor.execute("SELECT username FROM users WHERE username = %s", (username, ), True)
      user = mycursor.fetchone()

      if user != None:
         return render_template('userExist.html')

      # CHECK PASSWORD HASH/ENCRYPT
      mycursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashlib.md5(password.encode()).hexdigest()), True)

      mydb.commit()

      return redirect(url_for('login'))
   return render_template('register.html')

@app.route('/logout')
def logout():
   # DELETE SESSION
   # session.pop('username', None)
   return redirect(url_for('index'))

if __name__ == '__main__':
   app.run()