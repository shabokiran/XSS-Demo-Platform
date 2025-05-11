
  # app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_bcrypt import Bcrypt
from markupsafe import escape
import os
import json
import hashlib
from cryptography.fernet import Fernet
from datetime import timedelta
from markupsafe import escape  # Add this import
from flask_wtf.csrf import CSRFProtect


from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import os
import json
import hashlib
from cryptography.fernet import Fernet
from datetime import timedelta

from flask import Flask, render_template, request
from markupsafe import escape, Markup  # Explicit escaping
from flask_wtf.csrf import CSRFProtect
import secrets



app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # 64-character random key
csrf = CSRFProtect(app)

# ▼▼▼ Force escaping through context processor ▼▼▼
@app.context_processor
def inject_escape():
    return dict(escape=escape)

@app.route('/reflected', methods=['GET', 'POST'])
def reflected():
    raw_input = request.form.get('user_input', '') if request.method == 'POST' else ''
    return render_template(
        'reflected.html',
        vulnerable_output=Markup(raw_input),  # Explicitly mark as safe
        mitigated_output=escape(raw_input)    # Explicitly escape
    )

bcrypt = Bcrypt(app)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=30)

# Simulated user database
users = {'student': bcrypt.generate_password_hash("password").decode('utf-8'),
         'instructor': bcrypt.generate_password_hash("adminpass").decode('utf-8')}

key = Fernet.generate_key()
cipher = Fernet(key)



@app.after_request
def set_secure_headers(response):
    # Allow unsafe-inline temporarily for demo purposes
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and bcrypt.check_password_hash(users[username], password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.after_request
def set_secure_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.set_cookie('session', '', httponly=True, secure=True, samesite='Lax')
    return response

@app.route('/')
def index():
    return render_template('Index.html')



@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

"""
@app.route('/stored', methods=['GET', 'POST'])
def stored():
    if request.method == 'POST':
        comment = request.form['comment']
        with open('comments.txt', 'a', encoding='utf-8') as f:
            f.write(comment + "\n")
    comments = []
    if os.path.exists('comments.txt'):
        with open('comments.txt', 'r', encoding='utf-8') as f:
            comments = f.readlines()
    return render_template('stored.html', comments=comments)
"""

from markupsafe import Markup  # Add to imports

@app.route('/stored', methods=['GET', 'POST'])
def stored():
    if request.method == 'POST':
        comment = request.form['comment']
        with open('comments.txt', 'a', encoding='utf-8') as f:
            f.write(comment + "\n")
    
    comments = []
    if os.path.exists('comments.txt'):
        with open('comments.txt', 'r', encoding='utf-8') as f:
            # Mark existing comments as safe for demo purposes
            comments = [Markup(line.strip()) for line in f.readlines()]
    
    return render_template('stored.html', comments=comments)



@app.route('/dom')
def dom():
    # Temporarily disable CSP header for debugging
    response = make_response(render_template('Dom.html'))
    return response


@app.route('/crypto', methods=['GET', 'POST'])
def crypto():
    result = ''
    if request.method == 'POST':
        message = request.form['message']
        encrypted = cipher.encrypt(message.encode()).decode()
        decrypted = cipher.decrypt(encrypted.encode()).decode()
        result = f"Encrypted: {encrypted}<br>Decrypted: {decrypted}"
    return render_template('crypto.html', result=result)

@app.route('/malware')
def malware():
    return render_template('malware.html')





if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
