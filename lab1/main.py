# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gae_python38_app]
from flask import Flask, render_template, jsonify, Response, request, flash
from flask import send_from_directory, url_for, redirect, make_response
from google.cloud import datastore
from functools import wraps
from base64 import b64encode
import json, os, bcrypt, datetime

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__)

DS = datastore.Client()
if os.getenv('GAE_ENV','').startswith('standard'):
    ROOT = DS.key('Entities', 'root')
else:
    ROOT = DS.key('Entities', 'dev')

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = request.cookies.get('user')
        session_id = request.cookies.get('session')

        if username:
            q_key = DS.key('Users', username)
            q = DS.query(kind='Session', ancestor=q_key).fetch()

            for val in list(q):
                #print("database:"+val['Session_ID'])
                #print(session_id)
                if val['Session_ID']==session_id:
                    return func(*args, **kwargs)
        else:
            print("Please log in")
            return redirect(url_for('login'))

        print('Session Error: Unmatched user session')
        return redirect(url_for('login'))

    return wrapper

@app.route('/')
@login_required
def root():
    return send_from_directory('static','index.html')

@app.route('/login',methods=['GET', 'POST'])
def login():
    if request.method=='GET':
        return send_from_directory('static','login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = (request.form.get('password')).encode()
        key = DS.key('Users', username)
        entity = DS.query(kind='Users', ancestor=key).fetch()
        for ent in list(entity):
            if ent['Username'] == username and ent['Password'] == pwd_stretch(password, ent['Password']):
                return createSession(username)
            else:
                print("Username or password is incorrect. Please try again")
                return redirect(url_for('login'))
        else:
            print("Username or password does not match our records. Please try again")
            return redirect(url_for('login'))


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return send_from_directory('static','signup.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = (request.form.get('password')).encode()
        q_key = DS.key('Users', username)
        user = DS.query(kind='Users', ancestor=q_key)

        for ent in list(user.fetch()):
            if ent['Username']==username:
                print('Username already exists. Please choose a different username.')
                return redirect(url_for('register'))
        
        hashed = pwd_stretch(password)
        with DS.transaction():
            user = datastore.Entity(key=q_key)
            user.update({
                'Username': username,
                'Password': hashed
            })
            DS.put(user)

        if username == 'admin':
            migrate_data(username)
        
        return createSession(username)

@app.route('/logout')
def logout():
    user = request.cookies.get('user')
    session = request.cookies.get('session')
    q = DS.query(kind='Session', ancestor=DS.key('Users', user))
    for x in list(q.fetch()):
        if x['Session_ID'] == session:
            DS.delete(x.key)
            break
    print('You have been signed out.')
    expired = datetime.datetime.now() - datetime.timedelta(hours=1)
    res = make_response(redirect(url_for('login')))
    res.set_cookie('user', '', max_age=0, expires=expired, secure=True)
    res.set_cookie('session', '', max_age=0, expires=expired, secure=True)
    return res

    
@app.route('/events')
@login_required
def getEvents():
    username = request.cookies.get('user')
    p_key = DS.key('Users', username)
    vals = DS.query(kind='event', ancestor=p_key).fetch()
    return jsonify({
        'events':[{'name': v['name'], 'date': v['date']} for v in vals],
        'error': None,
    })
    
@app.route('/event', methods=['POST'])
@login_required
def addEvents():
    username = request.cookies.get('user')
    p_key = DS.key('Users', username)
    data = request.json
    entity = datastore.Entity(key=DS.key('event', parent=p_key))
    entity.update({
        'name': data['name'],
        'date': data['date'],
    })
    DS.put(entity)
    vals = DS.query(kind='event', ancestor=p_key).fetch()
    return jsonify({
        'events': [{
            'name': v['name'],
            'date': v['date'] 
            } for v in vals ],
        'error': None,
    })

def pwd_stretch(pwdStr, hash=None):
    if hash==None:
        return bcrypt.hashpw(pwdStr, bcrypt.gensalt(10))
    else:
        return bcrypt.hashpw(pwdStr, hash)

def createSession(username):
    key = DS.key('Users', username)
    session_id = b64encode(os.urandom(64)).decode()
    delta = datetime.datetime.now() + datetime.timedelta(hours=1)

    # Add session ID in Datastore under parent User key.
    session = datastore.Entity(key=DS.key('Session', parent=key))
    session.update({
        'Session_ID': session_id
    })
    DS.put(session)

    res = make_response(redirect(url_for('root')))
    res.set_cookie('user', username, max_age=(60*60), expires=delta,secure=True)
    res.set_cookie('session', session_id, max_age=(60*60), expires=delta, secure=True)
    return res

def migrate_data(username):
    if username == 'admin':
        old_key = DS.key('Entities', 'root')
        new_key = DS.key('Users', username)
        old_q = DS.query(kind='Event', ancestor=old_key)

        for val in list(old_q.fetch()):
            ent = datastore.Entity(key=DS.key('Event', parent=new_key))
            ent.update({
                'name': val['name'],
                'date': val['date']
            })
            DS.put(ent)
            DS.delete(val.key)  

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.config['SECRET_KEY'] = os.urandom(16)
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python38_app]
