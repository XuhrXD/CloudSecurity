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
from flask import Flask, render_template, jsonify, Response, request
from flask import send_from_directory
from google.cloud import datastore
import json, os

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__)

DS = datastore.Client()
if os.getenv('GAE_ENV','').startswith('standard'):
    ROOT = DS.key('Entities', 'root')
else:
    ROOT = DS.key('Entities', 'dev')

@app.route('/events')
def getEvents():
    vals = DS.query(kind='event', ancestor=ROOT).fetch()
    return jsonify({
        'events':[{'name': v['name'], 'date': v['date']} for v in vals],
        'error': None,
    })
    
@app.route('/event', methods=['POST'])
def addEvents():
    data = request.json
    entity = datastore.Entity(key=DS.key('event', parent=ROOT))
    entity.update({
        'name': data['name'],
        'date': data['date'],
    })
    DS.put(entity)
    vals = DS.query(kind='event', ancestor=ROOT).fetch()
    return jsonify({
        'events': [{
            'name': v['name'],
            'date': v['date'] 
            } for v in vals ],
        'error': None,
    })

#@app.route('/event/<int:event_id>', methods=['DELETE'])
#def delEvents():
#   DS.delete(DS.key('event', event_id, parent=ROOT))
#    return ""

@app.route('/')
def root():
    return send_from_directory('static','index.html')


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python38_app]
