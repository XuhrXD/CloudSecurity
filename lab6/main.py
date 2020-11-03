from flask import Flask, request, render_template
from os.path import join, dirname
from dotenv import load_dotenv
import os, psycopg2
import json

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

user = os.getenv('POSTGRES_USER')
db = os.getenv('POSTGRES_DATABASE')
secret = os.getenv('POSTGRES_PASSWORD')
host = os.getenv('POSTGRES_HOST')

app = Flask(__name__)

@app.route('/', defaults={'path': '/'}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def root(path):
    c_path = request.path
    print('CURRENT PATH: {}'.format(c_path))
    count_path(c_path)
    return display_paths()

def count_path(path):
    sql = """INSERT INTO pathcount (path, count)
                VALUES (%s, 1)
             ON CONFLICT (path) DO UPDATE
                SET count = pathcount.count + 1
             RETURNING count;"""
    conn = None
    
    try:
        conn = psycopg2.connect(host=host ,database=db, user=user, password=secret)
        cur = conn.cursor()
        cur.execute(sql, (path,))
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

def display_paths():
    sql = """SELECT path, count FROM pathcount ORDER BY path"""
    conn = None

    try:
        conn = psycopg2.connect(host=host ,database=db, user=user, password=secret)
        cur = conn.cursor()
        cur.execute(sql)
        row_headers=[x[0] for x in cur.description] #this will extract row headers
        rv = cur.fetchall()
        json_data=[]
        for result in rv:
            json_data.append(dict(zip(row_headers,result)))
        path_json = json.dumps(json_data)
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

    return render_template('index.html', data=path_json)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8080')


