from flask import Flask, render_template
from flask_socketio import SocketIO
from bottle import static_file, template
import os

templateDir = os.path.dirname(__file__)
appFlask = Flask(__name__, template_folder=templateDir)
appFlask.config['SECRET_KEY'] = 'securekim'
socketio = SocketIO(appFlask)
socketio.init_appFlask(appFlask, cors_allowed_origins="*")

@appFlask.route('/')
def sessions():
    return render_template("testSocketIO_flask.html")
    #return static_file("testSocketIO_flask.html", root=os.path.dirname(__file__))

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@socketio.on('reqMsg')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('recMsg', json)
    socketio.emit('broadcasting', "broadcasting", broadcast=True)

if __name__ == '__main__':
    socketio.run(appFlask, host='0.0.0.0', port=8080)