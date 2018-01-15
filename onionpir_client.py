#!/usr/bin/env python2
import cherrypy
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import sys
import optparse
import os
import json
from libonionpir.shared import *
from libonionpir.constants import *
from libonionpir import clientlib
import stem.process
from stem.control import Controller
from stem.util import term
import threading
import time
from websocket_server import WebsocketServer
import yaml

config = dict()
config_file = None

class WebsocketServerWrapper():
    server = None
websocket = WebsocketServerWrapper()

def parse_options():
    """Parses command line arguments and return a dict containing all relevant
    data
    """
    commandlineoptions = None

    parser = optparse.OptionParser()

    parser.add_option("", "--port", dest="port", type="int", metavar="portnum",
                      default=8080, help="Run the server on the following port (default: 8080)")

    parser.add_option("", "--reg_host", dest="reg_host", type="string",
                      metavar="hostname", default=None,
                      help="The hostname or ip address of the registration server")

    parser.add_option("", "--reg_port", dest="reg_port", type="int",
                      metavar="portnum", default=None,
                      help="The port of the registration server")

    parser.add_option("", "--config", dest="config_file", type="string",
                      metavar="path/to/config/file.yaml", default=None,
                      help="Path to the config file")

    parser.add_option("", "--server_pk", dest="server_pk_str", type="string",
                      metavar="PUBLICKEY_OF_THE_SERVER", default=None,
                      help="Publickey of the server")

    parser.add_option("", "--disable-onion-routing", dest="onion_routing_disabled",
                      default=False, action="store_true", help="Use this only for debugging purposes!")



    # parse the arguments
    (commandlineoptions, remainingargs) = parser.parse_args()

    if commandlineoptions.config_file == None:
        print "Please specify config file (via --config)"
        sys.exit(1)

    if remainingargs:
        print "Unknown options", remainingargs
        sys.exit(1)

    return commandlineoptions


class Contact:
    def __init__(self, mail, pk, secret_in, secret_out):
        assert isinstance(pk, PublicKey) or pk is None
        self.name = mail
        self.status_msg = ""
        self.mail = mail
        self.pk = pk
        self.secret_in = secret_in
        self.secret_out = secret_out
        self.chat = list()


class WebRoot():
    @cherrypy.expose
    def index(self):
        websocket.server.send_message_to_all('{"type": "profile_update"}')
        if config['registration_successful']:
            raise cherrypy.HTTPRedirect('/chat.html')
        else:
            raise cherrypy.HTTPRedirect('/index.html')

    @cherrypy.expose
    def ws(self):
        cherrypy.log("Handler created: %s" % repr(cherrypy.request.ws_handler))

class WebAPIget():
    @cherrypy.expose
    def profile(self):
        global config
        if not config['registration_successful']:
            cherrypy.response.status = 400
            return "registration_successful = False"

        pk = config['own_sk'].public_key.encode(
            encoder=nacl.encoding.HexEncoder)

        return json.dumps({'status': 'NONE', 'username': config['username'], 'status_msg': config['status_msg'], 'own_pk': pk, 'own_mail': config['own_mail']})

    @cherrypy.expose
    def contactlist(self):
        contact_list_js = list()
        for contact in config['contact_list']:
            if isinstance(contact.pk, PublicKey):
                status_msg = contact.status_msg
                contact_pk = contact.pk.encode(encoder=nacl.encoding.HexEncoder)
                contact_online = True
            else:
                status_msg = "Friend request pending"
                contact_pk = "Public key unknown"
                contact_online = False

            contact_dd_in = "[unknown]"
            contact_dd_in_time = "-"
            if not contact.secret_in is None:
                contact_dd_in =\
                    clientlib.derive_dead_drop_id(contact.secret_in)
                contact_dd_in_time =\
                    clientlib.get_secret_renewal_time(contact.secret_in)

            contact_dd_out = "[unknown]"
            contact_dd_out_time = "-"
            if not contact.secret_out is None:
                contact_dd_out =\
                    clientlib.derive_dead_drop_id(contact.secret_out)
                contact_dd_out_time =\
                    clientlib.get_secret_renewal_time(contact.secret_out)

            contact_js = dict()
            contact_js['name'] = contact.name
            contact_js['status_msg'] = status_msg
            contact_js['id'] = contact.mail
            contact_js['pk'] = contact_pk
            contact_js['ddin'] = contact_dd_in
            contact_js['ddin_time'] = contact_dd_in_time
            contact_js['ddout'] = contact_dd_out
            contact_js['ddout_time'] = contact_dd_out_time
            contact_js['online'] = contact_online
            contact_js['chat'] = contact.chat
            contact_js['last_msg_read'] = time.time()*1000

            contact_list_js.append(contact_js)

        return json.dumps(contact_list_js)

    @cherrypy.expose
    def pir_requests(self):
        global config

        do_PIR_requests()

        websocket.server.send_message_to_all('{"type": "friendlist_update"}')
        websocket.server.send_message_to_all('{"type": "profile_update"}')

def retrieve_messages():
    global config

    messages = clientlib.recv_messages(
        config['own_sk'], config['server_pk'], config['contact_list'])

    for m in messages:
        for contact in config['contact_list']:
            if contact.mail == m[0]:
                if m[1].startswith("UPDATEUSERNAME: "):
                    contact.name = m[1][len('UPDATEUSERNAME: '):]
                    websocket.server.send_message_to_all('{"type": "friendlist_update"}')
                elif m[1].startswith("UPDATESTATUSMSG: "):
                    contact.status_msg = m[1][len('UPDATESTATUSMSG: '):]
                    websocket.server.send_message_to_all('{"type": "friendlist_update"}')
                else:
                    message = dict()
                    message["isIncoming"] = True
                    message["isAction"] = False
                    message["message"] = m[1]
                    message["time"] = time.time()*1000
                    contact.chat.insert(0, message)
                    message["friend"] = contact.mail
                    websocket.server.send_message_to_all('{"type": "friend_message", "data": '+json.dumps(message)+'}')

    save_config_file(config)

class RequestToken():
    exposed = True
    def POST(self, mail):
        global config
        return_code = clientlib.register(str(mail), config['own_sk'], config['server_pk'])
        config['own_mail'] = str(mail)
        save_config_file(config)

        if return_code == 0:
            return 'success'
        elif return_code == 1:
            return 'invalid_mail'

        return 'unknown_error'

class VerifyToken():
    exposed = True
    def POST(self, mail, token):
        global config

        return_code = clientlib.verify_token(str(mail), config['own_sk'],
                                             config['server_pk'], str(token))

        if return_code == 0:
            config['registration_successful'] = True
            save_config_file(config)

            print("Uploading public key...")
            clientlib.upload_pk(config['own_sk'], str(mail),
                                config['server_pk'])
            return 'success'
        elif return_code == 1:
            return "The registration was already completed successfully"
        elif return_code == 2:
            return "Invalid token"
        elif return_code == 3:
            return "Invalid public key"
        else:
            return 'Internal server error'

class AddFriend():
    exposed = True
    def POST(self, mail):
        global config

        (contact_pk, secret_in, secret_out) = clientlib.get_contact_data(
            config['own_sk'], config['own_mail'], str(mail), config['reg_host']+":"+str(config['reg_port']+1))

        contact_found = False
        for contact in config['contact_list']:
            if contact.mail == mail:
                contact_found = True
                contact.pk = contact_pk
                contact.secret_in = secret_in
                contact.secret_out = secret_out

        if not contact_found:
            config['contact_list'].append(
                Contact(mail, contact_pk, secret_in, secret_out))

        save_config_file(config)

        if contact_pk is None:
            print "Error fetching public key for contact"
            return '{"status": "failure", "reason": "Contact not found."}'

        print "Found public key", contact_pk.encode(encoder=nacl.encoding.HexEncoder)
        return '{"status": "success"}'

class ChangeUsername():
    exposed = True
    def POST(self, username):
        global config
        config['username'] = username
        save_config_file(config)

        for contact in config['contact_list']:
            if isinstance(contact.pk, PublicKey):
                box = Box(config['own_sk'], contact.pk)
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt("UPDATEUSERNAME: "+str(username), nonce)

                if not contact.secret_out is None:
                    clientlib.send_message(
                        config['server_pk'], contact.secret_out, ciphertext)

        return '{"status": "success"}'

class ChangeStatusMsg():
    exposed = True
    def POST(self, status):
        global config
        config['status_msg'] = status
        save_config_file(config)

        for contact in config['contact_list']:
            if isinstance(contact.pk, PublicKey):
                box = Box(config['own_sk'], contact.pk)
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt("UPDATESTATUSMSG: "+str(status), nonce)

                if not contact.secret_out is None:
                    clientlib.send_message(
                        config['server_pk'], contact.secret_out, ciphertext)

        return '{"status": "success"}'

class SendMessage():
    exposed = True
    def POST(self, contact_id, msg):
        global config

        contact_found = False
        for contact in config['contact_list']:
            if contact.mail == contact_id:
                contact_found = True

                if not isinstance(contact.pk, PublicKey):
                    print "Contact has no pk"
                    return '{"status": "failure", "reason": "Error: Friend request still pending."}'

                box = Box(config['own_sk'], contact.pk)
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(str(msg), nonce)

                if contact.secret_out is None:
                    return '{"status": "failure", "reason": "Error: Friend request still pending."}'

                print 'Sending message...'
                clientlib.send_message(
                    config['server_pk'], contact.secret_out, ciphertext)

                message = dict()
                message["isIncoming"] = False
                message["isAction"] = False
                message["message"] = str(msg)
                message["time"] = time.time()*1000
                contact.chat.insert(0, message)
                save_config_file(config)

                return '{"status": "success"}'

        if not contact_found:
            return '{"status": "failure", "reason": "Contact not found."}'


def read_config_file(commandlineoptions=None):
    global config_file

    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return yaml.load(f)
    else:
        # generate the config file for the client including the secret key
        # which must be kept secret
        config = dict()
        config['own_sk'] = PrivateKey.generate()
        config['registration_successful'] = False
        config['server_pk'] = PublicKey(
            commandlineoptions.server_pk_str.decode('hex'))
        config['contact_list'] = list()
        config['username'] = "Demo user"
        config['status_msg'] = "Testing OnionPIR..."
        save_config_file(config)
        return config

def save_config_file(config):
    global config_file

    with open(config_file, 'w') as f:
        f.write(yaml.dump(config, default_flow_style=False))

def do_PIR_requests():
    global config

    for contact in config['contact_list']:
        print "querying for contact", contact.name

        (contact_pk, secret_in, secret_out) = clientlib.get_contact_data(
            config['own_sk'], config['own_mail'], contact.mail, config['reg_host']+":"+str(config['reg_host']+1))

        if contact_pk is None:
            print "Error fetching public key", contact.mail
        elif contact_pk == contact.pk:
            if contact.secret_in is None:
                contact.secret_in = secret_in
            if contact.secret_out is None:
                contact.secret_out = secret_out
        else:
            print "[WARNING] Public key of contact CHANGED"

        save_config_file(config)


def main():
    """main function with high level control flow"""
    global config, config_file

    commandlineoptions = parse_options()
    config_file = commandlineoptions.config_file

    if not os.path.exists(config_file) and commandlineoptions.server_pk_str is None:
        print "Please specify the public key of the server (via --server_pk)"
        sys.exit(1)

    config = read_config_file(commandlineoptions)

    if not 'reg_host' in config:
        if commandlineoptions.reg_host == None:
            print "Please specify the address of the registration server (via --reg_host)"
            sys.exit(1)
        else:
            config['reg_host'] = commandlineoptions.reg_host

    if commandlineoptions.reg_port is not None:
        config['reg_port'] = commandlineoptions.reg_port
    elif 'reg_port' not in config:
        config['reg_port'] = DEFAULT_REG_SERVER_PORT

    if not 'tor_socks_port' in config:
        config['tor_socks_port'] = TOR_SOCKS_PORT+commandlineoptions.port%10

    if not 'tor_control_port' in config:
        config['tor_control_port'] = TOR_CONTROL_PORT+commandlineoptions.port%10

    save_config_file(config)

    def print_bootstrap_lines(line):
      if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))

    if commandlineoptions.onion_routing_disabled:
        stemController = "tor_disabled"
    else:
        stemController = None
        try:
            stemController = Controller.from_port(port=config['tor_control_port'])
            stemController.authenticate()
            print "Tor is already running..."
        except Exception as e:
            print e
            print "Starting Tor..."

            tor_config = {
                'ControlPort': str(config['tor_control_port']),
                'SocksPort': str(config['tor_socks_port']),
                'DataDirectory': 'tor_data_dir_'+str(commandlineoptions.port)
            }

            tor_process = stem.process.launch_tor_with_config(
              config = tor_config,
              init_msg_handler = print_bootstrap_lines,
            )

            stemController = Controller.from_port(port=config['tor_control_port'])

    clientlib.setup(stemController, config['reg_host'], config['reg_port'],
                    config['tor_socks_port'], config['tor_control_port'])


    def set_interval(func, sec):
        def func_wrapper():
            set_interval(func, sec)
            func()
        t = threading.Timer(sec, func_wrapper)
        t.start()
        return t

    set_interval(retrieve_messages, 1)


    print "[INFO] Starting the webserver... http://127.0.0.1:" + str(commandlineoptions.port) + "/"
    #class WSThread(threading.Thread):
    #    def run(self):
    #        websocket.server.run_forever()
    #WSThread().start()

    # CherryPy
    script_dir = os.path.dirname(os.path.realpath(__file__))
    serve_dir = os.path.abspath(os.path.normpath(
        script_dir + '/' + HTTP_STATIC_DIR))

    cherrypy.tree.mount(RequestToken(), '/api/register/request_token', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })
    cherrypy.tree.mount(VerifyToken(), '/api/register/verify_token', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })
    cherrypy.tree.mount(AddFriend(), '/api/post/friend_request', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })
    cherrypy.tree.mount(ChangeUsername(), '/api/post/username', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })
    cherrypy.tree.mount(ChangeStatusMsg(), '/api/post/statusmessage', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })
    cherrypy.tree.mount(SendMessage(), '/api/post/message', {
        '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() }
    })

    cherrypy.tree.mount(WebAPIget(), '/api/get', {'/': {}})

    cherrypy.tree.mount(WebRoot(), '', config={
        '/': {
            'log.screen': False,
            'tools.staticdir.on': True,
            'tools.staticdir.dir': "",
            'tools.staticdir.root': serve_dir,
            'tools.response_headers.on': True,
            'tools.response_headers.headers': [
                ('X-Frame-options', 'deny'),
                ('X-XSS-Protection', '1; mode=block'),
                ('X-Content-Type-Options', 'nosniff')
            ]
        }
    })

    # comment the following line to show logs from the webserver
    cherrypy.log.screen = None

    cherrypy.config.update({'server.socket_port': commandlineoptions.port})
    cherrypy.engine.start()

    # WebSocket
    websocket.server = WebsocketServer(commandlineoptions.port+1, host='0.0.0.0')
    websocket.server.run_forever()

    print('exiting...')
    os.system('kill $PPID')

if __name__ == '__main__':
    assert STORAGE_REGISTRATION_DIR[-1] == '/'
    assert STORAGE_PIR_DIR[-1] == '/'
    assert HTTP_STATIC_DIR[-1] == '/'
    assert Box.NONCE_SIZE == NONCE_BYTES

    main()
