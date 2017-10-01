#!/usr/bin/env python2
import binascii
import socket
import SocketServer
import nacl.utils
from nacl.public import PublicKey, PrivateKey, Box
from email.utils import parseaddr
from libonionpir.shared import *
from libonionpir.constants import *
import os
import optparse
import json
import threading
import hashlib
import msgpack
from raidpir import raidpirlib
from raidpir import session # communication with the raidpir vendor

_global_db_write_lock = threading.Lock()
server_sk = None

def parse_options():
    """Parses command line arguments and return a dict containing all relevant
    data
    """
    commandlineoptions = None

    parser = optparse.OptionParser()

    parser.add_option("", "--port", dest="port", type="int", metavar="portnum",
                default=8900, help="Run the server on the following port (default: 8900)")

    # let's parse the args
    (commandlineoptions, remainingargs) = parser.parse_args()

    if remainingargs:
        print "Unknown options", remainingargs
        sys.exit(1)

    return commandlineoptions

def update_pir_manifest():
    raidpir_hostname = "0.0.0.0"
    raidpir_port = 8901

    print('[INFO] Creating the PIR manifest...')
    manifestdict = raidpirlib.create_manifest(
        rootdir=STORAGE_PIR_DIR,
        hashalgorithm="sha256-raw",
        block_size=4096,
        datastore_layout="nogaps",
        vendorhostname=raidpir_hostname,
        vendorport=raidpir_port)

    # open the destination file
    manifestfo = open("server_manifest.raw", 'w')

    # and write it in a safely serialized format (msgpack).
    rawmanifest = msgpack.packb(manifestdict)
    manifestfo.write(rawmanifest)
    manifestfo.close()

    try:
        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((raidpir_hostname, raidpir_port))
        session.sendmessage(sock, 'MANIFEST UPDATE')
    except:
        print "[WARNING] Could not send MANIFEST UPDATE message to PIR vendor."
    finally:
        sock.close()

    print "[INFO] Generated manifest with", manifestdict['blockcount'], 'blocks of',\
        manifestdict['blocksize'], 'Byte.'


class NonPirTCPHandler(SocketServer.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        (packet_id, data) = receive_packet(self.request)

        if packet_id == PACKET_ID_REGISTRATION_REQUEST:
            client_pk = data[0:PUBLICKEY_BYTES]
            client_nonce = data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES]
            client_mail_crypt = data[PUBLICKEY_BYTES+NONCE_BYTES:]

            box = Box(server_sk, PublicKey(client_pk))
            client_mail = box.decrypt(client_mail_crypt, client_nonce)

            client_mail = parseaddr(client_mail)[1]

            if '@' not in client_mail:
                raise UserWarning("Invalid mail address")

            client_mail_hash = hashlib.sha512(client_mail).hexdigest()

            return_code = 0

            _global_db_write_lock.acquire(True)
            try: # make sure the lock will be released again
                if os.path.isfile(STORAGE_PIR_DIR+client_mail_hash):
                    # do not allow reregistrations when the registration
                    # is already done
                    return_code = 1
                elif os.path.isfile(STORAGE_REGISTRATION_DIR+client_mail_hash):
                    # get the stored token
                    with open(STORAGE_REGISTRATION_DIR+client_mail_hash,
                              'rb') as f:
                        storage_data = f.read()

                    storage_pk = storage_data[0:PUBLICKEY_BYTES]
                    storage_token = storage_data[PUBLICKEY_BYTES:\
                                                 PUBLICKEY_BYTES+TOKEN_BYTES]

                    if not compare_bytes(storage_pk, client_pk):
                        return_code = 2
                    else:
                        client_token = storage_token
                else:
                    # only generate a token if none has been created yet
                    client_token = nacl.utils.random(TOKEN_BYTES)
                    with open(STORAGE_REGISTRATION_DIR+client_mail_hash,
                              'wb') as f:
                        f.write(client_pk + client_token)
            finally:
                _global_db_write_lock.release()

            # TODO: send token via mail
            if return_code == 0:
                print "[TOKEN] for `" + client_mail + "`: " + client_token.encode('hex')
            else:
                print "Not printing token because return_code is " +\
                      str(return_code)

            # send back the return code
            return_code_encrypted = box.encrypt(
                to_byte(return_code),
                increase_nonce(client_nonce)).ciphertext

            # we use 11 as our packed id for the response
            data = to_byte(PACKET_ID_REGISTRATION_REQUEST_ACK) +\
                   return_code_encrypted

            self.request.sendall(itonb(len(data)) + data)

        elif packet_id == PACKET_ID_REGISTRATION_TOKEN:
            client_pk = data[0:PUBLICKEY_BYTES]
            client_nonce = data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES]
            client_data_crypt = data[PUBLICKEY_BYTES+NONCE_BYTES:]

            box = Box(server_sk, PublicKey(client_pk))
            client_data = box.decrypt(client_data_crypt, client_nonce)

            client_token = client_data[0:TOKEN_BYTES]
            client_mail = client_data[TOKEN_BYTES:]
            client_mail = parseaddr(client_mail)[1]

            if '@' not in client_mail:
                raise UserWarning("Invalid mail address")

            client_mail_hash = hashlib.sha512(client_mail).hexdigest()

            return_code = 0
            return_msg = ""

            if os.path.isfile(STORAGE_PIR_DIR+client_mail_hash):
                return_code = 1
                return_msg = 'the registration was already completed successfully'

            if return_code == 0:
                _global_db_write_lock.acquire(True)
                try: # make sure the lock will be released again
                    with open(STORAGE_REGISTRATION_DIR+client_mail_hash,
                              'rb') as f:
                        storage_data = f.read()
                finally:
                    _global_db_write_lock.release()

                storage_pk = storage_data[0:PUBLICKEY_BYTES]
                storage_token = storage_data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+\
                                             TOKEN_BYTES]

                if not compare_bytes(storage_token, client_token):
                    return_code = 2
                    return_msg = 'invalid token'

                if not compare_bytes(storage_pk, client_pk):
                    return_code = 3
                    return_msg = 'wrong public key'

            if return_code == 0:
                # create the file that will be send when contacts query for an
                # email address
                _global_db_write_lock.acquire(True)
                try: # make sure the lock will be released again
                    with open(STORAGE_PIR_DIR+client_mail_hash,
                              'wb') as f:
                        f.write(client_pk)
                finally:
                    _global_db_write_lock.release()

                # update PIR manifest
                update_pir_manifest()

                # delete the file from the registration process which is not
                # needed any more
                _global_db_write_lock.acquire(True)
                try: # make sure the lock will be released again
                    os.remove(STORAGE_REGISTRATION_DIR+client_mail_hash)
                finally:
                    _global_db_write_lock.release()

            print "Return code", return_code, return_msg

            # send back the return code
            return_code_encrypted = box.encrypt(to_byte(return_code),
                increase_nonce(client_nonce)).ciphertext

            # add the packet id
            data = to_byte(PACKET_ID_REGISTRATION_TOKEN_ACK) +\
                   return_code_encrypted

            self.request.sendall(itonb(len(data)) + data)

        elif packet_id == PACKET_ID_UPDATE_PK_REQUEST:
            offset = 0
            client_pk = data[offset:offset+PUBLICKEY_BYTES]
            offset += PUBLICKEY_BYTES
            client_nonce = data[offset:offset+NONCE_BYTES]
            offset += NONCE_BYTES
            client_mail_raw = data[offset:offset+SHA512HASH_BYTES]
            client_mail_hash = binascii.hexlify(client_mail_raw).decode('ascii')
            offset += SHA512HASH_BYTES
            client_data_crypt = data[offset:]

            box = Box(server_sk, PublicKey(client_pk))
            client_tmp_pk_raw = box.decrypt(client_data_crypt, client_nonce)
            box = None
            assert len(client_tmp_pk_raw) == PUBLICKEY_BYTES

            tmp_sk = PrivateKey.generate()
            tmp_pk_raw =\
                tmp_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)

            client_nonce = increase_nonce(client_nonce)
            tmp_box1 = Box(server_sk, PublicKey(client_tmp_pk_raw))
            ciphertext = tmp_box1.encrypt(tmp_pk_raw, client_nonce).ciphertext
            tmp_box1 = None

            data = to_byte(PACKET_ID_UPDATE_PK_RESPONSE) + ciphertext

            self.request.sendall(itonb(len(data)) + data)
            (packet_id, data) = receive_packet(self.request)

            if packet_id != PACKET_ID_UPDATE_PK_SEND_DATA:
                raise UserWarning("Unexpected packet id.")

            client_nonce = increase_nonce(client_nonce)
            tmp_box2 = Box(tmp_sk, PublicKey(client_tmp_pk_raw))
            profile_data = tmp_box2.decrypt(data, client_nonce)

            return_code = 0

            if not os.path.isfile(STORAGE_PIR_DIR+client_mail_hash):
                # the registration is not completed yet
                return_code = 1

            if return_code == 0:
                _global_db_write_lock.acquire(True)
                try: # make sure the lock will be released again
                    with open(STORAGE_PIR_DIR+client_mail_hash,
                              'rb') as f:
                        storage_data = f.read()
                finally:
                    _global_db_write_lock.release()

                assert len(storage_data) >= PUBLICKEY_BYTES
                storage_pk = storage_data[0:PUBLICKEY_BYTES]

                # the client needs to verify it's identity against the server
                assert compare_bytes(profile_data[0:PUBLICKEY_BYTES],
                                     storage_pk)

                if len(storage_data) > PUBLICKEY_BYTES and compare_bytes(
                    profile_data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES],
                    storage_data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES]):
                    # the nonce has to change to avoid leaking information about
                    # the size of the friend list
                    return_code = 2

                # write the profile data sent by the client
                _global_db_write_lock.acquire(True)
                try: # make sure the lock will be released again
                    with open(STORAGE_PIR_DIR+client_mail_hash,
                              'wb') as f:
                        f.write(profile_data)
                except:
                    return_code = 3
                finally:
                    _global_db_write_lock.release()

                update_pir_manifest()


            # send back the return code
            return_code_encrypted = tmp_box2.encrypt(to_byte(return_code),
                increase_nonce(client_nonce)).ciphertext
            tmp_box2 = None

            # add the packet id
            data = to_byte(PACKET_ID_UPDATE_PK_SEND_DATA_ACK) +\
                   return_code_encrypted

            self.request.sendall(itonb(len(data)) + data)


        elif packet_id == PACKET_ID_SEND_MSG:
            client_pk = data[0:PUBLICKEY_BYTES]
            client_nonce = data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES]
            client_data_crypt = data[PUBLICKEY_BYTES+NONCE_BYTES:]

            box = Box(server_sk, PublicKey(client_pk))
            request = from_byte(box.decrypt(client_data_crypt, client_nonce))
            assert request == 0

            tmp_sk = PrivateKey.generate()
            tmp_pk_raw =\
                tmp_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)

            client_nonce = increase_nonce(client_nonce)
            ciphertext = box.encrypt(tmp_pk_raw, client_nonce).ciphertext
            box = None

            data = to_byte(PACKET_ID_SEND_MSG_RESPONSE) + ciphertext

            self.request.sendall(itonb(len(data)) + data)
            (packet_id, data) = receive_packet(self.request)

            if packet_id != PACKET_ID_SEND_MSG_DATA:
                raise UserWarning("Unexpected packet id.")

            client_nonce = increase_nonce(client_nonce)
            tmp_box1 = Box(tmp_sk, PublicKey(client_pk))
            data = tmp_box1.decrypt(data, client_nonce)
            channel = data[:128]
            msg = data[128:]

            return_code = 0

            print "WRITING TO CHANNEL", channel

            # write message sent by the client
            _global_db_write_lock.acquire(True)
            try: # make sure the lock will be released again
                with open(STORAGE_CHANNELS_DIR+channel,
                          'ab+') as f:
                    f.write(itonb(len(msg)) + msg)
            except:
                return_code = 1
            finally:
                _global_db_write_lock.release()

            # send back the return code
            return_code_encrypted = tmp_box1.encrypt(to_byte(return_code),
                increase_nonce(client_nonce)).ciphertext
            tmp_box1 = None

            # add the packet id
            data = to_byte(PACKET_ID_SEND_MSG_DATA_ACK) +\
                   return_code_encrypted

            self.request.sendall(itonb(len(data)) + data)


        elif packet_id == PACKET_ID_RECV_MSG:
            client_pk = data[0:PUBLICKEY_BYTES]
            client_nonce = data[PUBLICKEY_BYTES:PUBLICKEY_BYTES+NONCE_BYTES]
            client_data_crypt = data[PUBLICKEY_BYTES+NONCE_BYTES:]

            box = Box(server_sk, PublicKey(client_pk))
            channel = box.decrypt(client_data_crypt, client_nonce)

            data = None

            # read messages for the client
            _global_db_write_lock.acquire(True)
            try: # make sure the lock will be released again
                with open(STORAGE_CHANNELS_DIR+channel, 'r+') as f:
                    data = f.read()
                    f.seek(0)
                    f.truncate()
            except Exception as e:
                # print "Error reading file:", e
                # the channel does not exist
                data = ''
            finally:
                _global_db_write_lock.release()

            client_nonce = increase_nonce(client_nonce)
            ciphertext = box.encrypt(data, client_nonce).ciphertext
            box = None

            data = to_byte(PACKET_ID_RECV_MSG_RESPONSE) + ciphertext

            self.request.sendall(itonb(len(data)) + data)

        else:
            raise UserWarning("Unknown packet id.")


if __name__ == "__main__":
    assert STORAGE_REGISTRATION_DIR[-1] == '/'
    assert STORAGE_PIR_DIR[-1] == '/'
    assert HTTP_STATIC_DIR[-1] == '/'
    assert Box.NONCE_SIZE == NONCE_BYTES

    commandlineoptions = parse_options()

    keyfile = 'server.secret'

    if os.path.exists(keyfile):
        with open(keyfile, 'rb') as f:
            data = f.read()
            sk_bin = data[0:32]
            server_sk = PrivateKey(sk_bin)
    else:
        server_sk = PrivateKey.generate()
        sk_bin = server_sk.encode(encoder=nacl.encoding.RawEncoder)

        with open(keyfile, 'wb') as f:
            f.write(sk_bin)

    pk_bin = server_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    print "Server public key: " + pk_bin.encode('hex')

    HOST, PORT = "0.0.0.0", commandlineoptions.port

    # Update the PIR manifest
    update_pir_manifest()

    # Create the server
    print "[INFO] Starting server at", str(HOST)+":"+str(PORT)
    onionpir_server = SocketServer.TCPServer((HOST, PORT), NonPirTCPHandler)

    # Start the server; this will keep running until you
    # interrupt the program with Ctrl-C
    try:
        onionpir_server.serve_forever()
    except KeyboardInterrupt:
        update_pir_manifest()
        print "\nGracefully shutting down server..."

    onionpir_server.server_close()
