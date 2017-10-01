import hashlib
import hmac
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from libonionpir.shared import *
from libonionpir.constants import *
from raidpir import raidpirlib
from raidpir import simplexorrequestor
import socket
import socks
from stem import Signal
from stem.control import Controller
import threading
import time

options = {
    'stemController': None,
    'registration_server': "",
    'registration_server_port': -1,
    'tor_socks_port': -1,
    'tor_control_port': -1,
    'setup_complete': False,
}

"""
Setup the OnionPIR library.

stemController: a controller for the stem library
reg_host: The hostname or IP address of the OnionPIR server
reg_port: The port of the OnionPIR server
tor_socks_port: The port of the Tor socks proxy
tor_control_port: The port of Tor's control protocol
"""
def setup(stemController, reg_host, reg_port, tor_socks_port, tor_control_port):
    print "[INFO] Registration server: onionpir://"+str(reg_host)+":"+str(reg_port)

    if stemController == "tor_disabled":
        print "[WARNING] Tor is DISABLED. Use this option only for debugging!"

    options['stemController'] = stemController
    options['registration_server'] = reg_host
    options['registration_server_port'] = reg_port
    options['tor_socks_port'] = tor_socks_port
    options['tor_control_port'] = tor_control_port
    options['setup_complete'] = True


"""
Write the current profile (configuration to disk)

data: the data to be written
filename: the filename to be used
"""
def write_profile_data(data, filename):
    """Write the profile data to a file"""

    open(filename, "w").write(data)
    print "[INFO] wrote", filename


"""
Register for the OnionPIR service

mail: our mail address we would like to use for registration
own_sk: our secret key
server_pk: the server's public key
"""
def register(mail, own_sk, server_pk):
    assert isinstance(mail, str)
    assert isinstance(own_sk, PrivateKey)
    assert isinstance(server_pk, PublicKey)
    assert options['setup_complete']

    own_pk_raw = own_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    box = Box(own_sk, server_pk)
    ciphertext = box.encrypt(mail, nonce).ciphertext

    data = to_byte(PACKET_ID_REGISTRATION_REQUEST) + own_pk_raw + nonce +\
           ciphertext

    # Create a TCP socket, Tor is not needed here
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to server and send data
        print "[REGISTRATION] Connecting to OnionPIR server "+\
              str(options['registration_server'])+':'+\
              str(options['registration_server_port'])

        sock.connect((options['registration_server'],
                      options['registration_server_port']))
        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id == PACKET_ID_REGISTRATION_REQUEST_ACK:
            return_code = box.decrypt(data, increase_nonce(nonce))
            print "Return code: "+str(from_byte(return_code))
            return from_byte(return_code)
        else:
            raise UserWarning("Unknown packet id: " + str(packet_id))


    finally:
        sock.close()

"""
Verify the token received during the registration process

mail: our mail address used during the registration proccess
own_sk: out secret key
server_pk: the server's public key
token: the token received from the server
"""
def verify_token(mail, own_sk, server_pk, token):
    assert isinstance(own_sk, PrivateKey)
    assert isinstance(server_pk, PublicKey)
    assert isinstance(token, str)

    own_pk_raw = own_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    box = Box(own_sk, server_pk)

    token_raw = None
    try:
        token_raw = token.decode('hex')
    except Exception:
        return 2 # invalid token

    ciphertext = box.encrypt(token_raw + mail, nonce).ciphertext

    data = to_byte(PACKET_ID_REGISTRATION_TOKEN) + own_pk_raw + nonce +\
           ciphertext

    # Create a TCP socket, Tor is not needed here
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to server and send data
        sock.connect((options['registration_server'],
                      options['registration_server_port']))
        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id == PACKET_ID_REGISTRATION_TOKEN_ACK:
            return_code = box.decrypt(data, increase_nonce(nonce))
            print "Return code: "+str(from_byte(return_code))
            return from_byte(return_code)
        else:
            raise UserWarning("Unknown packet id: " + str(packet_id))

    finally:
        sock.close()


"""
Upload out public key to the PIR database (through the OnionPIR server)

own_sk: our secret key
own_mail: our mail address
server_pk: the server's public key
"""
def upload_pk(own_sk, own_mail, server_pk):
    assert isinstance(own_sk, PrivateKey)
    assert isinstance(own_mail, str)
    assert isinstance(server_pk, PublicKey)

    own_pk_raw = own_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    tmp_sk = PrivateKey.generate()
    tmp_pk_raw = tmp_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    own_pk_raw = own_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    own_mail_hash_raw = hashlib.sha512(own_mail).digest()

    box = Box(own_sk, server_pk)
    ciphertext = box.encrypt(tmp_pk_raw, nonce).ciphertext
    box = None

    data = to_byte(PACKET_ID_UPDATE_PK_REQUEST) + own_pk_raw + nonce +\
           own_mail_hash_raw + ciphertext

    # Create a TCP socket, Tor is not needed here since we authenticate
    # ourselves against the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to server and send data
        print "Connecting to registration server: "+\
              str(options['registration_server'])+":"+\
              str(options['registration_server_port'])
        sock.connect((options['registration_server'],
                      options['registration_server_port']))
        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id != PACKET_ID_UPDATE_PK_RESPONSE:
            raise UserWarning("Unknown packet id: " + str(packet_id))

        nonce = increase_nonce(nonce)
        tmp_box1 = Box(tmp_sk, server_pk)

        server_tmp_pk_raw = tmp_box1.decrypt(data, nonce)
        tmp_box1 = None

        nonce = increase_nonce(nonce)
        tmp_box2 = Box(tmp_sk, PublicKey(server_tmp_pk_raw))
        ciphertext = tmp_box2.encrypt(own_pk_raw, nonce).ciphertext
        data = to_byte(PACKET_ID_UPDATE_PK_SEND_DATA) + ciphertext

        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id != PACKET_ID_UPDATE_PK_SEND_DATA_ACK:
            raise UserWarning("Unexpected packet id: " + str(packet_id))

        nonce = increase_nonce(nonce)
        return_code = tmp_box2.decrypt(data, nonce)
        tmp_box2 = None
        print "Return code: "+str(from_byte(return_code))
        return from_byte(return_code)

    finally:
        sock.close()


"""
Receive our contact's public keys via PIR

own_sk: our secret key
own_mail: our mail address
contact_mail: out contact's mail address
pir_vendor: the hostname and port of the pir vendor
"""
def get_contact_data(own_sk, own_mail, contact_mail, pir_vendor):
    assert isinstance(contact_mail, str)
    assert isinstance(own_mail, str)

    filename = hashlib.sha512(contact_mail).hexdigest()

    # We need to download the manifest file...
    rawmanifestdata = raidpirlib.retrieve_rawmanifest(pir_vendor)

    # ...make sure it is valid...
    manifestdict = raidpirlib.parse_manifest(rawmanifestdata)

    # we will check that the files are in the release
    # find the list of files
    filelist = raidpirlib.get_filenames_in_release(manifestdict)

    numberofmirrors = 2
    redundancy = None
    rng = False
    parallel = False

    if (manifestdict['blockcount'] < numberofmirrors * 8) and redundancy != None:
        print "Block count too low to use chunks! Try reducing the block size or add more files to the database."
        return (None, None, None)

    # ensure the requested file exists...
    if filename not in filelist:
        print "The file", filename, "is not listed in the manifest."
        return (None, None, None)

    neededblocks = []
    # let's figure out what blocks we need
    theseblocks = raidpirlib.get_blocklist_for_file(filename, manifestdict)
    #print filename, theseblocks

    # add the blocks we don't already know we need to request
    for blocknum in theseblocks:
        if blocknum not in neededblocks:
            neededblocks.append(blocknum)

    # do the actual retrieval work
    blockdict = request_blocks_from_mirrors(neededblocks, manifestdict, redundancy, rng, parallel, numberofmirrors)

    # now we should write out the files
    contact_pk_raw = raidpirlib.extract_file_from_blockdict(
        filename, manifestdict, blockdict)

    # let's check the hash
    thisfilehash = raidpirlib.find_hash(contact_pk_raw,
                                        manifestdict['hashalgorithm'])

    for fileinfo in manifestdict['fileinfolist']:
        # find this entry
        if fileinfo['filename'] == filename:
            if thisfilehash == fileinfo['hash']:
                # we found it and it checks out!
                break
            else:
                raise Exception("Corrupt manifest has incorrect file hash despite passing block hash checks!")
    else:
        raise Exception("Internal Error: Cannot locate fileinfo in manifest!")

    assert len(contact_pk_raw) == PUBLICKEY_BYTES

    contact_pk = PublicKey(contact_pk_raw)
    box = Box(own_sk, contact_pk)
    nonce = b'\xaa'*24

    shared_secret = box.encrypt(b'\x55'*8, nonce)

    # bytes(contact_mail, 'utf8') for python3
    secret_in = hmac.new(shared_secret, bytes(own_mail), hashlib.sha512).digest()
    secret_out = hmac.new(shared_secret, bytes(contact_mail), hashlib.sha512).digest()

    return (contact_pk, secret_in, secret_out)


"""
Send a message to a dead drop derived from the given secret

server_pk: the public key of the server
secret_out: the secret to be used to derive the dead drop
msg: the message to be sent
"""
def send_message(server_pk, secret_out, msg):
    assert isinstance(server_pk, PublicKey)
    assert isinstance(secret_out, str)
    assert isinstance(msg, str)

    dead_drop = derive_dead_drop_id(secret_out)
    print "Sending message to dead drop", dead_drop


    tmp_sk = PrivateKey.generate()
    tmp_pk_raw = tmp_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    box = Box(tmp_sk, server_pk)
    ciphertext = box.encrypt(to_byte(0), nonce).ciphertext

    data = to_byte(PACKET_ID_SEND_MSG) + tmp_pk_raw + nonce +\
           ciphertext

    sock = get_new_socket()

    try:
        # Connect to server and send data
        sock.connect((options['registration_server'],
                      options['registration_server_port']))

        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id != PACKET_ID_SEND_MSG_RESPONSE:
            raise UserWarning("Unknown packet id: " + str(packet_id))

        nonce = increase_nonce(nonce)

        server_tmp_pk_raw = box.decrypt(data, nonce)
        box = None

        nonce = increase_nonce(nonce)
        tmp_box1 = Box(tmp_sk, PublicKey(server_tmp_pk_raw))
        ciphertext = tmp_box1.encrypt(dead_drop + msg, nonce).ciphertext
        data = to_byte(PACKET_ID_SEND_MSG_DATA) + ciphertext

        sock.sendall(itonb(len(data)) + data)
        (packet_id, data) = receive_packet(sock)

        if packet_id != PACKET_ID_SEND_MSG_DATA_ACK:
            raise UserWarning("Unexpected packet id: " + str(packet_id))

        nonce = increase_nonce(nonce)
        return_code = tmp_box1.decrypt(data, nonce)
        tmp_box1 = None
        print "Return code: "+str(from_byte(return_code))
        return from_byte(return_code)

    finally:
        sock.close()


"""
Get the renewal time from a secret in human readable format

secret: the secret of which the time is derived
"""
def get_secret_renewal_time(secret):
    assert isinstance(secret, bytes)
    assert len(secret) > 3

    offset = (ord(secret[0])+ord(secret[1])*256+ord(secret[2])*256*256+\
              ord(secret[3])*256*256*256)%(60*60*24)

    return time.strftime("%H:%M:%S", time.gmtime(offset))


"""
Get the current dead drop from a secret

secret: the secret of which the dead drop is derived
"""
def derive_dead_drop_id(secret):
    assert isinstance(secret, bytes)
    assert len(secret) > 3

    offset = (ord(secret[0])+ord(secret[1])*256+ord(secret[2])*256*256+\
              ord(secret[3])*256*256*256)%(60*60*24)
    timestamp = bytes(int((time.time()-offset)/(60*60*24)))
    # print 'timestamp:', timestamp, 'offset:', offset

    dead_drop_id = hmac.new(secret, timestamp, hashlib.sha512).hexdigest()
    return dead_drop_id


"""
Receive messages from contacts

own_sk: our secret key
server_pk: the server's public key
contacts: our list of contacts
"""
def recv_messages(own_sk, server_pk, contacts):
    assert isinstance(own_sk, PrivateKey)
    assert isinstance(server_pk, PublicKey)
    assert isinstance(contacts, list)

    messages = list()

    for contact in contacts:
        if contact.secret_in is None:
            continue;

        dead_drop = derive_dead_drop_id(contact.secret_in)

        tmp_sk = PrivateKey.generate()
        tmp_pk_raw = tmp_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
        nonce = nacl.utils.random(Box.NONCE_SIZE)

        box = Box(tmp_sk, server_pk)
        ciphertext = box.encrypt(dead_drop, nonce).ciphertext

        data = to_byte(PACKET_ID_RECV_MSG) + tmp_pk_raw + nonce +\
               ciphertext

        # Create a new Tor TCP socket
        sock = get_new_socket()

        try:
            # Connect to server and send data
            sock.connect((options['registration_server'],
                          options['registration_server_port']))
            sock.sendall(itonb(len(data)) + data)
            (packet_id, data) = receive_packet(sock)

            if packet_id != PACKET_ID_RECV_MSG_RESPONSE:
                raise UserWarning("Unknown packet id: " + str(packet_id))

            nonce = increase_nonce(nonce)

            data = box.decrypt(data, nonce)
            box = Box(own_sk, contact.pk)

            current_pos = 0
            while(current_pos + 5 < len(data)):
                # trying to decrypt the message of length `length`
                length = nbtoi(data[current_pos:current_pos + 4])
                current_pos += 4
                msg_crypt = data[current_pos:current_pos + length]
                current_pos += length

                try:
                    msg = box.decrypt(msg_crypt)
                    print "DECRYPTION SUCCESSFUL", (contact.mail, msg)
                    messages.append((contact.mail, msg))
                except Exception as e:
                    print "Decryption not successful", contact.mail
        finally:
            sock.close()

    return messages


"""
Request a new Tor curcuit and create a socket that can be used to contact the server
"""
def get_new_socket():
    global options
    sock = None

    if options['stemController'] == 'tor_disabled':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        # switch to new circuits, so new application requests don't share any
        # circuits with old ones (this also clears our DNS cache)
        print "Requesting new Tor circuits"
        with options['stemController'] as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)

        # Create a TCP socket through Tor
        sock = socks.socksocket()
        print "Creating socket to port "+str(options['tor_socks_port'])
        sock.set_proxy(socks.PROXY_TYPE_SOCKS5, "localhost",
                       options['tor_socks_port'])

    return sock


"""
Request blocks via PIR from the PIR mirrors

requestedblocklist: the blocks to acquire
manifestdict: the manifest with information about the release
redundancy: the redundancy parameter
rng: the random number generator to be used
parallel: specifies whether multi-block queries should be performed
numberofmirrors: the number of PIR mirrors that should be used
"""
def request_blocks_from_mirrors(requestedblocklist, manifestdict, redundancy, rng, parallel, numberofmirrors):
    timing = False
    batch = False

    # let's get the list of mirrors...
    # use data from manifest
    mirrorinfolist = raidpirlib.retrieve_mirrorinfolist(manifestdict['vendorhostname'], manifestdict['vendorport'])

    # use commandlineoptions
    # mirrorinfolist = raidpirlib.retrieve_mirrorinfolist(_commandlineoptions.vendorip)

    # print "Mirrors: ", mirrorinfolist

    # no chunks (regular upPIR / Chor)
    if redundancy == None:

        # let's set up a requestor object...
        rxgobj = simplexorrequestor.RandomXORRequestor(mirrorinfolist, requestedblocklist, manifestdict, numberofmirrors, batch, timing)

        print "Blocks to request:", len(rxgobj.activemirrors[0]['blockbitstringlist'])

        # let's fire up the requested number of threads.   Our thread will also participate (-1 because of us!)
        for tid in xrange(numberofmirrors - 1):
            threading.Thread(target=_request_helper, args=[rxgobj, tid]).start()

        _request_helper(rxgobj, numberofmirrors - 1)

        # wait for receiving threads to finish
        for mirror in rxgobj.activemirrors:
            mirror['rt'].join()

    else: # chunks

        # let's set up a chunk requestor object...
        rxgobj = simplexorrequestor.RandomXORRequestorChunks(mirrorinfolist, requestedblocklist, manifestdict, numberofmirrors, redundancy, rng, parallel, _commandlineoptions.batch, timing)


        print "# Blocks needed:", len(rxgobj.activemirrors[0]['blocksneeded'])

        if parallel:
            print "# Requests:", len(rxgobj.activemirrors[0]['blockchunklist'])

        #chunk lengths in BYTE
        global chunklen
        global lastchunklen
        chunklen = (manifestdict['blockcount'] / 8) / numberofmirrors
        lastchunklen = raidpirlib.bits_to_bytes(manifestdict['blockcount']) - (numberofmirrors-1)*chunklen

        if _commandlineoptions.timing:
            req_start = _timer()

        # let's fire up the requested number of threads.   Our thread will also participate (-1 because of us!)
        for tid in xrange(numberofmirrors - 1):
            threading.Thread(target=_request_helper_chunked, args=[rxgobj, tid]).start()

        _request_helper_chunked(rxgobj, numberofmirrors - 1)

        # wait for receiving threads to finish
        for mirror in rxgobj.activemirrors:
            mirror['rt'].join()

    rxgobj.cleanup()

    # okay, now we have them all. Let's get the returned dict ready.
    retdict = {}
    for blocknum in requestedblocklist:
        retdict[blocknum] = rxgobj.return_block(blocknum)

    return retdict


"""
Private PIR helper to get requests.
Multiple threads will execute this, each with a unique tid.
"""
def _request_helper(rxgobj, tid):
    thisrequest = rxgobj.get_next_xorrequest(tid)

    #the socket is fixed for each thread, so we only need to do this once
    socket = thisrequest[0]['sock']

    # go until there are no more requests
    while thisrequest != ():
        bitstring = thisrequest[2]
        try:
            # request the XOR block...
            raidpirlib.request_xorblock(socket, bitstring)

        except Exception, e:
            if 'socked' in str(e):
                rxgobj.notify_failure(thisrequest)
                sys.stdout.write('F')
                sys.stdout.flush()
            else:
                # otherwise, re-raise...
                raise

        # regardless of failure or success, get another request...
        thisrequest = rxgobj.get_next_xorrequest(tid)

    # and that's it!
    return
