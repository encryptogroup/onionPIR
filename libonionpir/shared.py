import struct

def itonb(i):
    '''
    Convert an integer to a four bytes network byte order bytestring
    '''
    return struct.pack("!I", i)

def nbtoi(b):
    """
    Convert a 4 byte network byte oder bytestring to an int
    """
    return struct.unpack("!I", b)[0]

def to_byte(i):
    """
    Converts an integer to a byte
    """
    return struct.pack("B", i)

def from_byte(b):
    """
    Converts a byte to an integer
    """
    return struct.unpack("B", b)[0]

def increase_nonce(nonce):
    """
    Increases a binary nonce by 1
    """
    assert isinstance(nonce, bytes)
    nonce_bin = bytearray(nonce)

    for i in range(len(nonce_bin)-1, -1, -1):
        if nonce_bin[i] == 255:
            continue;
        nonce_bin[i] += 1
        return str(nonce_bin)

    return b"\x00" * len(nonce_bin)

def compare_bytes(b1, b2):
    assert(isinstance(b1, bytes))
    assert(isinstance(b2, bytes))

    # it is important to not use secret data to control a branch in order to
    # prevent sidechannel attacks
    bytes_are_equal = (len(b1) == len(b2))

    for i in range(len(b1)):
        bytes_are_equal &= (b1[i] == b2[i])

    return bytes_are_equal

def receive_packet(sock):
    # wait for the response
    # detemine the packet length as defined by the protocol
    packet_length = nbtoi(sock.recv(4))

    # receive the data itself
    data = sock.recv(packet_length)

    # the first byte is the id of the packet
    packet_id = from_byte(data[0])

    #print "--- received a packet with packet id {} and length {} - [{}]".format(packet_id, packet_length, sock.getpeername()[0])

    return (packet_id, data[1:])
