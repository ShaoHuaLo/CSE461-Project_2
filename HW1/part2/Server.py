import struct
import socket
import random
import math
import _thread

STEP = 2
STUDENT_ID = 972

SERVER_NAME = "attu2.cs.washington.edu"
PORT_START = 12235

HEADER_LEN = 12
BUFFER_SIZE = 1024
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def roundUpTo4(x):
    """
    :param x: length of a payload
    :return a new length which is divisible by 4
    """
    return int(4 * math.ceil(x / 4))


def get_header(payload_len, psecret, step = STEP, id = STUDENT_ID):
    """

    :param payload_len: length of payload which excludes the padding for byte-align
    :param psecret: secret of last step
    :param step: constant, value 1 for the client and 2 for the server respectively
    :param id: student_id
    :return: Object of bytes of length 12 bytes long.
    """
    header = struct.pack('!IIHH', payload_len, psecret, step, id)
    return header


def is_valid_packet_size(packet):
    """
    :param: a packet(type of python bytes) received through the newtworking
    :return: Boolean True if the packet'size is divisible by 4, False otherwise
    """
    if len(packet) % 4 != 0:
        print("packet size: ", len(packet), "which is not divisible by 4")
        return False
    else:
        return True


def resolve_packet(packet_rec):
    """
    This utility function will extract the data we need from the original packet
    :param packet_rec: A packet received through the networking
    :return: A tuple of (header, payload) of which the :header: is of fixed 12-bytes length
            and the :payload: is only the non-padding part of the original payload
    """

    header = packet_rec[:12]
    payload_len, psecret, step, id = struct.unpack('!2I2H', header)
    payload_with_padding = packet_rec[12:]
    payload = payload_with_padding[:payload_len]
    return header, payload


def is_valid_packet_a(header, payload):
    """
    Verify given packet are valid or not according to each step's context
    :param header: a packet (of type python bytes)
    :param payload: boolean True if it's valid packet, False otherwise.
    :return:
    """

    payload_len, psecret, step, id = struct.unpack('!IIHH', header)
    if psecret != 0 or step != 1:
        print("expected (psecret, step): (0, 1)", "vs. current (", psecret, ", ", step, ")")
        return False
    if payload_len != len(b'hello world\0'):
        return False
    if payload != b'hello world\0':
        print("expected payload: ", b'hello world\0', "vs. current: ", payload)
        return False
    return True


def is_valid_packet_b(header, payload, secretA, len_of_zero, id):
    payload_len, psecret, step, _ = struct.unpack('!IIHH', header)
    if psecret != secretA:
        print("secret not correct")
        return False

    packet_id, zeros = struct.unpack('! I {}s'.format(len_of_zero), payload)
    if packet_id != id or step != 1:
        print("id is wrong", "actual: ", packet_id, " expected: ", id)
        print("step is wrong")
        return False

    if len(zeros) != len_of_zero:
        print("actual len: ", len(zeros), " expected len: ", len_of_zero)
        return False

    if zeros[4:] != (b'\0' * len_of_zero)[4:]:
        print("actual len: ", len(zeros), " expected len: ", len_of_zero)
        print("actual: ", zeros, "expected: ", b'\0' * len_of_zero)
        return False
    return True


def is_valid_packet_d(header, payload, secretC, c):
    payload_len, psecret, step, id = struct.unpack('!IIHH', header)
    if psecret != secretC or step != 1:
        return False
    if payload != c*payload_len:
        return False
    return True


def response_to_client_a(addr_client):
    num, len0, udp_port, secretA = random.randint(0, 10), random.randint(0, 10),\
                                   random.randint(49152, 65535), random.randint(0, 50)
    packet_reply = struct.pack('! 12s 4I', get_header(16, 0), num, len0, udp_port, secretA)
    print("sending secretA: ", secretA, " to-- ", addr_client)
    my_UDP_socket.sendto(packet_reply, addr_client)
    return num, len0, udp_port, secretA


def response_to_client_b(socket_b, addr_client, psecret):
    tcp_port, secretB = random.randint(49152, 65535), random.randint(0, 1000)
    packet_to_send = struct.pack('! 12s I I', get_header(8, psecret), tcp_port, secretB)
    print("sending secretB: ", secretB, " to-- ", addr_client)
    socket_b.sendto(packet_to_send, addr_client)
    return tcp_port, secretB


def response_to_client_c(conn, psecret):
    num2, len2, secretC, c = random.randint(0, 50), \
                             random.randint(0, 50),\
                             random.randint(0, 50), \
                             bytes(CHARS[random.randint(0, 51)], 'utf-8')
    packet_to_send = struct.pack('! 12s I I I c 3s', get_header(16, psecret), num2, len2, secretC, c, b'\0\0\0')
    print("sending secretC: ", secretC, " to-- ", addr_client)
    conn.sendall(packet_to_send)
    return num2, len2, secretC, c


def response_to_client_d(conn, psecret):
    secretD = random.randint(0, 50)
    packet_to_send = struct.pack('! 12s I', get_header(4, psecret), secretD)
    print("sending secretD: ", secretD, " to -- ", addr_client)
    conn.sendall(packet_to_send)


def send_awk_packet(socket_b, addr_client, psecret):
    awk_id = random.randint(0, 1000)
    awk_pack = struct.pack('! 12s I', get_header(1, psecret), awk_id)
    socket_b.sendto(awk_pack, addr_client)


def connect_to_TCP(tcp_port):
    tcp_master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_master_socket.bind(("localhost", tcp_port))
    tcp_master_socket.listen()
    conn, addr_client = tcp_master_socket.accept()
    conn.settimeout(3)
    return conn, addr_client


def threaded(packet_recv, addr_client, sock):
    # step a
    # verify header & payload
    header, payload = resolve_packet(packet_recv)
    if not is_valid_packet_size(payload) or not is_valid_packet_a(header, payload):
        return
    num, len0, udp_port, secretA = response_to_client_a(addr_client)

    # -----------------------------------------------------------------------#

    # step b
    socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_b.bind((SERVER_NAME, udp_port))

    id = 0
    while id < num:
        packet_recv, addr_client = socket_b.recvfrom(BUFFER_SIZE)
        if not packet_recv:
            print("data stream all sent: transmission over...") # for debugging
            break

        # verify header & payload
        if not is_valid_packet_size(packet_recv):
            print("row165: size not divisible by 4") # for debugging
            return

        header, payload = resolve_packet(packet_recv)
        if not is_valid_packet_b(header, payload, secretA, len0, id):
            print("row171: header or payload is not correct") # for debugging
            return

        if random.randint(0, 1000) < 200:
            continue

        send_awk_packet(socket_b, addr_client, secretA)
        id += 1

    # one more check if the number of packets recved is correct
    if id != num:
        print("row188: something went wrong, total packets recv didnt match")
        return

    tcp_port, secretB = response_to_client_b(socket_b, addr_client, secretA)

    # -----------------------------------------------------------------------#

    # step c1
    conn, addr_client = connect_to_TCP(tcp_port)
    # step c2
    try:
        num2, len2, secretC, c = response_to_client_c(conn, secretB)

        # -----------------------------------------------------------------------#
        # d1
        count = 0
        while count < num2:
            packet_recv = conn.recv(12 + roundUpTo4(len2))
            # if transmission is done
            if not packet_recv:
                break
            # verify header & payload
            header, payload = resolve_packet(packet_recv)
            if not is_valid_packet_size(packet_recv):
                print("packet size is not divisible by 4... terminating the loop")
                conn.close()
                return
            if not is_valid_packet_d(header, payload, secretC, c):
                print("packet from step-d is not valid... ending the loop")
                conn.close()
                return
            # print("NO-", count," packet recved") # for debugging
            count += 1

        # one more check
        if count != num2:
            print("something went wrong, packet might be missing")
            conn.close()
            return

        response_to_client_d(conn, secretC)
    except socket.timeout:
        print("3s timeout, reconnecting again")
    finally:
        conn.close()


if __name__ == "__main__":
    my_UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_UDP_socket.bind((SERVER_NAME, PORT_START))
    while True:
        # -----------------------------------------------------------------------#
        # UDP socket
        packet_recv, addr_client = my_UDP_socket.recvfrom(BUFFER_SIZE)
        _thread.start_new_thread(threaded, (packet_recv, addr_client, my_UDP_socket))
