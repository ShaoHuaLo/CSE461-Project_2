import socket
import math
import struct

STEP = 1
STUDENT_ID = 972

SERVER_NAME = "attu2.cs.washington.edu"
# SERVER_NAME = "localhost" # for testing
PORT = 12235
HEADER_LEN = 12
BUFFER_SIZE = 1024


# utility function : round up payload len to be divisible by 4
def roundUpTo4(x):
    return int(4 * math.ceil(x / 4))


# utility function : return header (bytes)
def get_header(payload_len, psecret, step=STEP, id=STUDENT_ID):
    header = struct.pack('!IIHH', payload_len, psecret, step, id)
    return header


def resolve_packet(packet_rec):
    header = packet_rec[:12]
    payload = packet_rec[12:]
    return header, payload


def byte_align(payload_before_padding):
    n = len(payload_before_padding)
    if n % 4 == 0:
        return payload_before_padding, n, n
    new_n = roundUpTo4(n)
    diff = new_n - n
    new_pay_load = payload_before_padding + b'\0' * diff
    return new_pay_load, n, new_n


def stage_A():
    my_UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'hello world\0'
    payload_len = len(payload)

    # Step a1
    # prepare header and packet
    header = get_header(payload_len, 0)
    packet_to_send = struct.pack('! 12s {}s'.format(payload_len), header, payload)
    my_UDP_socket.sendto(packet_to_send, (SERVER_NAME, PORT))

    # Step a2
    packet_recv = my_UDP_socket.recv(BUFFER_SIZE)
    # last 4 number are what we want
    header, num, len1, udp_port, secretA  = struct.unpack('! 12s 4I', packet_recv)
    print("Secret A: ", secretA)
    return num, len1, udp_port, secretA


def stage_B(num, len1, udp_port, secretA):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.settimeout(0.5)
    header = get_header(len1+4, secretA)
    zeros = b'\0' * len1
    # Step b1
    packet_id = 0
    while packet_id < num:
        payload_before_padding = int.to_bytes(packet_id, 4, 'big', signed=False) + zeros
        payload_after_padding, before_len, after_len = byte_align(payload_before_padding)
        packet_to_send = struct.pack('!12s {}s'.format(after_len), header, payload_after_padding)
        try:
            my_socket.sendto(packet_to_send, (SERVER_NAME, udp_port))
            awk = my_socket.recv(BUFFER_SIZE)

            # check if we need to resend this pack_id
            if not awk:
                print("didn't receive awk, resending")
                continue
            packet_id += 1

        except socket.timeout:
            print("0.5s timeout in b1, retrying")
            continue;

    # Step b2
    try:
        packet_recv = my_socket.recv(BUFFER_SIZE)
        _, tcp_port, secretB = struct.unpack('! 12sII', packet_recv)
        print("Secret B: ", secretB)
        return tcp_port, secretB
    except socket.timeout:
        print("timeout in b2")
        return -1, -1


def stage_C_D(tcp_port, secretB):
    # if stage B failed exit the program
    if tcp_port == -1 and secretB == -1:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_tcp_socket:
        # step c1
        my_tcp_socket.connect((SERVER_NAME, tcp_port))
        # step c2
        packet_recv = my_tcp_socket.recv(BUFFER_SIZE)
        _, num2, len2, secretC, c, _ = struct.unpack('! 12s 3I c 3s', packet_recv)
        print("Secret C: ", secretC)

        # step d1
        payload_before_padding = c * len2
        payload_after_padding, before_len, after_len = byte_align(payload_before_padding)
        header = get_header(len2, secretC)
        packet_to_send = struct.pack('! 12s {}s'.format(after_len), header, payload_after_padding)

        for i in range(num2):
            my_tcp_socket.sendall(packet_to_send)

        # step d2
        packet_recv = my_tcp_socket.recv(BUFFER_SIZE)
        _, secretD = struct.unpack('! 12s I', packet_recv)
        print("secret D: ", secretD)


def main():
    num, len1, udp_port, secretA = stage_A()
    tcp_port, secretB = stage_B(num, len1, udp_port, secretA)
    stage_C_D(tcp_port, secretB)


if __name__ == "__main__":
    main()
