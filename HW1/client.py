import socket
import struct

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    payload_len = 16
    p_secret = 0
    step = 1
    student_id = 972
    message_bytes = b'hello world\0'
    print(len(message_bytes))

    message = struct.pack('!hhhis', payload_len, p_secret, step, student_id, message_bytes)
    print(message)
    s.sendto(message, ('attu3.cs.washington.edu', 12235))
    print("Sending data")
    data, address = s.recvfrom(4096)
    print("Received message : ", data.decode('utf-8'), "\n\n")
    s.close()
