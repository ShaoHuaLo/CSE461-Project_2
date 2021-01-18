import socket
import struct

# addr_info = socket.getaddrinfo('attu2.cs.washington.edu', 12235)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('128.208.1.138', 12235))
    message = struct.pack('hello world\0')
    s.send(message)
    data = s.recv(1024)
    s.close()
    # struct.pack() use this for making the header
    # when writing a strting write b'hello\0'

print('Received', repr(data))
