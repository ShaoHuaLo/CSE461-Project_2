import socket
import struct
import math

# don't change these
STEP = 1
STUDENT_ID = 972

# round x up to the nearet number divisible by 4
def roundUpTo4(x):
	return int(4 * math.ceil(x/4))

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
	#### STAGE A ####
	payload_len = 12
	p_secret = 0
	message_bytes = b'hello world\0'

	message = struct.pack('!IIHH12s', payload_len, p_secret, STEP, STUDENT_ID, message_bytes)
	data = struct.unpack('!IIHH12s', message)

	s.sendto(message, ('attu3.cs.washington.edu', 12235))
	reponse, _ = s.recvfrom(28)
	_, _, _, _, num1, len1, udp_port, secretA = struct.unpack('!IIHHIIII', reponse)
	print("Secret A: ", secretA)

	#### STAGE B ####
	len1_rounded = roundUpTo4(len1)
	s.settimeout(0.5)
	payload1 = ''.ljust(len1_rounded, '\0')
	payload1 = bytes(payload1, 'utf-8')
	packet_id = 0
	while packet_id < num1:
		try:
			message = struct.pack('!IIHHI' + str(len1_rounded) + 's', len1+4, secretA, STEP, STUDENT_ID, packet_id, payload1)

			s.sendto(message, ('attu3.cs.washington.edu', udp_port))
			s.recvfrom(16)

			print("Received message")
			packet_id = packet_id + 1
		except socket.timeout:
			print("Resending packet")
	response, _ = s.recvfrom(20)
	_, _, _, _, tcp_port, secretB = struct.unpack('!IIHHII', response)
	print("Secret B: ", secretB)

	#### STAGE C ####
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('attu3.cs.washington.edu', tcp_port))
	response = s.recv(28)
	_, _, _, _, num2, len2, secretC, c, _ = struct.unpack('!IIHHIIIc3s', response)
	print("Secret C: ", secretC)

	#### STAGE D ####
	len2_rounded = roundUpTo4(len2)
	payload2 = ''.ljust(len2_rounded, c.decode('utf-8'))
	payload2 = bytes(payload2, 'utf-8')
	message = struct.pack('!IIHH' + str(len2_rounded) + 's', len2, secretC, STEP, STUDENT_ID, payload2)

	for _ in range(num2):
		s.sendall(message)

	response = s.recv(16)
	_, _, _, _, secretD = struct.unpack('!IIHHI', response)
	print("Secret D: ", secretD)

	s.close()
