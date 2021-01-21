import socket
import struct
import math

# round x up to the nearet number divisible by 4
def roundUpTo4(x):
	return int(4 * math.ceil(x/4))

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
	#### STAGE A ####
	payload_len = 12
	p_secret = 0
	step = 1
	student_id = 972
	message_bytes = b'hello world\0'

	message = struct.pack('!IIHH12s', payload_len, p_secret, step, student_id, message_bytes)
	data = struct.unpack('!IIHH12s', message)

	s.sendto(message, ('attu3.cs.washington.edu', 12235))
	reponse, _ = s.recvfrom(28)
	_, _, _, _, num, len, udp_port, secretA = struct.unpack('!IIHHIIII', reponse)

	len_rounded = roundUpTo4(len)

	print("Secret A: ", secretA)

	#### STAGE B ####
	s.settimeout(0.5)
	payload = ''.ljust(len_rounded, '\0')
	payload = bytes(payload, 'utf-8')
	packet_id = 0
	while packet_id < num:
		try:
			message = struct.pack('!IIHHI' + str(len_rounded) + 's', len+4, secretA, step, student_id, packet_id, payload)
			data = struct.unpack('!IIHHI' + str(len_rounded) + 's', message)
			# print(data)

			s.sendto(message, ('attu3.cs.washington.edu', udp_port))
			response, _ = s.recvfrom(16)

			resp = struct.unpack('!IIHHI', response)
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
	payload = ''.ljust(len2_rounded, c.decode('utf-8'))
	payload = bytes(payload, 'utf-8')
	message = struct.pack('!IIHH' + str(len2_rounded) + 's', len2, secretC, step, student_id, payload)
	data = struct.unpack('!IIHH' + str(len2_rounded) + 's', message)

	for i in range(num2):
		s.sendall(message)

	response = s.recv(16)
	_, _, _, _, secretD = struct.unpack('!IIHHI', response)
	print("Secret D: ", secretD)

	s.close()
