import socket
import struct

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
	#### STAGE A ####
	payload_len = 12
	p_secret = 0
	step = 1
	student_id = 972
	message_bytes = b'hello world\0'

	message = struct.pack('!IIHH12s', payload_len, p_secret, step, student_id, message_bytes)
	data = struct.unpack('!IIHH12s', message)
	print(data)

	print("Sending data A")
	s.sendto(message, ('attu3.cs.washington.edu', 12235))
	print("Sent data A")
	data, _ = s.recvfrom(28)
	payload_len, p_secret, step2, student_id, num, len, udp_port, secretA = \
			struct.unpack('!IIHHIIII', data)

	# round len up to the nearet number divisible by 4
	len = int(4 * round(len/4))

	print("Received message A")
	print((payload_len, p_secret, step2, student_id, num,len,udp_port,secretA))

	#### STAGE B ####
	s.settimeout(.5)
	payload = ''.ljust(len, '\0')
	payload = bytes(payload, 'utf-8')
	packet_id = 0
	while packet_id < num:
		try:
			message = struct.pack('!IIHHI' + str(len) + 's', len+4, secretA, step, student_id, packet_id, payload)
			data = struct.unpack('!IIHHI' + str(len) + 's', message)
			# print(data)

			s.sendto(message, ('attu3.cs.washington.edu', udp_port))
			response, _ = s.recvfrom(16)

			packet_id = packet_id + 1
			resp = struct.unpack('!IIHHI', response)
			print("Received message")
		except socket.timeout:
			print("Resending packet")
	response, _ = s.recvfrom(20)
	_, _, _, _, tcp_port, secretB = struct.unpack('!IIHHII', response)
	print("tcp port: ", tcp_port)
	print("Secret B:", secretB)

	### STAGE C ###
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('attu3.cs.washington.edu', tcp_port))
	response = s.recv(25)
	payload_len, p_secret, step2, student_id, num2, len2, secretC, c = struct.unpack('!IIHHIIIc', response)
	print(struct.unpack('!IIHHIIIc', response))
	print("Secret C: ", secretC)

	## STAGE D ##
	len2 = int(4 * round(len2 / 4))
	# Had issues passing in c into ljust this is a workaround but there must be a better way
	s_char = struct.pack('s', c)
	payload = ''.ljust(len2, chr(s_char[0]))
	payload = bytes(payload, 'utf-8')
	for packet_id in range(num2):
		message = struct.pack('!IIHHI' + str(len2) + 's', len2 + 4, secretC, step, student_id, packet_id, payload)
		data = struct.unpack('!IIHHI' + str(len2) + 's', message)
		print(data)

		s.sendto(message, ('attu3.cs.washington.edu', tcp_port))
	# Keep running into an issue that there are too many values to unpack
	response, _ = s.recv(16)
	payload_len, p_secret, step, student_id, secretD = struct.unpack('!IIHHI', response)
	print("Secret D: ", secretD)

	s.close()
