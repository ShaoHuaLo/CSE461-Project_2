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
	s.settimeout(0.5)
	payload = ''
	payload = bytes(payload.zfill(len), 'utf-8')
	while packet_id < num:
		try:
			message = struct.pack('!IIHHI' + str(len) + 's', len+4, secretA, step, student_id, packet_id, payload)
			data = struct.unpack('!IIHHI' + str(len) + 's', message)
			print(data)

			s.sendto(message, ('attu3.cs.washington.edu', udp_port))
			packet_id = packet_id + 1
			response, _ = s.recvfrom(16)
			resp = struct.unpack('!IIHHI', response)
			print(resp)
		except socket.timeout:
			print("Resending packet")

	s.close()
