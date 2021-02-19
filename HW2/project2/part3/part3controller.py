# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPs = {
  "h10" : "10.0.1.10",
  "h20" : "10.0.2.20",
  "h30" : "10.0.3.30",
  "serv1" : "10.0.4.10",
  "hnotrust" : "172.16.10.100",
}

class Part3Controller (object):
	"""
	A Connection object for that switch is passed to the __init__ function.
	"""
	def __init__ (self, connection):
		print (connection.dpid)
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)
		#use the dpid to figure out what switch is being created
		if ((connection.dpid >= 1 and connection.dpid <= 3) or connection.dpid == 31):  # the 3 switches and dcs31
			self.switch_setup()
		elif (connection.dpid == 21):
			self.cores21_setup()
		else:
			print ("UNKNOWN SWITCH")
			exit(1)

	def switch_setup(self):
		#put switch 1 rules here

		msg_flood = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD),
		                            priority = 100)

		self.connection.send(msg_flood)

  	def cores21_setup(self):
		#put core switch rules here

		# drop packets from hnotrust sometimes (see spec)
		# first one drops all IP communication from hnotrust to serv1
		# second one drops all ICMP traffic from hnotrust
		hnotrust_in1 = of.ofp_flow_mod(match = of.ofp_match(nw_src = IPs["hnotrust"], nw_dst = IPs["serv1"], dl_type = 0x0800),
									 priority = 200)
		hnotrust_in2 = of.ofp_flow_mod(match = of.ofp_match(nw_src = IPs["hnotrust"], dl_type = 0x0800, nw_proto = 1),
									 priority = 200)

		# hook up connections for all the other hosts
		h10 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPs["h10"]),
									 action = of.ofp_action_output(port = 1),
									 priority = 100)
		h20 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPs["h20"]),
									 action = of.ofp_action_output(port = 2),
									 priority = 100)
		h30 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPs["h30"]),
									 action = of.ofp_action_output(port = 3),
									 priority = 100)
		serv1 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPs["serv1"]),
									 action = of.ofp_action_output(port = 4),
									 priority = 100)
		# it is ok to send packets TO hnotrust
		hnotrust_out = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPs["hnotrust"]),
									 action = of.ofp_action_output(port = 5),
									 priority = 100)

		broadcast = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD),
									priority = 50)

		self.connection.send(hnotrust_in1)
		self.connection.send(hnotrust_in2)
		
		self.connection.send(h10)
		self.connection.send(h20)
		self.connection.send(h30)
		self.connection.send(serv1)
		self.connection.send(hnotrust_out)

		self.connection.send(broadcast)

	#used in part 4 to handle individual ARP packets
	#not needed for part 3 (USE RULES!)
	#causes the switch to output packet_in on out_port
	def resend_packet(self, packet_in, out_port):
		msg = of.ofp_packet_out()
		msg.data = packet_in
		action = of.ofp_action_output(port = out_port)
		msg.actions.append(action)
		self.connection.send(msg)

	def _handle_PacketIn (self, event):
		"""
		Packets not handled by the router rules will be
		forwarded to this method to be handled by the controller
		"""

		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp # The actual ofp_packet_in message.
		print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Part3Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
