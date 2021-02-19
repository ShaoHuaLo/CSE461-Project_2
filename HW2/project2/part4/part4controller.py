# Part 4 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST


# class Entry(object):
#     """
#     Not strictly an ARP entry.
#     We use the port to determine which port to forward traffic out of.
#     We use the MAC to answer ARP replies.
#     We use the timeout so that if an entry is older than ARP_TIMEOUT, we
#     flood the ARP request rather than try to answer it ourselves.
#     """
#
#     def __init__(self, port, mac):
#         self.port = port
#         self.mac = mac
#
#     def __eq__(self, other):
#         if type(other) == tuple:
#             return (self.port, self.mac) == other
#         else:
#             return (self.port, self.mac) == (other.port, other.mac)
#
#     def __ne__(self, other):
#         return not self.__eq__(other)


log = core.getLogger()



def dpid_to_mac(dpid):
	return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class Part3Controller(object):
	"""
	A Connection object for that switch is passed to the __init__ function.
	"""

	def __init__(self, connection):
		print (connection.dpid)
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection
		self.arpTable = {}

		# This binds our PacketIn event listener
		connection.addListeners(self)
		# use the dpid to figure out what switch is being created
		if ((connection.dpid >= 1 and connection.dpid <= 3) or connection.dpid == 31):
			self.switch_setup()
		elif (connection.dpid == 21):
			self.cores21_setup()
		else:
			print ("UNKNOWN SWITCH")
			exit(1)

	def switch_setup(self):
		# put switch rules here
		msg_flood = of.ofp_flow_mod(action=of.ofp_action_output(port=of.OFPP_FLOOD),
		        priority=50)
		self.connection.send(msg_flood)

	def cores21_setup(self):
		# put core switch rules here
		hnotrust_ip = "172.16.10.100"
		serv1_ip = "10.0.4.10"
		# filters ipv4 communication from hnotrust to serv1
		hnotrust_in1 = of.ofp_flow_mod(match=of.ofp_match(nw_src=hnotrust_ip, nw_dst=serv1_ip, dl_type=0x0800),
										priority=200)
		# filters ipv4 ICMP communication from hnotrust to anything on the network
		hnotrust_in2 = of.ofp_flow_mod(match=of.ofp_match(nw_src=hnotrust_ip, dl_type=0x0800, nw_proto=1),
										priority=200)
		self.connection.send(hnotrust_in1)
		self.connection.send(hnotrust_in2)

	# used in part 4 to handle individual ARP packets
	# not needed for part 3 (USE RULES!)
	# causes the switch to output packet_in on out_port
	def resend_packet(self, packet_in, out_port):
		msg = of.ofp_packet_out()
		msg.data = packet_in
		action = of.ofp_action_output(port=out_port)
		msg.actions.append(action)
		self.connection.send(msg)

	def _handle_PacketIn(self, event):
		"""
		Packets not handled by the router rules will be
		forwarded to this method to be handled by the controller
		"""

		packet = event.parsed  # This is the parsed packet data.
		dpid = event.dpid
		inport = event.port

		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		if packet.type == packet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
			payload = packet.payload
			src_ip = payload.protosrc

			# add src_ip to arp table and set up ip connection if it isn't already in the arp table
			if src_ip not in self.arpTable or self.arpTable[src_ip][0] != inport:
				self.arpTable[src_ip] = (inport, payload.hwsrc)
				actions = []
				actions.append(of.ofp_action_dl_addr.set_dst(payload.hwsrc))
				actions.append(of.ofp_action_output(port=inport))
				ip_flow = of.ofp_flow_mod(match=of.ofp_match(dl_type=0x0800, nw_dst=src_ip),
										action=actions,
										priority=100)
				self.connection.send(ip_flow)

				# Make and send an ARP reply
				r = arp()
				r.hwtype = payload.hwtype
				r.prototype = payload.prototype
				r.hwlen = payload.hwlen
				r.protolen = payload.protolen
				r.opcode = arp.REPLY
				r.hwdst = payload.hwsrc
				r.protodst = payload.protosrc
				r.protosrc = payload.protodst
				r.hwsrc = dpid_to_mac(dpid)
				e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=payload.hwsrc)
				e.set_payload(r)
				self.resend_packet(e, inport)
				return

		print("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())


def launch():
	"""
	Starts the component
	"""
	def start_switch(event):
		log.debug("Controlling %s" % (event.connection,))
		Part3Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
