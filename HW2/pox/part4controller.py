# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)


log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

arpTable = {}

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

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
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    #put switch 1 rules here
    msg_s1 = of.ofp_flow_mod(match = of.ofp_match(nw_src = IPS["hnotrust"][0], 
                                                  dl_type = 0x0800, 
                                                  nw_proto = 1),
                              priority = 100)
    msg_flood = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD), 
                                priority = 50)

    self.connection.send(msg_s1)
    self.connection.send(msg_flood)


  def s2_setup(self):
    #put switch 2 rules here
    msg_s2 = of.ofp_flow_mod(match = of.ofp_match(nw_src = IPS["hnotrust"][0],
                                                  dl_type = 0x0800,
                                                  nw_proto = 1),
                              priority = 100)
    msg_flood = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD), 
                                priority = 50)

    self.connection.send(msg_s2)
    self.connection.send(msg_flood)


  def s3_setup(self):
    #put switch 3 rules here
    msg_s3 = of.ofp_flow_mod(match = of.ofp_match(nw_src = IPS["hnotrust"][0],
                                                  dl_type = 0x0800,
                                                  nw_proto = 1),
                              priority = 100)
    msg_flood = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD), 
                                priority = 50)
    self.connection.send(msg_s3)
    self.connection.send(msg_flood)


  def cores21_setup(self):
    #put core switch rules here
    
    # may need to remove these individual rule!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    msg_cores1 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPS["h10"][0]),
                                  action = of.ofp_action_output(port = 1),
                                  priority = 100)
    msg_cores2 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPS["h20"][0]),
                                  action = of.ofp_action_output(port = 2),
                                  priority = 100)
    msg_cores3 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPS["h30"][0]),
                                  action = of.ofp_action_output(port = 3),
                                  priority = 100)
    msg_cores4 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPS["serv1"][0]),
                                  action = of.ofp_action_output(port = 4),
                                  priority = 100)
    msg_cores5 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_dst = IPS["hnotrust"][0]),
                                  action = of.ofp_action_output(port = 5),
                                  priority = 100)
    
    self.connection.send(msg_cores1)
    self.connection.send(msg_cores2)
    self.connection.send(msg_cores3)
    self.connection.send(msg_cores4)
    self.connection.send(msg_cores5)

    msg_arp = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0806), 
                              action = of.ofp_action_output(port = of.OFPP_CONTROLLER),
                              priority = 100)
    msg_ip = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800),
                            action = of.ofp_action_output(port = of.OFPP_CONTROLLER),
                            priority = 200)
    self.connection.send(msg_arp)
    self.connection.send(msg_ip)


    broadcast = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD), priority = 50)
    self.connection.send(broadcast)


  def dcs31_setup(self):
    #put datacenter switch rules here
    msg_dcs31 = of.ofp_flow_mod(match = of.ofp_match(dl_type = 0x0800, nw_src = IPS["hnotrust"][0]),
                              priority = 100)
    msg_flood = of.ofp_flow_mod(action = of.ofp_action_output(port = of.OFPP_FLOOD), 
                                priority = 50)
    self.connection.send(msg_dcs31)
    self.connection.send(msg_flood)



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
    dpid = event.dpid
    inport = event.port
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    if isinstance(packet.next, arp):
      print("arp recved.......")
      a = packet.next

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:
            
            src_ip = a.protosrc
            target_ip = a.protodst
            arpTable[src_ip] = (inport, target_ip)

            if a.opcode == arp.REQUEST:
              print("table: ", arpTable, "protodst: ", a.protodst)
              print("hwsrc: ", a.hwsrc, " hwdst: ", a.hwdst)
              print("protosrc: ", a.protosrc, " protodst: ", a.protodst)

              if a.protosrc in arpTable:
                print("sending!!!")
                r = arp()
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protodst = a.protosrc
                r.protosrc = a.protodst
                r.hwsrc = dpid_to_mac(dpid)
                e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwsrc)
                e.set_payload(r)

                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                msg.in_port = inport
                event.connection.send(msg)
                return
            # arpTable[a.protosrc] = Entry(inport, packet.src)
            # if a.opcode == arp.REQUEST:
            #   print("Dict: ", arpTable, " next protodst: ", a.protodst)
              
            #   if a.protodst in arpTable:
            #     print("composing ARP reply...............")
            #     r = arp()
            #     r.hwtype = a.hwtype
            #     r.prototype = a.prototype
            #     r.hwlen = a.hwlen
            #     r.protolen = a.protolen
            #     r.opcode = arp.REPLY
            #     r.hwdst = a.hwsrc
            #     r.protodst = a.protosrc
            #     r.protosrc = a.protodst
            #     r.hwsrc = arpTable[a.protodst].mac
            #     e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwsrc)
            #     e.set_payload(r)

            #     msg = of.ofp_packet_out()
            #     msg.data = e.pack()
            #     msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            #     msg.in_port = inport
            #     event.connection.send(msg)
            #     return

    
    elif isinstance(packet.next, ipv4):
        print("ippacket reved.....")
        # TODO: 
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