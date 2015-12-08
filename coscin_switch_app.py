# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A frenetic app that acts mostly like a switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics

import sys, array, logging, time, binascii, datetime
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
from ryu.lib.packet import packet, ethernet, vlan, arp
from ryu.ofproto import ether
from tornado.ioloop import IOLoop

def get(pkt,protocol):
  for p in pkt:
    if p.protocol_name == protocol:
      return p

class CoscinSwitchApp(frenetic.App):
  client_id = "coscin_switch"
  frenetic_http_host = "localhost"
  frenetic_http_port = "9000"

  # The switch can be in one of three states
  STATE_INITIAL_CONFIG = 0
  STATE_ROUTER_LEARNING = 1
  STATE_NORMAL_OPERATION = 2
  state = STATE_INITIAL_CONFIG

  switches = {}

  # In later incarnations, this will get dynamically changed to 0, 1 or 2
  # depending on the utilization.  The paths for now are:
  #  0:  192.168.156.* -> 192.168.157.*
  #  1:  192.168.158.* -> 192.168.159.*
  #  2:  192.168.160.* -> 192.168.161.*

  paths = [ 
    ("192.168.156", "192.168.157"),
    ("192.168.158", "192.168.159"),
    ("192.168.160", "192.168.161")
  ]
  current_path = 0

  # hosts = { mac1 => (sw1, port1), mac2 => (sw2, port2), ... }
  # where hoplistn is the next_hop table for each switch: [(sw1, port1), (sw2, port2), etc.] 
  hosts = {}

  # We maintain our own little ARP table for the router IP's
  arp_cache = {}

  def dpid_to_switch(self, dpid):
    # Really simple for now - make it data driven later
    if dpid == 95073481681482:
      return "ithaca"
    elif dpid == 200171111126854:
      return "nyc"
    else:
      return "UKNOWN"

  def switch_to_dpid(self, sw):
    if sw == "ithaca":
      return 95073481681482
    elif sw == "nyc":
      return 200171111126854
    else:
      return 0

  def __init__(self):
    frenetic.App.__init__(self) 

  def capture_arp_requests_policy(self):
    # ARP packets looking for the default gateway 56.1 will be occurring right away.
    # The 56.1 interface is virtual, and we map it to either 156.1, 158.1 or 160.1 
    # depending on the state.  
    ithaca_outgoing = Filter( \
      Test(Switch(self.switch_to_dpid("ithaca"))) & \
      Test(EthType(0x806)) &
      Test(IP4Dst("192.168.56.1"))
    ) >> Mod(Location(Pipe("coscin_switch_app")))
    nyc_incoming = Filter( \
      Test(Switch(self.switch_to_dpid("nyc"))) & \
      Test(EthType(0x806)) &
      Test(IP4Dst("192.168.157.100"))
    ) >> Mod(Location(Pipe("coscin_switch_app")))
    nyc_outgoing = Filter( \
      Test(Switch(self.switch_to_dpid("nyc"))) & \
      Test(EthType(0x806)) &
      Test(IP4Dst("192.168.57.1"))
    ) >> Mod(Location(Pipe("coscin_switch_app")))
    ithaca_incoming = Filter( \
      Test(Switch(self.switch_to_dpid("ithaca"))) & \
      Test(EthType(0x806)) &
      Test(IP4Dst("192.168.156.100"))
    ) >> Mod(Location(Pipe("coscin_switch_app")))
    return Union([ ithaca_outgoing, nyc_incoming, nyc_outgoing, ithaca_incoming ])

  def preferred_route_policy(self, switch_id, port_id, dest_ip):
    # TODO: renumber the xx network to the 1xx network, leaving host in place
    if switch_id == "ithaca":
      new_src = self.paths[self.current_path][0] + ".100"
      new_dst = self.paths[self.current_path][1] + ".100"
    else:
      new_src = self.paths[self.current_path][1] + ".100"
      new_dst = self.paths[self.current_path][0] + ".100"

    output_actions = Seq([
      Mod(IP4Src(new_src)), 
      Mod(IP4Dst(new_dst)),
      # TODO: Need to look up the port based on the new src or dest 
      Mod(Location(Physical(2)))
    ]) 
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch_id))) & \
      Test(EthType(0x800)) & \
      Test(Location(Physical(port_id))) & \
      Test(IP4Dst(dest_ip))
    ) >> output_actions 

  def reverse_preferred_route_policy(self, switch_id, port_id, dest_ip):
    # TODO: renumber the xx network to the 1xx network, leaving host in place
    if switch_id == "nyc":
      new_src = "192.168.56.100"
      new_dst = "192.168.57.100"
    else:
      new_src = "192.168.57.100"
      new_dst = "192.168.56.100"

    output_actions = Seq([
      Mod(IP4Src(new_src)), 
      Mod(IP4Dst(new_dst)), 
      Mod(Location(Physical(1)))
    ]) 
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch_id))) & \
      Test(EthType(0x800)) & \
      Test(Location(Physical(port_id))) & \
      Test(IP4Dst(dest_ip))
    ) >> output_actions 

  def direct_route_policy(self, switch_id, new_port_id, dest_ip, renumber_src_ip):
    output_actions = Seq([
      Mod(IP4Src(renumber_src_ip)), 
      Mod(Location(Physical(new_port_id)))
    ]) 
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch_id))) & \
      Test(EthType(0x800)) & \
      Test(Location(Physical(1))) & \
      Test(IP4Dst(dest_ip))
    ) >> output_actions 

  def normal_operation_policy(self):
    return Union([
      self.capture_arp_requests_policy(),
      self.preferred_route_policy("ithaca", 1, "192.168.57.100"),
      self.preferred_route_policy("nyc", 1, "192.168.56.100"),
      self.reverse_preferred_route_policy("nyc", 2, "192.168.157.100"),
      self.reverse_preferred_route_policy("ithaca", 2, "192.168.156.100"),
      self.direct_route_policy("ithaca",2,"192.168.157.100","192.168.156.100"),
      self.direct_route_policy("nyc",2,"192.168.156.100","192.168.157.100")
    ])

  # Send payload to all ports  
  def flood_indiscriminately(self, dpid, payload):
    output_actions = [ Output(Physical(p)) for p in self.switches[self.dpid_to_switch(dpid)] ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(dpid, payload, output_actions)

  def send_arp_request(self, dpid, src_ip, target_ip):
    # It's unclear what the source should be, since the switch has no mac or IP address.
    # It just hears all replies and picks out the interesting stuff.
    src_mac = "00:de:ad:00:be:ef"
    dst_mac = "ff:ff:ff:ff:ff:ff"
    e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_ARP)
    pkt = arp.arp_ip(arp.ARP_REQUEST, src_mac, src_ip, "00:00:00:00:00:00", target_ip)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(pkt)
    p.serialize()
    payload = NotBuffered(binascii.a2b_base64(binascii.b2a_base64(p.data)))
    logging.info("Sending Arp Request to "+target_ip)
    self.flood_indiscriminately(dpid, payload)

  def send_network_arp_request(self, dpid, target_ip_net):
    src_ip = target_ip_net + ".250"
    dst_ip = target_ip_net + ".1"
    self.send_arp_request(dpid, src_ip, dst_ip)

  def arp_reply(self, dpid, port_id, src_mac, src_ip, target_mac, target_ip):
    # Not sure if the src is right.  We should be answering "us", as in the switch,
    # but the mac address of "us" is unclear.  
    e = ethernet.ethernet(dst=src_mac, src=target_mac, ethertype=ether.ETH_TYPE_ARP)
    # Note for the reply we flip the src and target, as per ARP rules
    pkt = arp.arp_ip(arp.ARP_REPLY, target_mac, target_ip, src_mac, src_ip)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(pkt)
    p.serialize()
    payload = NotBuffered(binascii.a2b_base64(binascii.b2a_base64(p.data)))
    self.pkt_out(dpid, payload, [Output(Physical(port_id))])

  def arp_entry(self, target_ip):
    if target_ip in arp_cache:
      return arp_cache[target_ip]

  def packet_in(self, dpid, port_id, payload):
    if self.state == self.STATE_INITIAL_CONFIG:
      logging.info("Packets received before initialization, dropping" )
    elif self.state == self.STATE_ROUTER_LEARNING:
      self.packet_in_router_learning(dpid, port_id, payload)
    else:
      self.packet_in_normal_operation(dpid, port_id, payload)

  def packet_in_router_learning(self, dpid, port_id, payload):
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'arp')
    switch = self.dpid_to_switch(dpid)
    logging.info("Received "+p.src_ip+" -> ("+str(switch)+", "+str(port_id)+") -> "+p.dst_ip)
    self.arp_cache[p.src_ip] = p.src_mac
    if len(self.arp_cache) >= len(self.paths) * 2 + 2:
      logging.info("Switching to Normal mode" )
      self.update(self.normal_operation_policy())
      self.state = self.STATE_NORMAL_OPERATION

  def packet_in_normal_operation(self, dpid, port_id, payload):
    # Right now, only ARP packets come to the controller
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'arp')
    switch = self.dpid_to_switch(dpid)
    logging.info("Received "+p.src_ip+" -> ("+str(switch)+", "+str(port_id)+") -> "+p.dst_ip)
    # TODO: Learn mac address

    if p.dst_ip == "192.168.56.1":
      real_dest_ip = self.paths[self.current_path][0] + ".1"
      real_dest_mac = self.arp_cache[real_dest_ip]
    elif p.dst_ip == "192.168.157.100" or p.src_ip == "192.168.159.100" or p.src_ip == "192.168.161.100":
      real_dest_ip = "192.168.57.100"
      real_dest_mac = self.arp_cache[real_dest_ip]
    elif p.dst_ip == "192.168.57.1":
      real_dest_ip = self.paths[self.current_path][1] + ".1"
      real_dest_mac = self.arp_cache[real_dest_ip]
    elif p.dst_ip == "192.168.156.100" or p.src_ip == "192.168.158.100" or p.src_ip == "192.168.160.100":
      real_dest_ip = "192.168.56.100"
      real_dest_mac = self.arp_cache[real_dest_ip]
    self.arp_reply(dpid, port_id, p.src_mac, p.src_ip, real_dest_mac, p.dst_ip)

  def router_learning_policy(self):
    # In the intial config, grab all ARP replies for ourselves
    return Filter( \
      Test(EthType(0x806)) 
      # TODO: We may want to filter only replies
    ) >> Mod(Location(Pipe("coscin_switch_app")))

  def learn_routers(self):
    logging.info("Switching to Router Learning mode")
    self.state = self.STATE_ROUTER_LEARNING
    # Send out ARP packets for all router interfaces to learn their mac addresses.  The
    # packet_in_router will handle the replies as they arrive
    for path in self.paths:
      ithaca_router_net = path[0]
      self.send_network_arp_request(self.switch_to_dpid("ithaca"), ithaca_router_net)
      nyc_router_net = path[1] 
      self.send_network_arp_request(self.switch_to_dpid("nyc"), nyc_router_net)
    # TODO: This is a little discomforting, as it requires hosts to be up when app is
    # started.  Might need to do a little ARP spoofing.  
    self.send_arp_request(self.switch_to_dpid("ithaca"), "192.168.156.250", "192.168.56.100")
    self.send_arp_request(self.switch_to_dpid("nyc"), "192.168.157.250", "192.168.57.100")

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
      logging.info("Connected to Frenetic - Switches: "+str(self.switches))
      logging.info("Installing router learning rules")
      self.update(self.router_learning_policy())
      logging.info("Pausing 2 seconds to allow rules to be installed")
      IOLoop.instance().add_timeout(datetime.timedelta(seconds=2), self.learn_routers)

    # If Frenetic went down, it'll call connected() when it comes back up.  In that case, just 
    # resend the current policies
    if self.state == self.STATE_NORMAL_OPERATION:
      self.update(self.policy())
    else:
      self.current_switches(callback=handle_current_switches) 

if __name__ == '__main__':
  logging.basicConfig(stream = sys.stderr, format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

  logging.info("*** CoSciN Switch Application Begin")
  app = CoscinSwitchApp()
  app.start_event_loop()