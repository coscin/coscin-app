# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A frenetic app that acts mostly like a switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics

import sys, array, logging, time, binascii, datetime, json
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
from ryu.lib.packet import packet, ethernet, vlan, arp
from ryu.ofproto import ether
from ryu.lib import ip
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

  # index of alternate_path being used now
  current_path = 0

  # hosts = { mac1 => (sw1, port1), mac2 => (sw2, port2), ... }
  hosts = {}

  # endhosts = { "ithaca" => [(host_portion_of_ip), ...], "nyc" => ... }
  # This is more for enumerating end user hosts on each end network
  endhosts = { "ithaca": [], "nyc": []}

  # We maintain our own little ARP table for the router IP's
  arp_cache = {}

  def dpid_to_switch(self, dpid):
    for sw in ["ithaca", "nyc"]:
      if dpid == self.config[sw]["dpid"]:
        return sw
    return "UKNOWN"

  def switch_to_dpid(self, sw):
    if sw in self.config:
      return self.config[sw]["dpid"]
    else:
      return 0

  def __init__(self, config_file='laptop_demo_network.json'):
    frenetic.App.__init__(self) 

    f = open(config_file, "r")
    self.config = json.load(f)
    f.close()

  ##################################
  # Common operations

  # Given a network and a host, construct an IP, real or imagined.  A lot of the path mapping
  # is done this way, so host x.100 on the real network gets mapped to the bogus addresses 
  # x1.100, x2.100 and x3.100 for each of the paths
  def ip_for_network(net, host):
    # The net is assumed of the form xx.xx.xx.xx/mask using the CIDR notation, as per IP custom
    (net, mask) = split(net, "/")
    # Most of the time, the net is in the proper form with zeroes in the right places, but we 
    # run it through a subnet filter just in case it isn't.
    net_int = ip4_to_int(net)
    net_int = net && (mask 1s << (32-mask))
    ip_int = net && int(host)
    return ipv4_to_str(ip_int)
    
  # Send payload to all ports  
  def flood_indiscriminately(self, switch, payload):
    output_actions = [ Output(Physical(p)) for p in self.switches[switch] ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.switch_to_dpid(switch), payload, output_actions)

  def arp_payload(e, pkt):
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(pkt)
    p.serialize()
    return NotBuffered(binascii.a2b_base64(binascii.b2a_base64(p.data)))

  def send_arp_request(self, switch, src_ip, target_ip):
    # It's unclear what the source should be, since the switch has no mac or IP address.
    # It just hears all replies and picks out the interesting stuff.
    src_mac = "00:de:ad:00:be:ef"
    dst_mac = "ff:ff:ff:ff:ff:ff"
    e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_ARP)
    pkt = arp.arp_ip(arp.ARP_REQUEST, src_mac, src_ip, "00:00:00:00:00:00", target_ip)
    payload = arp_payload(e, pkt)
    logging.info("Sending Arp Request to "+target_ip)
    self.flood_indiscriminately(self.switch_to_dpid(switch), payload)

  def send_arp_request_router_interface(self, switch, target_ip_net):
    # Note this may not or may not be a real host, but the reply will always come back to the switch anyway.
    src_ip = ip_for_network(target_ip_net, 250)
    dst_ip = ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
    self.send_arp_request(switch, src_ip, dst_ip)

  def arp_reply(self, switch, port_id, src_mac, src_ip, target_mac, target_ip):
    # Not sure if the src is right.  We should be answering "us", as in the switch,
    # but the mac address of "us" is unclear.  
    e = ethernet.ethernet(dst=src_mac, src=target_mac, ethertype=ether.ETH_TYPE_ARP)
    # Note for the reply we flip the src and target, as per ARP rules
    pkt = arp.arp_ip(arp.ARP_REPLY, target_mac, target_ip, src_mac, src_ip)
    payload = arp_payload(e, pkt)
    self.pkt_out(self.switch_to_dpid(switch), payload, [Output(Physical(port_id))])

  def send_to_controller():
    Mod(Location(Pipe("coscin_switch_app")))

  def is_arp():
   Test(EthType(0x806))

  def at_ithaca():
    Test(Switch(self.switch_to_dpid("ithaca")))

  def at_nyc():
    Test(Switch(self.switch_to_dpid("nyc")))

  def dest_is(ip_net, ip_host):
    Test(IP4Dst(ip_for_network(ip_net, ip_host)))

  def dest_real_net(switch, ip_host):
    dest_is(self.config[switch]["network"], ip_host)
 
  ########################
  # Frenetic Dispatchers

  def connected(self):
    # If Frenetic went down, it'll call connected() when it comes back up.  In that case, just 
    # resend the current policies
    if self.state == self.STATE_NORMAL_OPERATION:
      self.update(self.policy())
    else:
      self.current_switches(callback=handle_current_switches) 

  def packet_in(self, dpid, port_id, payload):
    if self.state == self.STATE_INITIAL_CONFIG:
      logging.info("Packets received before initialization, dropping" )
    elif self.state == self.STATE_ROUTER_LEARNING:
      self.packet_in_router_learning(dpid, port_id, payload)
    else:
      self.packet_in_normal_operation(dpid, port_id, payload)

  ########################
  # Initial Config Mode

  def handle_current_switches(switches):
    # Convert ugly switch id to nice one
    self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
    logging.info("Connected to Frenetic - Switches: "+str(self.switches))
    logging.info("Installing router learning rules")
    self.update(self.router_learning_policy())
    logging.info("Pausing 2 seconds to allow rules to be installed")
    IOLoop.instance().add_timeout(datetime.timedelta(seconds=2), self.learn_routers)

  ########################
  # Router Learning Mode
  # We assume all router interfaces are up for all alternate paths and that they're fixed for the duration
  # of the controller.  In this mode, we send ARP requests to all paths so we can learn (1) their Mac address 
  # (2) their switch port.  

  def packet_in_router_learning(self, dpid, port_id, payload):
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'arp')
    switch = self.dpid_to_switch(dpid)
    logging.info("Received "+p.src_ip+" -> ("+switch+", "+str(port_id)+") -> "+p.dst_ip)
    self.arp_cache[p.src_ip] = p.src_mac
    if len(self.arp_cache) >= len(self.config.alternate_paths) * len(self.switches):
      self.normal_mode()

  def router_learning_policy(self):
    # In the intial config, grab all ARP replies for ourselves
    return Filter( is_arp() ) >> send_to_controller()

  def learn_routers(self):
    logging.info("Switching to Router Learning mode")
    self.state = self.STATE_ROUTER_LEARNING
    # Send out ARP packets for all router interfaces to learn their mac addresses.  The
    # packet_in_router will handle the replies as they arrive
    for path in self.config.alternate_paths:
      if "ithaca" in self.config:
        ithaca_router_net = path["ithaca"]
        self.send_arp_request_router_interface("ithaca", ithaca_router_net)
      if "nyc" in self.config:
        nyc_router_net = path["nyc"] 
        self.send_arp_request_router_interface("nyc", nyc_router_net)
    # TODO: This is a little discomforting, as it requires hosts to be up when app is
    # started.  Might need to do a little ARP spoofing.  
    # self.send_arp_request(self.switch_to_dpid("ithaca"), "192.168.156.250", "192.168.56.100")
    # self.send_arp_request(self.switch_to_dpid("nyc"), "192.168.157.250", "192.168.57.100")

  ########################
  # Normal Mode
  # This basically handles all traffic afterwards.  It learns host ports coming up.  

  def normal_mode(self):
    logging.info("Switching to Normal mode" )
    self.update(self.normal_operation_policy())
    self.state = self.STATE_NORMAL_OPERATION

  def capture_arp_requests_policy(self):

    # In normal mode, we capture ARP requests for IP's that don't really exist.  You can
    # think of them as symbolic links to the real IP.  First, we capture .1 address of
    # each of the endpoint networks

    policies = []
    policies << Filter(at_ithaca() & is_arp() & dest_real_net("ithaca", 1)) >> send_to_controller()
    policies << Filter(at_nyc() & is_arp() & dest_real_net("nyc", 1)) >> send_to_controller()

    # We also capture virtual host addresses for each side of the alternate path
    # These will get mapped to their actual host address once they've travelled through 
    # the NYC<->Ithaca path and reach their destination net

    for host in self.endhosts["ithaca"]:
      for path in self.config.alternate_paths:
        dest_net = path["ithaca"]
        policies << Filter( at_nyc() & is_arp() & dest_is(dest_net, host)) >> send_to_controller()

    for host in self.endhosts["nyc"]:
      for path in self.config.alternate_paths:
        dest_net = path["nyc"]
        policies << Filter( at_ithaca() & is_arp() & dest_is(dest_net, host)) >> send_to_controller()

    return policies

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


if __name__ == '__main__':
  logging.basicConfig(stream = sys.stderr, format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

  logging.info("*** CoSciN Switch Application Begin")
  app = CoscinSwitchApp()
  app.start_event_loop()