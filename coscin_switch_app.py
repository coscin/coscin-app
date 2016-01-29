# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A frenetic app that acts mostly like a switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics

import sys, logging, time, binascii, datetime
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
# Temporary until we merge streamlined sytnax into master
from streamlined_syntax import *
from ryu.lib.packet import packet, ethernet, vlan, arp, ipv4
from ryu.ofproto import ether
from tornado.ioloop import IOLoop
from tornado.ioloop import PeriodicCallback
from net_utils import NetUtils
from policies import Policies
from network_information_base import NetworkInformationBase
from arp_handler import ArpHandler
from broadcast_handler import BroadcastHandler
from intranet_handler import IntranetHandler
from cross_campus_handler import CrossCampusHandler

# Interval in milliseconds
PREFERRED_PATH_ADJUSTMENT_INTERVAL = 5000

class CoscinSwitchApp(frenetic.App):
  client_id = "coscin_switch"
  frenetic_http_host = "localhost"
  frenetic_http_port = "9000"

  # The switch can be in one of three states
  STATE_INITIAL_CONFIG = 0
  STATE_ROUTER_LEARNING = 1
  STATE_NORMAL_OPERATION = 2
  state = STATE_INITIAL_CONFIG

  # Used as destination Mac for ARP replies that we ignore
  BOGUS_MAC = "00:de:ad:00:be:ef"

  def __init__(self, config_file='laptop_demo_network.json'):
    frenetic.App.__init__(self) 
    nib = NetworkInformationBase()
    self.nib = nib
    nib.load_config(config_file)

    self.arp_handler = ArpHandler(self, nib)
    self.intranet_handler = IntranetHandler(self, nib)
    self.cross_campus_handler = CrossCampusHandler(self, nib)
    #self.broadcast_handler = BroadcastHandler(self, nib)

  ##################################
  # Common operations

  # Send payload to all ports  
  def flood(self, switch, except_port, payload):
    flood_to_ports = [ p for p in self.nib.switches[switch] if p != except_port ]
    output_actions = [ Output(Physical(p)) for p in flood_to_ports ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.nib.switch_to_dpid(switch), payload, output_actions)

  def arp_payload(self, e, pkt):
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(pkt)
    p.serialize()
    return NotBuffered(binascii.a2b_base64(binascii.b2a_base64(p.data)))

  def send_arp_request(self, switch, src_ip, target_ip):
    # It's unclear what the source should be, since the switch has no mac or IP address.
    # It just hears all replies and picks out the interesting stuff.
    src_mac = self.BOGUS_MAC
    dst_mac = "ff:ff:ff:ff:ff:ff"
    e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_ARP)
    pkt = arp.arp_ip(arp.ARP_REQUEST, src_mac, src_ip, "00:00:00:00:00:00", target_ip)
    payload = self.arp_payload(e, pkt)
    logging.info("Sending Arp Request to "+target_ip)
    # None means the request will go out every available port
    self.flood(switch, None, payload)

  def send_arp_request_router_interface(self, switch, target_ip_net):
    # Note this may not or may not be a real host, but the reply will always come back to the switch anyway.
    # TODO: host 250 is appropriate for /24 subnets, but not anything smaller
    src_ip = NetUtils.ip_for_network(target_ip_net, 250)
    dst_ip = NetUtils.ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
    self.send_arp_request(switch, src_ip, dst_ip)

  def update_and_clear_dirty(self):
    self.update(self.normal_operation_policy())
    self.nib.clear_dirty()

  ########################
  # Frenetic Dispatchers

  def connected(self):
    def handle_current_switches(switches):
      self.nib.save_switches_and_ports(switches)

      logging.info("Connected to Frenetic - Switches: "+self.nib.switch_description())
      logging.info("Installing router learning rules")
      self.update(self.router_learning_policy())

      logging.info("Pausing 2 seconds to allow rules to be installed")
      IOLoop.instance().add_timeout(datetime.timedelta(seconds=2), self.learn_routers)

    # If Frenetic went down, it'll call connected() when it comes back up.  In that case, just 
    # resend the current policies
    if self.state == self.STATE_NORMAL_OPERATION:
      self.update_and_clear_dirty()
    else:
      # Turn on remove_tail_drops to get around issue 463
      #self.config( CompilerOptions("empty", "IP4Dst < EthType < Location < IP4Src < Switch", True, False, True) )
      self.current_switches(callback=handle_current_switches) 

  def packet_in(self, dpid, port, payload):
    if self.state == self.STATE_INITIAL_CONFIG:
      logging.info("Packets received before initialization, dropping" )
    elif self.state == self.STATE_ROUTER_LEARNING:
      self.packet_in_router_learning(dpid, port, payload)
    else:
      self.packet_in_normal_operation(dpid, port, payload)

  # TODO: Bizarrely, port_up events from an HP switch are reported as port_down and vice-versa.
  # I don't know if the problem is in the switch, Frenetic, or the language bindings.  
  def port_down(self, dpid, port):
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Port up: "+switch+"/"+str(port))
    # If port comes up, remove any learned macs on it (probably won't be any).  This is necessary
    # in case port_down was not fired.   
    if self.nib.unlearn_mac_on_port(switch, port):
      self.update_and_clear_dirty()

  def port_up(self, dpid, port):
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Port down: "+switch+"/"+str(port))
    # If port goes down, remove any learned macs on it
    if self.nib.unlearn_mac_on_port(switch, port):
      self.update_and_clear_dirty()

  def switch_up(self, dpid, ports):
    switch = self.nib.dpid_to_switch(dpid)
    # If we've seen this switch before, just return.  Otherwise add the ports to unlearned. 
    if self.nib.contains_switch(switch):
      return
    self.nib.add_switches_and_ports(switch, ports)
    self.update_and_clear_dirty()
    logging.info("Updated Switches: "+self.nib.switch_description())

  # Don't remove switch info when it supposedly goes down.  That way if it comes back up 
  # without properly signalling switch_up, we're not over a barrel.  
  def switch_down(self, dpid):
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Switch down: "+switch)

  ########################
  # Router Learning Mode
  # We assume all router interfaces are up for all alternate paths and that they're fixed for the duration
  # of the controller.  In this mode, we send ARP requests to all paths so we can learn (1) their Mac address 
  # (2) their switch port.  

  # RouterLearningHandler.packet_in
  def packet_in_router_learning(self, dpid, port, payload):
    p = NetUtils.packet(payload, 'arp')
    p_eth = NetUtils.packet(payload, 'ethernet')
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Received ("+str(p_eth.ethertype)+"): "+p_eth.src+"/"+p.src_ip+" -> ("+switch+", "+str(port)+") -> "+p.dst_ip)

    # Supposedly, the src mac in the ARP reply and the ethernet frame itself should be the
    # the same, but that's not always the case.  The Ethernet frame is definitive. 
    self.nib.learn(switch, self.nib.ROUTER_PORT, port, p_eth.src, p.src_ip)
    self.waiting_for_router_arps -= 1
    if self.waiting_for_router_arps == 0:
      self.normal_mode()

  # RouterLearningHandler.policy
  def router_learning_policy(self):
    # In the intial config, grab all ARP replies for ourselves
    return Filter( Policies.is_arp() ) >> Policies.send_to_controller()

  # RouterLearningHandler.start
  def learn_routers(self):
    logging.info("Switching to Router Learning mode")
    self.state = self.STATE_ROUTER_LEARNING
    self.waiting_for_router_arps = 0
    for side in [ "ithaca", "nyc" ]:
      if self.nib.switch_present(side):
        self.send_arp_request_router_interface(side, self.nib.actual_net_for(side))
        self.waiting_for_router_arps += 1

  ########################
  # Normal Mode
  # This basically handles all traffic afterwards.  It learns host ports coming up.  

  def normal_mode(self):
    logging.info("Switching to Normal mode.  Host ports to learn: "+self.nib.unlearned_ports_description())
    self.update(self.normal_operation_policy())
    self.state = self.STATE_NORMAL_OPERATION

  def normal_operation_policy(self):
    return Union([
      self.arp_handler.policy(),
      #self.broadcast_handler.policy(),
      self.intranet_handler.policy(),
      self.cross_campus_handler.policy()
    ])

  def packet_in_normal_operation(self, dpid, port, payload):
    switch = self.nib.dpid_to_switch(dpid)
    # TODO: deal with non-IP packets, although that's fairly unlikely
    p_eth = NetUtils.packet(payload, 'ethernet')
    if p_eth.ethertype == 0x0806:
      p_arp = NetUtils.packet(payload, 'arp')
      src_ip = p_arp.src_ip
      dst_ip = p_arp.dst_ip
    elif p_eth.ethertype == 0x0800:
      p_ip = NetUtils.packet(payload, 'ipv4')
      src_ip = p_ip.src
      dst_ip = p_ip.dst
    else:
      src_ip = '0.0.0.0'
      dst_ip = '0.0.0.0'
      logging.info("Received packet of type "+str(p_eth.ethertype))

    # TODO: Handle DHCP requests someday, ... maybe
    if src_ip == '0.0.0.0':
      return

    if self.nib.learn(switch, self.nib.ENDHOST_PORT, port, p_eth.src, src_ip):
      self.nib.set_dirty()

    logging.info("Received ("+str(p_eth.ethertype)+"): "+p_eth.src+"/"+src_ip+" -> ("+switch+", "+str(port)+") -> "+dst_ip)

    self.arp_handler.packet_in(dpid, port, payload)
    #self.broadcast_handler.packet_in(dpid, port, payload)
    self.intranet_handler.packet_in(dpid, port, payload)
    self.cross_campus_handler.packet_in(dpid, port, payload)

    if self.nib.is_dirty():
      self.update_and_clear_dirty()

  def set_preferred_path(self, new_preferred_path):
    # Send pings
    preferred_path = self.nib.get_preferred_path() 
    logging.info("Adjusting preferred path from "+str(preferred_path)+" to "+str(new_preferred_path))
    # Setting a preferred path is pretty hard on the switch - it sends a whole new flow table
    # so don't do it unless absolutely necessary
    if preferred_path == new_preferred_path:
      logging.info("No change.")
    else:
      self.nib.set_preferred_path(new_preferred_path)
      self.update(self.normal_operation_policy())

def adjust_preferred_path():
  app.set_preferred_path(1)

if __name__ == '__main__':
  logging.basicConfig(stream = sys.stderr, format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

  logging.info("*** CoSciN Switch Application Begin")
  if len(sys.argv) > 1:
    app = CoscinSwitchApp(sys.argv[1])
  else:
    app = CoscinSwitchApp()
  #PeriodicCallback(adjust_preferred_path, PREFERRED_PATH_ADJUSTMENT_INTERVAL).start()
  app.start_event_loop()
