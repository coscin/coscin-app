# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A frenetic app that acts mostly like a switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics

import sys, array, logging, time, binascii, datetime
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
from network_information_base import NetworkInformationBase

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

  nib = NetworkInformationBase()

  def __init__(self, config_file='laptop_demo_network.json'):
    frenetic.App.__init__(self) 
    self.nib.load_config(config_file)

  ##################################
  # Common operations

  def packet(self, payload, protocol):
    pkt = packet.Packet(array.array('b', payload.data))
    for p in pkt:
      if p.protocol_name == protocol:
        return p
    return None

  # Send payload to all ports  
  def flood_indiscriminately(self, switch, payload):
    output_actions = [ Output(Physical(p)) for p in self.nib.ports_on_switch(switch) ]
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
    self.flood_indiscriminately(switch, payload)

  def send_arp_request_router_interface(self, switch, target_ip_net):
    # Note this may not or may not be a real host, but the reply will always come back to the switch anyway.
    # TODO: host 250 is appropriate for /24 subnets, but not anything smaller
    src_ip = NetUtils.ip_for_network(target_ip_net, 250)
    dst_ip = NetUtils.ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
    self.send_arp_request(switch, src_ip, dst_ip)

  def arp_reply(self, switch, port, src_mac, src_ip, target_mac, target_ip):
    e = ethernet.ethernet(dst=src_mac, src=target_mac, ethertype=ether.ETH_TYPE_ARP)
    # Note for the reply we flip the src and target, as per ARP rules
    pkt = arp.arp_ip(arp.ARP_REPLY, target_mac, target_ip, src_mac, src_ip)
    payload = self.arp_payload(e, pkt)
    self.pkt_out(self.nib.switch_to_dpid(switch), payload, [Output(Physical(port))])

  def gateway_ip(self, switch):
    return NetUtils.ip_for_network(self.nib.actual_net_for(switch), 1)

  def send_to_controller(self):
    return SendToController("coscin_switch_app")

  def is_arp(self):
    return EthTypeEq(0x806)

  def is_ip(self):
    return EthTypeEq(0x800)

  def at_switch(self, switch):
    return SwitchEq(self.nib.switch_to_dpid(switch))

  def at_switch_port(self, switch, port):
    #logging.info("at_switch_port("+switch+","+str(port)+")")
    return SwitchEq(self.nib.switch_to_dpid(switch)) & PortEq(port)

  def dest_real_net(self, switch):
    return self.to_dest_net(self.nib.actual_net_for(switch))

  def to_dest_net(self, net_and_mask):
    (net, mask) = NetUtils.net_mask(net_and_mask)
    return IP4DstEq(net,mask)

  def is_ip_from_to(self, src_ip, dest_ip):
    return self.is_ip() & IP4SrcEq(src_ip) & IP4DstEq(dest_ip)

  def destination_not_known_host_on_net(self, host_ip, dest_net):
    # Given an IP, find all src_dest pairs we've seen for this src, filter the dests down to 
    # those on the dest_net, and return a clause that doesn't match any of them
    preds = []
    for src_dest_pair in self.nib.get_ingress_src_dest_pairs():
      (src_ip, dst_ip) = src_dest_pair 
      if src_ip == host_ip and NetUtils.ip_in_network(dst_ip, dest_net):
        preds.append(IP4DstEq(dst_ip))
    if not preds:
      return true
    else:
      return Not(Or(preds))

  def src_dest_pair_not_learned(self, dest_net):
    # Given a destination net, find all learned src, dest pairs that match it and return
    # a clause that doesn't match any of them.
    preds = []
    for src_dest_pair in self.nib.get_egress_src_dest_pairs():
      (src_ip, dst_ip) = src_dest_pair 
      if NetUtils.ip_in_network(dst_ip, dest_net):
        preds.append(IP4SrcEq(src_ip) & IP4DstEq(dst_ip))
    if not preds:
      return true
    else:
      return Not(Or(preds))

  def ip_in_coscin_network(self, dst_ip):
    if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for("ithaca")):
      return True
    if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for("nyc")):
      return True    
    for ap in self.nib.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap["ithaca"]) or NetUtils.ip_in_network(dst_ip, ap["nyc"]):
        return True
    return False      

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
      self.update(self.normal_operation_policy())
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
      self.update(self.normal_operation_policy())

  def port_up(self, dpid, port):
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Port down: "+switch+"/"+str(port))
    # If port goes down, remove any learned macs on it
    if self.nib.unlearn_mac_on_port(switch, port):
      self.update(self.normal_operation_policy())

  def switch_up(self, dpid, ports):
    switch = self.nib.dpid_to_switch(dpid)
    # If we've seen this switch before, just return.  Otherwise add the ports to unlearned. 
    if self.nib.contains_switch(switch):
      return
    self.nib.add_switches_and_ports(switch, ports)
    logging.info("Updated Switches: "+self.nib.switch_description())

  # Don't remove switch info when it supposedly goes down. 
  def switch_down(self, dpid):
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Switch down: "+switch)

  ########################
  # Router Learning Mode
  # We assume all router interfaces are up for all alternate paths and that they're fixed for the duration
  # of the controller.  In this mode, we send ARP requests to all paths so we can learn (1) their Mac address 
  # (2) their switch port.  

  def packet_in_router_learning(self, dpid, port, payload):
    p = self.packet(payload, 'arp')
    p_eth = self.packet(payload, 'ethernet')
    switch = self.nib.dpid_to_switch(dpid)
    logging.info("Received ("+str(p_eth.ethertype)+"): "+p_eth.src+"/"+p.src_ip+" -> ("+switch+", "+str(port)+") -> "+p.dst_ip)

    # Supposedly, the src mac in the ARP reply and the ethernet frame itself should be the
    # the same, but that's not always the case.  The Ethernet frame is definitive. 
    self.nib.learn(switch, self.nib.ROUTER_PORT, port, p_eth.src, p.src_ip)
    self.waiting_for_router_arps -= 1
    if self.waiting_for_router_arps == 0:
      self.normal_mode()

  def router_learning_policy(self):
    # In the intial config, grab all ARP replies for ourselves
    return Filter( self.is_arp() ) >> self.send_to_controller()

  def learn_routers(self):
    logging.info("Switching to Router Learning mode")
    self.state = self.STATE_ROUTER_LEARNING
    self.waiting_for_router_arps = 0
    # Send out ARP packets for all router interfaces to learn their mac addresses.  The
    # packet_in_router will handle the replies as they arrive
    for path in self.nib.alternate_paths():
      if self.nib.switch_present("ithaca"):
        ithaca_router_net = path["ithaca"]
        self.send_arp_request_router_interface("ithaca", ithaca_router_net)
        self.waiting_for_router_arps += 1
      if self.nib.switch_present("nyc"):
        nyc_router_net = path["nyc"] 
        self.send_arp_request_router_interface("nyc", nyc_router_net)
        self.waiting_for_router_arps += 1

  ########################
  # Normal Mode
  # This basically handles all traffic afterwards.  It learns host ports coming up.  

  def normal_mode(self):
    logging.info("Switching to Normal mode.  Host ports to learn: "+self.nib.unlearned_ports_description())
    self.update(self.normal_operation_policy())
    self.state = self.STATE_NORMAL_OPERATION

  def capture_arp_requests_policy(self):
    policies = []
    for switch in self.nib.switches_present():
      # In normal mode, we capture ARP requests for IP's that don't really exist.  You can
      # think of them as symbolic links to the real IP.  We capture .1 address of
      # each of the endpoint networks, plus any real hosts on the net
      policies.append(Filter(self.at_switch(switch) & self.is_arp() & self.dest_real_net(switch)) >> self.send_to_controller())

      # And we capture ARP requests for the alternate paths.  These will always be for 
      # hosts that have no real estate on the imaginary link, as in 192.168.156.100 along 
      # the 192.168.156.* imaginary network.  This will be translated to the real net 192.168.56.100
      for ap in self.nib.alternate_paths():
        (net, mask) = NetUtils.net_mask(ap[switch])
        policies.append(Filter(self.at_switch(switch) & self.is_arp() & IP4DstEq(net,mask)) >> self.send_to_controller())

    return Union(policies)

  # For each end host, pick up all packets going to the destination network.  As we 
  # learn source host -> destination host pairs, we will add rules for that pair, making
  # more specific rules that will override this one.
  def capture_new_source_dest_pairs_policy(self):
    policies = []
    for switch in self.nib.switches_present():
      for endhost in self.nib.get_endhosts(switch):
        (host, host_port, host_mac, host_ip) = endhost
        opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
        dest_cdr = self.nib.actual_net_for(opposite_switch)
        (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)
        # logging.info("(dest_net,dest_mask) = ("+dest_net+","+str(dest_mask)+")")
        # Note we really don't have to test for source IP, but it's extra security
        policies.append(Filter( 
          self.at_switch_port(switch,host_port) & 
          self.is_ip() & 
          IP4SrcEq(host_ip) & 
          IP4DstEq(dest_net,dest_mask) & 
          self.destination_not_known_host_on_net(host_ip, dest_cdr)
        ) >> self.send_to_controller())
        for ap in self.nib.alternate_paths():
          dest_cdr = ap[opposite_switch]
          (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)
          policies.append(Filter( 
            self.at_switch_port(switch,host_port) & 
            self.is_ip() & 
            IP4SrcEq(host_ip) & 
            IP4DstEq(dest_net,dest_mask) &
            self.destination_not_known_host_on_net(host_ip, dest_cdr)
          ) >> self.send_to_controller())

      # Now handle incoming packets for all our home networks.  We need to learn
      # those (src, dest) pairs as well
      for ap in self.nib.alternate_paths():
        dest_cdr = ap[switch]
        (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)
        policies.append(Filter( 
          self.is_ip() & 
          IP4DstEq(dest_net,dest_mask) &
          self.src_dest_pair_not_learned(dest_cdr)
        ) >> self.send_to_controller())

    return Union(policies)

  def unlearned_ports_policy(self):
    is_at_unlearned_port = []
    unlearned_ports = self.nib.get_unlearned_ports()
    for switch, ports in unlearned_ports.iteritems():
      for port in ports:
        is_at_unlearned_port.append(self.at_switch_port(switch,port))
    return Filter(Or(is_at_unlearned_port)) >> self.send_to_controller()

  # TODO: This is a lot like send_along_preferred_path and send_along_direct_path, 
  # but in rule form
  def ingress_src_dest_pairs_policy(self):
    policies = []
    for src_dest_pair in self.nib.get_ingress_src_dest_pairs():
      (src_ip, dst_ip) = src_dest_pair
      switch = self.nib.switch_for_ip(src_ip)
      port = self.nib.port_for_ip(src_ip) 
      src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
      # If this is going to the preferred network, write a rule choosing the 
      # correct route here.
      opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
        # Get host from src_ip
        src_pref_net = self.preferred_net(switch)
        new_src = NetUtils.ip_for_network(src_pref_net, src_host)
        dest_host = NetUtils.host_of_ip(dst_ip, self.nib.actual_net_for(opposite_switch))
        new_dest = NetUtils.ip_for_network(self.preferred_net(opposite_switch), dest_host)

        preferred_net_gateway = NetUtils.ip_for_network(src_pref_net, 1)
        preferred_net_port = self.nib.port_for_ip(preferred_net_gateway) 

        output_actions = SetIP4Src(new_src) >> SetIP4Dst(new_dest) >> Send(preferred_net_port)
        policies.append(
          Filter( self.at_switch_port(switch, port) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )

      else: 
        # It's a direct path.  Find the path first.
        for ap in self.nib.alternate_paths():
          if NetUtils.ip_in_network(dst_ip, ap[opposite_switch]):
            alternate_path = ap
        new_src = NetUtils.ip_for_network(alternate_path[switch], src_host)
        direct_net_gateway = NetUtils.ip_for_network(alternate_path[switch], 1)
        direct_net_port = self.nib.port_for_ip(direct_net_gateway)
        direct_mac = self.nib.mac_for_ip(direct_net_gateway)
        output_actions = SetIP4Src(new_src) >> SetEthDst(direct_mac) >> Send(direct_net_port)
        policies.append(
          Filter( self.at_switch_port(switch, port) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )

    return Union(policies)

  # Egress src dest pairs are a little easier to deal with
  # TODO: This acts a lot like send_to_host
  def egress_src_dest_pairs_policy(self):
    policies = []
    for src_dest_pair in self.nib.get_egress_src_dest_pairs():
      (src_ip, dst_ip) = src_dest_pair 
      # Convert dst_ip to its real form.  First find out what the egress switch actually is:
      for ap in self.nib.alternate_paths():
        if NetUtils.ip_in_network(dst_ip, ap["ithaca"]): 
          switch = "ithaca" 
          imaginary_net = ap["ithaca"]
        elif NetUtils.ip_in_network(dst_ip, ap["nyc"]):
          switch = "nyc"
          imaginary_net = ap["nyc"]
      real_net = self.nib.actual_net_for(switch)
      dst_host = NetUtils.host_of_ip(dst_ip, imaginary_net)
      new_dest_ip = NetUtils.ip_for_network(real_net, dst_host)
      # If it's not in the ARP cache, it already has an ARP request on the way so ignore it for now.
      if self.nib.learned_ip(new_dest_ip):
        direct_net_port = self.nib.port_for_ip(new_dest_ip)
        new_src_ip = self.translate_alternate_net(src_ip)
        output_actions = SetIP4Src(new_src_ip) >> SetIP4Dst(new_dest_ip) >> Send(direct_net_port)
        policies.append(
          Filter( SwitchEq(self.nib.switch_to_dpid(switch)) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )
    return Union(policies)

  # Output rules for each pair of learned endhosts so intranet traffic can be handled nicely on 
  # the switch.
  # TODO: If the app is restarted but hosts are hanging onto ARP cache entries, they won't be able
  # to get packets to each other.  I'm letting this go for now because (1) intranet host
  # traffic is relatively rare (2) ARP cache entries usually timeout in 10 minutes anyway.  
  def intranet_policy(self):
    policies = []
    for switch in self.nib.switches_present():
      for src_endhost in self.nib.get_endhosts(switch):
        (_, src_port, _, src_ip) = src_endhost
        for dst_endhost in self.nib.get_endhosts(switch):
          (_, dst_port, _, dst_ip) = dst_endhost
          # No rule for a host to itself, obviously
          if src_ip != dst_ip:
            policies.append(
              Filter(self.is_ip_from_to(src_ip, dst_ip) & self.at_switch_port(switch, src_port) )
              >> Send(dst_port)
            )
    return Union(policies)

  def normal_operation_policy(self):
    return Union([
      self.capture_arp_requests_policy(),
      self.capture_new_source_dest_pairs_policy(),
      self.unlearned_ports_policy(),
      self.ingress_src_dest_pairs_policy(),
      self.egress_src_dest_pairs_policy(),
      self.intranet_policy()
    ])

  def preferred_net(self, switch):
    return self.nib.alternate_paths()[self.nib.get_preferred_path()][switch]

  def send_along_preferred_path(self, switch, src_ip, dst_ip, payload ):
    # Get host from src_ip
    src_pref_net = self.preferred_net(switch)
    src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
    # Translate this to the preferred path IP
    new_src = NetUtils.ip_for_network(src_pref_net, src_host)
    # And do the same for the destination
    opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
    dest_host = NetUtils.host_of_ip(dst_ip, self.nib.actual_net_for(opposite_switch))
    new_dest = NetUtils.ip_for_network(self.preferred_net(opposite_switch), dest_host)

    # What is the port on this switch that corresponds to the preferred path?
    preferred_net_gateway = NetUtils.ip_for_network(src_pref_net, 1)
    preferred_net_port = self.nib.port_for_ip(preferred_net_gateway)   

    output_actions = [
      SetIP4Src(new_src), 
      SetIP4Dst(new_dest),
      Output(Physical(preferred_net_port))
    ]
    dpid = self.nib.switch_to_dpid(switch)
    self.pkt_out(dpid, payload, output_actions)

  # TODO: This is almost like send_along_preferred_path except we don't touch the 
  # destination host address
  def send_along_direct_path(self, switch, src_ip, dst_ip, payload ):
    opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
    for ap in self.nib.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap[opposite_switch]):
        src_net = ap[switch] 

    src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
    # Translate this to the direct path IP
    new_src = NetUtils.ip_for_network(src_net, src_host)

    # What is the port on this switch that corresponds to the direct path?
    direct_net_gateway = NetUtils.ip_for_network(src_net, 1)
    direct_net_port = self.nib.port_for_ip(direct_net_gateway) 

    output_actions = [
      SetIP4Src(new_src), 
      SetEthDst(self.nib.mac_for_ip(direct_net_gateway)),
      Output(Physical(direct_net_port))
    ]
    dpid = self.nib.switch_to_dpid(switch)
    self.pkt_out(dpid, payload, output_actions)

  def translate_alternate_net(self, dst_ip):
    # First find out which side (ithaca or nyc) it's on
    side = "unknown"
    for ap in self.nib.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap["ithaca"]):
        side = "ithaca"
        imaginary_net = ap["ithaca"]
      elif NetUtils.ip_in_network(dst_ip, ap["nyc"]):
        side = "nyc"
        imaginary_net = ap["nyc"]
    if side == "unknown":
      logging.error("Ooops.  Got an ARP request for a net we don't know about.  Oh well.")
      return False
    else:
      host = NetUtils.host_of_ip(dst_ip, imaginary_net)
      return NetUtils.ip_for_network(self.nib.actual_net_for(side), host)

  def send_to_host(self, switch, src_ip, dst_ip, payload ):
    # Convert dst_ip to its real form.  First find out what the egress switch actually is:
    for ap in self.nib.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap[switch]): 
        imaginary_net = ap[switch]
    real_net = self.nib.actual_net_for(switch)
    dst_host = NetUtils.host_of_ip(dst_ip, imaginary_net)
    new_dest_ip = NetUtils.ip_for_network(real_net, dst_host)
    # If we don't know the port for this address (which might happen if the 
    # IP is on this network, but the host isn't up or doesn't exist) there's not
    # much we can do with this packet.  Send an ARP request and hope the 
    # original packet gets retransmitted (which is normally the case)
    if not self.nib.learned_ip(new_dest_ip):
      src_ip = NetUtils.ip_for_network(real_net, 250)
      self.send_arp_request(switch, src_ip, new_dest_ip)
    else:
      direct_net_port = self.nib.port_for_ip(new_dest_ip)
      # We also need to translate the alternately-numbered net to a real one.  Otherwise the 
      # host (which only knows real networks) may not know what to do with it.
      new_src_ip = self.translate_alternate_net(src_ip)
      output_actions = [
        SetIP4Src(new_src_ip),
        SetIP4Dst(new_dest_ip),
        Output(Physical(direct_net_port))
      ]
      dpid = self.nib.switch_to_dpid(switch)
      self.pkt_out(dpid, payload, output_actions)

  def packet_in_normal_operation(self, dpid, port, payload):
    switch = self.nib.dpid_to_switch(dpid)
    # TODO: deal with non-IP packets, although that's fairly unlikely
    p_eth = self.packet(payload, 'ethernet')
    if p_eth.ethertype == 0x0806:
      p_arp = self.packet(payload, 'arp')
      src_ip = p_arp.src_ip
      dst_ip = p_arp.dst_ip
    elif p_eth.ethertype == 0x0800:
      p_ip = self.packet(payload, 'ipv4')
      src_ip = p_ip.src
      dst_ip = p_ip.dst
    else:
      src_ip = '0.0.0.0'
      logging.info("Received packet of type "+str(p_eth.ethertype))

    # TODO: Handle DHCP requests someday, ... maybe
    if src_ip == '0.0.0.0':
      return

    if self.nib.learn(switch, self.nib.ENDHOST_PORT, port, p_eth.src, src_ip):
      # Update policies so we don't catch any more non-ARP packets on this port.  (Actually, there might
      # be a lag where we pick up some packets.  These are dropped, which is OK.)
      self.update(self.normal_operation_policy())

    logging.info("Received "+src_ip+" -> ("+str(switch)+", "+str(port)+") -> "+dst_ip)

    # Handle ARP requests.    
    if p_eth.ethertype == 0x0806 and p_arp.opcode == arp.ARP_REQUEST:
      # logging.info("Comparing to "+self.gateway_ip("ithaca"))
      preferred_path = self.nib.get_preferred_path()
      if dst_ip == self.gateway_ip("ithaca"):
        real_dest_ip = NetUtils.ip_for_network(self.nib.alternate_paths()[preferred_path]["ithaca"], 1)
      elif dst_ip == self.gateway_ip("nyc"):
        real_dest_ip = NetUtils.ip_for_network(self.nib.alternate_paths()[preferred_path]["nyc"], 1)
      # If the request is for a host in the net we're already in, just broadcast it.  The host
      # itself will answer.
      elif NetUtils.ip_in_network(src_ip, self.nib.actual_net_for(switch)) and \
           NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
         real_dest_ip = None
      else:    # It's an imaginary host on one of the alternate paths
        real_dest_ip = self.translate_alternate_net(dst_ip) 

      if real_dest_ip == None:
        # TODO: Don't send packet out ingress port,  Do it sloppy for now.
        logging.info("Flooding ARP Request")
        self.flood_indiscriminately(switch, payload)
      elif self.nib.learned_ip(real_dest_ip):
        real_dest_mac = self.nib.mac_for_ip(real_dest_ip)
        self.arp_reply(switch, port, p_eth.src, src_ip, real_dest_mac, dst_ip)
      else:
        # Send an ARP request to all ports, then just stay out of the way.  If the host is up
        # on an unlearned port, it'll send a response, and that'll trigger learning.  Then
        # when the NEXT ARP request for this address is received (it'll get retried a bunch of
        # times in practice), the reply can be generated from the ARP cache.  
        # It doesn't matter so much where the ARP reply goes, because this switch will pick it up.
        switch_net = self.nib.actual_net_for(switch)
        # TODO: 250 will work as a host on subnets with a /24, but not any higher.  
        src_ip = NetUtils.ip_for_network(switch_net, 250)
        self.send_arp_request(switch, src_ip, real_dest_ip)

    # We don't do anything special to ARP replies, just forward them onto their destination
    # unidirectionally
    elif p_eth.ethertype == 0x0806 and p_arp.opcode == arp.ARP_REPLY:
      # We ignore the text of ARP replies bound for us.  We just used them for learning the port.
      if p_eth.dst == self.BOGUS_MAC:
        pass
      # The destination port was definitely learned because that's where the request originated
      elif not self.nib.seen_mac(p_eth.dst):
        logging.error("Ooops!  ARP reply bound for a destination we don't know")
        return
      elif self.nib.switch_for_mac(p_eth.dst) != switch:
        logging.error("Ooops!  ARP reply is destined for a different network.  Can't happen.")
        return
      else:
        direct_net_port = self.nib.port_for_mac(p_eth.dst)
        output_actions = [Output(Physical(direct_net_port))]
        self.pkt_out(dpid, payload, output_actions)

    elif p_eth.ethertype == 0x0800:
      # If we haven't seen this source, dest pair yet, add it, and the rule with it.
      # Which list we put it in depends on whether we're at the ingress or egress switch
      if self.nib.at_ingress_switch(switch, port):
        # TODO: If this packet is bound for hosts outside the CoSciN network, in production just forward them,
        # For now, just drop them.  
        if not self.ip_in_coscin_network(dst_ip):
           logging.info("Internet-bound packet dropped in this test network")
           return
        # It's possible that this is an intra-network packet even though the rule should 've been installed
        # to handle such packets directly.  send_along_direct_path will handle it below.
        elif NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
          pass 
        elif not self.nib.seen_src_dest_pair_at_ingress(src_ip, dst_ip):
          self.nib.add_ingress_src_dest_pair(src_ip, dst_ip)
          self.update(self.normal_operation_policy())
      elif self.nib.at_egress_switch(switch, port):
        if not self.nib.seen_src_dest_pair_at_egress(src_ip, dst_ip):
          self.nib.add_egress_src_dest_pair(src_ip, dst_ip)
          self.update(self.normal_operation_policy())

      # If we have seen it, the rule should've taken care of the next packets, but it might
      # not be in effect yet so we handle it manually
      opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
        self.send_along_preferred_path( switch, src_ip, dst_ip, payload )
      elif self.nib.at_ingress_switch(switch, port):
        self.send_along_direct_path( switch, src_ip, dst_ip, payload )
      elif self.nib.at_egress_switch(switch, port):
        self.send_to_host( switch, src_ip, dst_ip, payload )

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
