# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A frenetic app that acts mostly like a switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics

import sys, array, logging, time, binascii, datetime, json, copy
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
from ryu.lib.packet import packet, ethernet, vlan, arp, ipv4
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

  # switches, unlearned_ports and router_ports are of the form { "ithaca": [1,2,3], "nyc": [2,3]}
  switches = {}
  unlearned_ports = {}
  router_ports = { "ithaca": set(), "nyc": set() }

  # index of alternate_path being used now
  current_path = 1

  # hosts = { mac1: (sw1, port1), mac2: (sw2, port2), ... }
  hosts = {}

  # endhosts = { "ithaca": [(host_portion_of_ip, port, mac, ip), ...], "nyc": ... }
  # This is more for enumerating end user hosts on each end network
  endhosts = { "ithaca": [], "nyc": []}

  # We maintain our own little ARP table for the router IP's.  Entries are of the form
  # ip: (switch, port, mac).  It's like hosts, but for L3.  We also have entries for
  # every virtual host IP on the alternate paths to make it fast.
  arp_cache = {}

  # We add paths for each source, dest pair as we see them.  This is a set 
  # [ (192.168.56.100, 192.168.57.100) ].  We need to separate them out into two sets
  # because there are different rules for each 
  ingress_src_dest_pairs = set()
  egress_src_dest_pairs = set()

  def __init__(self, config_file='laptop_demo_network.json'):
    frenetic.App.__init__(self) 

    f = open(config_file, "r")
    self.coscin_config = json.load(f)
    f.close()

  ##################################
  # Common operations

  # Stolen from RYU.  This is part of the RyuApp class, so we can't use it directly.
  def ipv4_to_str(self, integre):
    ip_list = [str((integre >> (24 - (n * 8)) & 255)) for n in range(4)]
    return '.'.join(ip_list)

  def ipv4_to_int(self, string):
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
      b = int(b)
      i = (i << 8) | b
    return i

  def dpid_to_switch(self, dpid):
    for sw in ["ithaca", "nyc"]:
      if dpid == self.coscin_config[sw]["dpid"]:
        return sw
    return "UKNOWN"

  def switch_to_dpid(self, sw):
    if sw in self.coscin_config:
      return self.coscin_config[sw]["dpid"]
    else:
      return 0

  def net_mask(self, net_mask_combo):
    # The net is assumed of the form xx.xx.xx.xx/mask using the CIDR notation, as per IP custom
    (net, mask) = net_mask_combo.split("/")
    return (net, int(mask))

  # Given a network and a host, construct an IP, real or imagined.  A lot of the path mapping
  # is done this way, so host x.100 on the real network gets mapped to the bogus addresses 
  # x1.100, x2.100 and x3.100 for each of the paths
  def ip_for_network(self, net, host):
    (net, mask) = self.net_mask(net)
    # Most of the time, the net is in the proper form with zeroes in the right places, but we 
    # run it through a subnet filter just in case it isn't.
    net_int = self.ipv4_to_int(net)
    # A mask of all ones is just 2^(n+1) -1
    all_ones = pow(2, mask+1) -1  
    #logging.info("Net Filter: "+format(all_ones, '08x'))
    net_int = net_int & (all_ones << (32-mask))
    #logging.info("Net: "+format(net_int, '08x'))
    ip_int = net_int | int(host)
    #logging.info("Net with host: "+format(ip_int, '08x'))
    return self.ipv4_to_str(ip_int)

  # Given a network and an IP, extract just the host number.
  def host_of_ip(self, src_ip, net):
    (net, mask) = self.net_mask(net)
    src_ip_int = self.ipv4_to_int(src_ip)
    net_int = self.ipv4_to_int(net)
    # A mask of all ones is just 2^(n+1) -1.  The host mask is just the inverse of the net mask
    all_ones = pow(2, mask+1) -1
    host_int = ~ (all_ones << (32-mask))
    # TODO: Maybe check the net portion of src_ip against net_int to make sure it's from the
    # same net.  
    return host_int & int(src_ip_int)

  def ip_in_network(self, src_ip, net):
    (net, mask) = self.net_mask(net)
    net_int = self.ipv4_to_int(net)
    net_mask = (pow(2, mask+1) -1) << (32-mask)
    net_int = net_int & net_mask   # Most likely, there is no change here
    src_net_int = self.ipv4_to_int(src_ip) & net_mask
    return net_int == src_net_int

  # Send payload to all ports  
  def flood_indiscriminately(self, switch, payload):
    output_actions = [ Output(Physical(p)) for p in self.switches[switch] ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.switch_to_dpid(switch), payload, output_actions)

  def arp_payload(self, e, pkt):
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
    payload = self.arp_payload(e, pkt)
    logging.info("Sending Arp Request to "+target_ip)
    self.flood_indiscriminately(switch, payload)

  def send_arp_request_router_interface(self, switch, target_ip_net):
    # Note this may not or may not be a real host, but the reply will always come back to the switch anyway.
    src_ip = self.ip_for_network(target_ip_net, 250)
    dst_ip = self.ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
    self.send_arp_request(switch, src_ip, dst_ip)

  def arp_reply(self, switch, port, src_mac, src_ip, target_mac, target_ip):
    e = ethernet.ethernet(dst=src_mac, src=target_mac, ethertype=ether.ETH_TYPE_ARP)
    # Note for the reply we flip the src and target, as per ARP rules
    pkt = arp.arp_ip(arp.ARP_REPLY, target_mac, target_ip, src_mac, src_ip)
    payload = self.arp_payload(e, pkt)
    self.pkt_out(self.switch_to_dpid(switch), payload, [Output(Physical(port))])

  def learn(self, switch, port, mac, src_ip):
    logging.info("Learning: "+mac+"/"+src_ip+" attached to ( "+switch+", "+str(port)+" )")
    self.hosts[mac] = (switch, port)
    # TODO: Guard against learning a port twice
    host_portion = self.host_of_ip(src_ip, self.coscin_config[switch]["network"])
    self.endhosts[switch].append( (host_portion, port, mac, src_ip) )
    self.arp_cache[src_ip] = (switch, port, mac)
    # We also add entries for this host on all its imaginary paths
    for ap in self.coscin_config["alternate_paths"]:
      virtual_ip = self.ip_for_network(ap[switch], host_portion)
      self.arp_cache[virtual_ip] = (switch, port, mac)
    self.unlearned_ports[switch].remove(port)

  def gateway_ip(self, switch):
    return self.ip_for_network(self.coscin_config[switch]["network"], 1)

  def send_to_controller(self):
    return Mod(Location(Pipe("coscin_switch_app")))

  def is_arp(self):
    return Test(EthType(0x806))

  def is_ip(self):
    return Test(EthType(0x800))

  def at_ithaca(self):
    return Test(Switch(self.switch_to_dpid("ithaca")))

  def at_nyc(self):
    return Test(Switch(self.switch_to_dpid("nyc")))

  def at_switch(self, switch):
    return Test(Switch(self.switch_to_dpid(switch)))

  def at_switch_port(self, switch, port):
    #logging.info("at_switch_port("+switch+","+str(port)+")")
    return Test(Switch(self.switch_to_dpid(switch))) & Test(Location(Physical(port)))

  def is_dest(self, ip_net, ip_host):
    return Test(IP4Dst(self.ip_for_network(ip_net, ip_host)))

  def dest_real_net(self, switch, ip_host):
    return self.is_dest(self.coscin_config[switch]["network"], ip_host)

  def to_dest_net(self, net_and_mask):
    (net, mask) = self.net_mask(net_and_mask)
    return Test(IP4Dst(net,mask))

  def is_ip_from_to(self, src_ip, dest_ip):
    return self.is_ip() & Test(IP4Src(src_ip)) & Test(IP4Dst(dest_ip))

  def destination_not_known_host_on_net(self, host_ip, dest_net):
    # Given an IP, find all src_dest pairs we've seen for this src, filter the dests down to 
    # those on the dest_net, and return a clause that doesn't match any of them
    preds = []
    for src_dest_pair in self.ingress_src_dest_pairs:
      (src_ip, dst_ip) = src_dest_pair 
      if src_ip == host_ip and self.ip_in_network(dst_ip, dest_net):
        preds.append(Test(IP4Dst(dst_ip)))
    if not preds:
      return true
    else:
      return Not(Or(preds))

  def src_dest_pair_not_learned(self, dest_net):
    # Given a destination net, find all learned src, dest pairs that match it and return
    # a clause that doesn't match any of them.
    preds = []
    for src_dest_pair in self.egress_src_dest_pairs:
      (src_ip, dst_ip) = src_dest_pair 
      if self.ip_in_network(dst_ip, dest_net):
        preds.append(Test(IP4Src(src_ip)) & Test(IP4Dst(dst_ip)))
    if not preds:
      return true
    else:
      return Not(Or(preds))

  def packet_at_egress_switch(self, switch, port, src_ip, dst_ip):
    # We're at a host port on the egress switch if we're on a router port
    return port in self.router_ports[switch] 

  def packet_at_ingress_switch(self, switch, port, src_ip, dst_ip):
    return not self.packet_at_egress_switch(switch, port, src_ip, dst_ip)

  ########################
  # Frenetic Dispatchers

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
      self.unlearned_ports = copy.deepcopy(self.switches)

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

  def port_up(self, dpid, port):
    switch = self.dpid_to_switch(dpid)
    # If port comes up, remove any learned macs on it (probably won't be any) 
    self.unlearn_mac_on_port(switch, port)

  def port_down(self, dpid, port):
    switch = self.dpid_to_switch(dpid)
    # If port goes down, remove any learned macs on it
    self.unlearn_mac_on_port(switch, port)

  def switch_up(self, dpid,ports):
    switch = self.dpid_to_switch(dpid)
    # If we've seen this switch before, just return.  Otherwise add the ports to unlearned. 
    if switch in self.switches:
      return
    self.switches[switch] = ports
    self.unlearned_ports[switch] = ports
    logging.info("Updated Switches: "+str(self.switches))

  # Don't remove switch info when it supposedly goes down - this happens all the time on Dell switches and it comes 
  # right back up.  
  def switch_down(self, dpid):
    pass

  ########################
  # Router Learning Mode
  # We assume all router interfaces are up for all alternate paths and that they're fixed for the duration
  # of the controller.  In this mode, we send ARP requests to all paths so we can learn (1) their Mac address 
  # (2) their switch port.  

  def packet_in_router_learning(self, dpid, port, payload):
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'arp')
    p_eth = get(pkt, 'ethernet')
    switch = self.dpid_to_switch(dpid)
    logging.info("Received "+p_eth.src+"/"+p.src_ip+" -> ("+switch+", "+str(port)+") -> "+p.dst_ip)
    self.unlearned_ports[switch].remove(port)
    self.router_ports[switch].add(port)
    # Supposedly, the src mac in the ARP reply and the ethernet frame itself should be the
    # the same, but that's not always the case.  The Ethernet frame is definitive. 
    self.arp_cache[p.src_ip] = (switch, port, p_eth.src)
    if len(self.arp_cache) >= len(self.coscin_config["alternate_paths"]) * len(self.switches):
      self.normal_mode()

  def router_learning_policy(self):
    # In the intial config, grab all ARP replies for ourselves
    return Filter( self.is_arp() ) >> self.send_to_controller()

  def learn_routers(self):
    logging.info("Switching to Router Learning mode")
    self.state = self.STATE_ROUTER_LEARNING
    # Send out ARP packets for all router interfaces to learn their mac addresses.  The
    # packet_in_router will handle the replies as they arrive
    for path in self.coscin_config["alternate_paths"]:
      if "ithaca" in self.coscin_config:
        ithaca_router_net = path["ithaca"]
        self.send_arp_request_router_interface("ithaca", ithaca_router_net)
      if "nyc" in self.coscin_config:
        nyc_router_net = path["nyc"] 
        self.send_arp_request_router_interface("nyc", nyc_router_net)

  ########################
  # Normal Mode
  # This basically handles all traffic afterwards.  It learns host ports coming up.  

  def normal_mode(self):
    logging.info("Switching to Normal mode.  Host ports to learn: "+str(self.unlearned_ports))
    self.update(self.normal_operation_policy())
    self.state = self.STATE_NORMAL_OPERATION

  def capture_arp_requests_policy(self):
    policies = []
    for switch in self.switches:
      # In normal mode, we capture ARP requests for IP's that don't really exist.  You can
      # think of them as symbolic links to the real IP.  We capture .1 address of
      # each of the endpoint networks
      policies.append(Filter(self.at_switch(switch) & self.is_arp() & self.dest_real_net(switch, 1)) >> self.send_to_controller())

      # And we capture ARP requests for the alternate paths.  These will always be for 
      # hosts that have no real estate on the imaginary link, as in 192.168.156.100 along 
      # the 192.168.156.* imaginary network.  This will be translated to the real net 192.168.56.100
      for ap in self.coscin_config["alternate_paths"]:
        (net, mask) = self.net_mask(ap[switch])
        policies.append(Filter(self.at_switch(switch) & self.is_arp() & Test(IP4Dst(net,mask))) >> self.send_to_controller())

    return Union(policies)

  # For each end host, pick up all packets going to the destination network.  As we 
  # learn source host -> destination host pairs, we will add rules for that pair, making
  # more specific rules that will override this one.
  def capture_new_source_dest_pairs_policy(self):
    policies = []
    for switch in self.switches:
      for endhost in self.endhosts[switch]:
        (host, host_port, host_mac, host_ip) = endhost
        opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
        dest_cdr = self.coscin_config[opposite_switch]["network"]
        (dest_net, dest_mask) = self.net_mask(dest_cdr)
        # logging.info("(dest_net,dest_mask) = ("+dest_net+","+str(dest_mask)+")")
        # Note we really don't have to test for source IP, but it's extra security
        policies.append(Filter( 
          self.at_switch_port(switch,host_port) & 
          self.is_ip() & 
          Test(IP4Src(host_ip)) & 
          Test(IP4Dst(dest_net,dest_mask)) & 
          self.destination_not_known_host_on_net(host_ip, dest_cdr)
        ) >> self.send_to_controller())
        for ap in self.coscin_config["alternate_paths"]:
          dest_cdr = ap[opposite_switch]
          (dest_net, dest_mask) = self.net_mask(dest_cdr)
          policies.append(Filter( 
            self.at_switch_port(switch,host_port) & 
            self.is_ip() & 
            Test(IP4Src(host_ip)) & 
            Test(IP4Dst(dest_net,dest_mask)) &
            self.destination_not_known_host_on_net(host_ip, dest_cdr)
          ) >> self.send_to_controller())

      # Now handle incoming packets for all our home networks.  We need to learn
      # those (src, dest) pairs as well
      # TODO: Do we need to process packets in intra-net paths too?  This will be
      # those with a destination on the real network
      for ap in self.coscin_config["alternate_paths"]:
        dest_cdr = ap[switch]
        (dest_net, dest_mask) = self.net_mask(dest_cdr)
        policies.append(Filter( 
          self.is_ip() & 
          Test(IP4Dst(dest_net,dest_mask)) &
          self.src_dest_pair_not_learned(dest_cdr)
        ) >> self.send_to_controller())

    return Union(policies)

  def unlearned_ports_policy(self):
    is_at_unlearned_port = []
    for switch, ports in self.unlearned_ports.iteritems():
      for port in ports:
        is_at_unlearned_port.append(self.at_switch_port(switch,port))
    return Filter(Or(is_at_unlearned_port)) >> self.send_to_controller()

  # TODO: This is a lot like send_along_preferred_path and send_along_direct_path, 
  # but in rule form
  def ingress_src_dest_pairs_policy(self):
    policies = []
    for src_dest_pair in self.ingress_src_dest_pairs:
      (src_ip, dst_ip) = src_dest_pair 
      (switch, port, _) = self.arp_cache[src_ip]
      src_host = self.host_of_ip(src_ip, self.coscin_config[switch]["network"])
      # If this is going to the preferred network, write a rule choosing the 
      # correct route here.
      opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
      if self.ip_in_network(dst_ip, self.coscin_config[opposite_switch]["network"]):
        # Get host from src_ip
        src_pref_net = self.preferred_net(switch)
        new_src = self.ip_for_network(src_pref_net, src_host)
        dest_host = self.host_of_ip(dst_ip, self.coscin_config[opposite_switch]["network"])
        new_dest = self.ip_for_network(self.preferred_net(opposite_switch), dest_host)

        preferred_net_gateway = self.ip_for_network(src_pref_net, 1)
        preferred_net_port = self.arp_cache[preferred_net_gateway][1] 

        output_actions = Seq([
          Mod(IP4Src(new_src)), 
          Mod(IP4Dst(new_dest)),
          Mod(Location(Physical(preferred_net_port)))
        ])
        policies.append(
          Filter( self.at_switch_port(switch, port) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )

      else: 
        # It's a direct path.  Find the path first.
        for ap in self.coscin_config["alternate_paths"]:
          if self.ip_in_network(dst_ip, ap[opposite_switch]):
            alternate_path = ap
        new_src = self.ip_for_network(alternate_path[switch], src_host)
        direct_net_gateway = self.ip_for_network(alternate_path[switch], 1)
        direct_net_port = self.arp_cache[direct_net_gateway][1] 
        output_actions = Seq([
          Mod(IP4Src(new_src)),
          Mod(EthDst(self.arp_cache[direct_net_gateway][2])),
          Mod(Location(Physical(direct_net_port)))
        ])
        policies.append(
          Filter( self.at_switch_port(switch, port) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )

    return Union(policies)

  # Egress src dest pairs are a little easier to deal with
  # TODO: This acts a lot like send_to_host
  def egress_src_dest_pairs_policy(self):
    policies = []
    for src_dest_pair in self.egress_src_dest_pairs:
      (src_ip, dst_ip) = src_dest_pair 
      # Convert dst_ip to its real form.  First find out what the egress switch actually is:
      for ap in self.coscin_config["alternate_paths"]:
        if self.ip_in_network(dst_ip, ap["ithaca"]): 
          switch = "ithaca" 
          imaginary_net = ap["ithaca"]
        elif self.ip_in_network(dst_ip, ap["nyc"]):
          switch = "nyc"
          imaginary_net = ap["nyc"]
      real_net = self.coscin_config[switch]["network"]
      dst_host = self.host_of_ip(dst_ip, imaginary_net)
      new_dest_ip = self.ip_for_network(real_net, dst_host)
      # If it's not in the ARP cache, it already has an ARP request on the way so ignore it for now.
      if new_dest_ip in self.arp_cache:
        direct_net_port = self.arp_cache[new_dest_ip][1]
        new_src_ip = self.translate_alternate_net(src_ip)
        output_actions = Seq([
          Mod(IP4Src(new_src_ip)),
          Mod(IP4Dst(new_dest_ip)),
          Mod(Location(Physical(direct_net_port)))
        ])
        policies.append(
          Filter( Test(Switch(self.switch_to_dpid(switch))) & self.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )
    return Union(policies)


  def normal_operation_policy(self):
    return Union([
      self.capture_arp_requests_policy(),
      self.capture_new_source_dest_pairs_policy(),
      self.unlearned_ports_policy(),
      self.ingress_src_dest_pairs_policy(),
      self.egress_src_dest_pairs_policy()
    ])

  def preferred_net(self, switch):
    return self.coscin_config["alternate_paths"][self.current_path][switch]

  def send_along_preferred_path(self, switch, src_ip, dst_ip, payload ):
    # Get host from src_ip
    src_pref_net = self.preferred_net(switch)
    src_host = self.host_of_ip(src_ip, self.coscin_config[switch]["network"])
    # Translate this to the preferred path IP
    new_src = self.ip_for_network(src_pref_net, src_host)
    # And do the same for the destination
    opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
    dest_host = self.host_of_ip(dst_ip, self.coscin_config[opposite_switch]["network"])
    new_dest = self.ip_for_network(self.preferred_net(opposite_switch), dest_host)

    # What is the port on this switch that corresponds to the preferred path?
    preferred_net_gateway = self.ip_for_network(src_pref_net, 1)
    #logging.info("Preferred net gateway is "+preferred_net_gateway)
    preferred_net_port = self.arp_cache[preferred_net_gateway][1] 
    #logging.info("Thrrough port "+str(preferred_net_port))

    output_actions = [
      Mod(IP4Src(new_src)), 
      Mod(IP4Dst(new_dest)),
      Output(Physical(preferred_net_port))
    ]
    dpid = self.switch_to_dpid(switch)
    self.pkt_out(dpid, payload, output_actions)

  # TODO: This is almost like send_along_preferred_path except we don't touch the 
  # destination host address
  def send_along_direct_path(self, switch, src_ip, dst_ip, payload ):
    opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
    for ap in self.coscin_config["alternate_paths"]:
      if self.ip_in_network(dst_ip, ap[opposite_switch]):
        src_net = ap[switch] 

    src_host = self.host_of_ip(src_ip, self.coscin_config[switch]["network"])
    # Translate this to the direct path IP
    new_src = self.ip_for_network(src_net, src_host)

    # What is the port on this switch that corresponds to the direct path?
    direct_net_gateway = self.ip_for_network(src_net, 1)
    direct_net_port = self.arp_cache[direct_net_gateway][1] 

    output_actions = [
      Mod(IP4Src(new_src)), 
      Mod(EthDst(self.arp_cache[direct_net_gateway][2])),
      Output(Physical(direct_net_port))
    ]
    dpid = self.switch_to_dpid(switch)
    self.pkt_out(dpid, payload, output_actions)

  def translate_alternate_net(self, dst_ip):
    # First find out which side (ithaca or nyc) it's on
    side = "unknown"
    for ap in self.coscin_config["alternate_paths"]:
      if self.ip_in_network(dst_ip, ap["ithaca"]):
        side = "ithaca"
        imaginary_net = ap["ithaca"]
      elif self.ip_in_network(dst_ip, ap["nyc"]):
        side = "nyc"
        imaginary_net = ap["nyc"]
    if side == "unknown":
      logging.error("Ooops.  Got an ARP request for a net we don't know about.  Oh well.")
      return False
    else:
      host = self.host_of_ip(dst_ip, imaginary_net)
      return self.ip_for_network(self.coscin_config[side]["network"], host)

  def send_to_host(self, switch, src_ip, dst_ip, payload ):
    # Convert dst_ip to its real form.  First find out what the egress switch actually is:
    for ap in self.coscin_config["alternate_paths"]:
      if self.ip_in_network(dst_ip, ap[switch]): 
        imaginary_net = ap[switch]
    real_net = self.coscin_config[switch]["network"]
    dst_host = self.host_of_ip(dst_ip, imaginary_net)
    new_dest_ip = self.ip_for_network(real_net, dst_host)
    # If we don't know the port for this address (which might happen if the 
    # IP is on this network, but the host isn't up or doesn't exist) there's not
    # much we can do with this packet.  Send an ARP request and hope the 
    # original packet gets retransmitted (which is normally the case)
    if new_dest_ip not in self.arp_cache:
      src_ip = self.ip_for_network(real_net, 250)
      self.send_arp_request(switch, src_ip, new_dest_ip)
    else:
      direct_net_port = self.arp_cache[new_dest_ip][1]
      # We also need to translate the alternately-numbered net to a real one.  Otherwise the 
      # host (which only knows real networks) may not know what to do with it.
      new_src_ip = self.translate_alternate_net(src_ip)
      output_actions = [
        Mod(IP4Src(new_src_ip)),
        Mod(IP4Dst(new_dest_ip)),
        Output(Physical(direct_net_port))
      ]
      dpid = self.switch_to_dpid(switch)
      self.pkt_out(dpid, payload, output_actions)

  def packet_in_normal_operation(self, dpid, port, payload):
    # The packet may be from an unlearned port.  If so, learn it.
    pkt = packet.Packet(array.array('b', payload.data))
    switch = self.dpid_to_switch(dpid)
    # TODO: deal with non-IP packets, although that's fairly unlikely
    p_eth = get(pkt, 'ethernet')
    if p_eth.ethertype == 0x0806:
      p_arp = get(pkt, 'arp')
      src_ip = p_arp.src_ip
      dst_ip = p_arp.dst_ip
    elif p_eth.ethertype == 0x0800:
      p_ip = get(pkt, 'ipv4')
      src_ip = p_ip.src
      dst_ip = p_ip.dst

    if port in self.unlearned_ports[switch]:
      self.learn(switch, port, p_eth.src, src_ip)
      # Update policies so we don't catch any more non-ARP packets.  (Actually, there might
      # be a lag where we pick up some packets.  These are dropped, which is OK.)
      self.update(self.normal_operation_policy())

    logging.info("Received "+src_ip+" -> ("+str(switch)+", "+str(port)+") -> "+dst_ip)

    # Handle ARP requests.  ARP Replies also might come here to trigger port learning, but we
    # don't do anything special with them.  
    if p_eth.ethertype == 0x0806 and p_arp.opcode == arp.ARP_REQUEST:
      # logging.info("Comparing to "+self.gateway_ip("ithaca"))
      if dst_ip == self.gateway_ip("ithaca"):
        real_dest_ip = self.ip_for_network(self.coscin_config["alternate_paths"][self.current_path]["ithaca"], 1)
      elif dst_ip == self.gateway_ip("nyc"):
        real_dest_ip = self.ip_for_network(self.coscin_config["alternate_paths"][self.current_path]["nyc"], 1)
      else:    # It's an imaginary host on one of the alternate paths
        real_dest_ip = self.translate_alternate_net(dst_ip) 

      if real_dest_ip in self.arp_cache:
        real_dest_mac = self.arp_cache[real_dest_ip][2]
        self.arp_reply(switch, port, p_eth.src, src_ip, real_dest_mac, dst_ip)
      else:
        # Send an ARP request to all ports, then just stay out of the way.  If the host is up
        # on an unlearned port, it'll send a response, and that'll trigger learning.  Then
        # when the NEXT ARP request for this address is received (it'll get retried a bunch of
        # times in practice), the reply can be generated from the ARP cache.  
        # It doesn't matter so much where the ARP reply goes, because this switch will pick it up.
        switch_net = self.coscin_config[switch]["network"]
        src_ip = self.ip_for_network(switch_net, 250)
        self.send_arp_request(switch, src_ip, real_dest_ip)

    elif p_eth.ethertype == 0x0800:
      # If we haven't seen this source, dest pair yet, add it, and the rule with it.
      # Which list we put it in depends on whether we're at the ingress or egress switch
      if self.packet_at_ingress_switch(switch, port, src_ip, dst_ip):
        if (src_ip, dst_ip) not in self.ingress_src_dest_pairs:
          self.ingress_src_dest_pairs.add( (src_ip, dst_ip) )
          self.update(self.normal_operation_policy())
      else:
        if (src_ip, dst_ip) not in self.egress_src_dest_pairs:
          self.egress_src_dest_pairs.add( (src_ip, dst_ip) )
          self.update(self.normal_operation_policy())
      # If we have seen it, the rule should've taken care of the next packets, but it might
      # not be in effect yet so we handle it manually
      opposite_switch = "nyc" if (switch=="ithaca") else "ithaca"
      if self.ip_in_network(dst_ip, self.coscin_config[opposite_switch]["network"]):
        self.send_along_preferred_path( switch, src_ip, dst_ip, payload )
      elif self.packet_at_ingress_switch(switch, port, src_ip, dst_ip):
        self.send_along_direct_path( switch, src_ip, dst_ip, payload )
      elif self.packet_at_egress_switch(switch, port, src_ip, dst_ip):
        self.send_to_host( switch, src_ip, dst_ip, payload )

if __name__ == '__main__':
  logging.basicConfig(stream = sys.stderr, format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

  logging.info("*** CoSciN Switch Application Begin")
  app = CoscinSwitchApp()
  app.start_event_loop()