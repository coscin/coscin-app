# NetworkInformationBase (nib) for Coscin App
# Craig Riecke, CoSciN Programmer/Nalayst January 2016
#
# Some parts of the NIB are familiar, like the ARP cache.  Some are highly specialized
# for this app.  In particular, we assume and Ithaca "side" and NYC "side", with 
# corresponding switch, controller, and networks on each side.

import json, copy, logging
from net_utils import NetUtils

class NetworkInformationBase():

  # switches and unlearned_ports are of the form { "ithaca": [1,2,3], "nyc": [2,3]}
  switches = {}
  unlearned_ports = {}

  # Router ports are tallied on the approriate side
  router_ports = { "ithaca": set(), "nyc": set() }

  # index of alternate_path being used now
  preferred_path = 0

  # hosts = { mac1: (sw1, port1), mac2: (sw2, port2), ... }
  hosts = {}

  # endhosts = { "ithaca": [(host_portion_of_ip, port, mac, ip), ...], "nyc": ... }
  # This is more for enumerating end user hosts on each end network
  endhosts = { "ithaca": [], "nyc": []}

  # We maintain our own little ARP table for the router IP's and endhosts.  Entries are of the form
  # ip: (switch, port, mac).  It's like hosts, but for L3.  We also have entries for
  # every virtual host IP on the alternate paths to make it fast.
  arp_cache = {}

  # We add paths for each source, dest pair as we see them.  This is a set 
  # [ (192.168.56.100, 192.168.57.100) ].  We need to separate them out into two sets
  # because there are different rules for each 
  ingress_src_dest_pairs = set()
  egress_src_dest_pairs = set()

  # Ports are segregated into ROUTER ports and ENDHOST ports
  ROUTER_PORT = 1
  ENDHOST_PORT = 2

  # This will be seeded with network data in .json file
  coscin_config = {} 

  # Dirty flag set if policies need to be regenerated and sent to switches
  dirty = False

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

  def not_learned_yet(self, switch, port):
    return port in self.unlearned_ports[switch]

  def learned(self, switch, port):
    return not self.not_learned_yet(switch, port)

  # Update NIB tables and return True if table changes occurred.  Return False otherwise.
  def learn(self, switch, port_type, port, mac, src_ip):
    if self.learned(switch, port):
      return False

    logging.info("Learning: "+mac+"/"+src_ip+" attached to ( "+switch+", "+str(port)+" )")
    self.hosts[mac] = (switch, port)
    self.arp_cache[src_ip] = (switch, port, mac)
    self.unlearned_ports[switch].remove(port)
    if port_type == self.ENDHOST_PORT:
      host_portion = NetUtils.host_of_ip(src_ip, self.coscin_config[switch]["network"])
      self.endhosts[switch].append( (host_portion, port, mac, src_ip) )
      # We also add entries for this host on all its imaginary paths
      for ap in self.coscin_config["alternate_paths"]:
        virtual_ip = NetUtils.ip_for_network(ap[switch], host_portion)
        self.arp_cache[virtual_ip] = (switch, port, mac)
    elif port_type == self.ROUTER_PORT:
      self.router_ports[switch].add(port)
    else:
      logging.error("Unknown port type: "+str(port_type))
      return False
    return True

  def unlearn_mac_on_port(self, switch, port):
    # TODO: If a router port went down, we need to retrigger MAC learning somehow.  Ignore for now.
    if port in self.router_ports[switch]:
      return False
    # If the port hasn't been learned, there's no saved state, so do nothing.
    if port in self.unlearned_ports[switch]:
      return False
    for mac in self.hosts:
      (sw, p) = self.hosts[mac]
      if sw==switch and p==port:
        del self.hosts[mac]
    for i, endhost in enumerate(self.endhosts[switch]):
      (_, p, _, _) = endhost
      if p==port:
        del self.endhosts[switch][i]
    for src_ip in self.arp_cache:
      (sw, p, _) = self.arp_cache[src_ip]
      if sw==switch and p==port:
        del self.arp_cache[src_ip]
    self.unlearned_ports[switch].add(port)
    return True   # Triggers rules to be resent to switch

  def save_switches_and_ports(self, switches):
    self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
    self.unlearned_ports = copy.deepcopy(self.switches)

  def add_switches_and_ports(self, switch, ports):
    self.switches[switch] = ports
    self.unlearned_ports[switch] = ports

  def switch_description(self):
    return str(self.switches)

  def unlearned_ports_description(self):
    return str(self.unlearned_ports)

  def contains_switch(self, switch):
    return switch in self.switches

  def ports_on_switch(self, switch):
    return self.switches[switch]

  def switch_count(self):
    return len(self.switches)

  def switch_present(self, switch):
    return switch in self.switches

  def switches_present(self):
    return self.switches.keys()

  def at_egress_switch(self, switch, port):
    # We're at a host port on the egress switch if we're on a router port
    return port in self.router_ports[switch] 

  def at_ingress_switch(self, switch, port):
    return not self.at_egress_switch(switch, port)

  def get_preferred_path(self):
    return self.preferred_path

  def set_preferred_path(self, pp):
    self.preferred_path = pp

  def get_endhosts(self, switch):
    return self.endhosts[switch]

  def port_for_ip(self, src_ip):
    return self.arp_cache[src_ip][1]

  def seen_mac(self, src_mac):
    return src_mac in self.hosts

  def switch_for_mac(self, src_mac):
    return self.hosts[src_mac][0]

  def port_for_mac(self, src_mac):
    return self.hosts[src_mac][1]

  def size_arp_cache(self):
    return len(self.arp_cache)

  def switch_for_ip(self, src_ip):
    return self.arp_cache[src_ip][0]

  def port_for_ip(self, src_ip):
    return self.arp_cache[src_ip][1]

  def mac_for_ip(self, src_ip):
    return self.arp_cache[src_ip][2]

  def learned_ip(self, src_ip):
    return src_ip in self.arp_cache

  def get_ingress_src_dest_pairs(self):
    return self.ingress_src_dest_pairs

  def get_egress_src_dest_pairs(self):
    return self.egress_src_dest_pairs

  def seen_src_dest_pair_at_ingress(self, src_ip, dst_ip):
    return (src_ip, dst_ip) in self.ingress_src_dest_pairs

  def add_ingress_src_dest_pair(self, src_ip, dst_ip):
    self.ingress_src_dest_pairs.add( (src_ip, dst_ip) )

  def seen_src_dest_pair_at_egress(self, src_ip, dst_ip):
    return (src_ip, dst_ip) in self.egress_src_dest_pairs

  def add_egress_src_dest_pair(self, src_ip, dst_ip):
    self.egress_src_dest_pairs.add( (src_ip, dst_ip) )

  def load_config(self, config_file):
    f = open(config_file, "r")
    self.coscin_config = json.load(f)
    f.close()

  def actual_net_for(self, switch):
    return self.coscin_config[switch]["network"]

  def alternate_paths(self):
    return self.coscin_config["alternate_paths"]

  def get_unlearned_ports(self):
    return self.unlearned_ports

  def preferred_net(self, switch):
    return self.alternate_paths()[self.get_preferred_path()][switch]

  def translate_alternate_net(self, dst_ip):
    # First find out which side (ithaca or nyc) it's on
    found_side = None
    for ap in self.alternate_paths():
      for side in ["ithaca", "nyc"]:
        if NetUtils.ip_in_network(dst_ip, ap[side]):
          found_side = side
          imaginary_net = ap[side]

    if side == None:
      logging.error("Ooops.  Got an ARP request for a net we don't know about.  Oh well.")
      return False
    else:
      host = NetUtils.host_of_ip(dst_ip, imaginary_net)
      return NetUtils.ip_for_network(self.actual_net_for(found_side), host)

  def is_dirty(self):
    return self.dirty

  def set_dirty(self):
    self.dirty = True

  def clear_dirty(self):
    self.dirty = False

  def opposite_switch(self, switch):
    return "nyc" if (switch=="ithaca") else "ithaca"

  def ip_in_coscin_network(self, dst_ip):
    if NetUtils.ip_in_network(dst_ip, self.actual_net_for("ithaca")):
      return True
    if NetUtils.ip_in_network(dst_ip, self.actual_net_for("nyc")):
      return True    
    for ap in self.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap["ithaca"]) or NetUtils.ip_in_network(dst_ip, ap["nyc"]):
        return True
    return False      

