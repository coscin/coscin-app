# CrossCampusHandler
# Handles Coscin Traffic from NYC to Ithaca or Vice-Versa.  If the destinations uses an 
# "imaginary" destination address, choose the path explicitly.  If it uses a "real"
# destination address, choose the current preferred path.

import sys, logging
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
# Temporary until we merge streamlined sytnax into master
from streamlined_syntax import *
from policies import Policies
from net_utils import NetUtils
from ryu.lib.packet import ethernet, arp
from ryu.ofproto import ether

class CrossCampusHandler():

  def __init__(self, main_app, nib):
    self.main_app = main_app
    self.nib = nib

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

  # For each end host, pick up all packets going to the destination network.  As we 
  # learn source host -> destination host pairs, we will add rules for that pair, making
  # more specific rules that will override this one.
  def capture_new_source_dest_pairs_policy(self):
    policies = []
    for switch in self.nib.switches_present():
      dpid = self.nib.switch_to_dpid(switch)
      for endhost in self.nib.get_endhosts(switch):
        (host, host_port, host_mac, host_ip) = endhost
        opposite_switch = self.nib.opposite_switch(switch)
        dest_cdr = self.nib.actual_net_for(opposite_switch)
        (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)

        # Note we really don't have to test for source IP, but it's extra security
        policies.append(Filter( 
          Policies.at_switch_port(dpid,host_port) & 
          Policies.is_ip() & 
          IP4SrcEq(host_ip) & 
          IP4DstEq(dest_net,dest_mask) & 
          self.destination_not_known_host_on_net(host_ip, dest_cdr)
        ) >> Policies.send_to_controller())
        for ap in self.nib.alternate_paths():
          dest_cdr = ap[opposite_switch]
          (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)
          policies.append(Filter( 
            Policies.at_switch_port(dpid,host_port) & 
            Policies.is_ip() & 
            IP4SrcEq(host_ip) & 
            IP4DstEq(dest_net,dest_mask) &
            self.destination_not_known_host_on_net(host_ip, dest_cdr)
          ) >> Policies.send_to_controller())

      # Now handle incoming packets for all our home networks.  We need to learn
      # those (src, dest) pairs as well
      for ap in self.nib.alternate_paths():
        dest_cdr = ap[switch]
        (dest_net, dest_mask) = NetUtils.net_mask(dest_cdr)
        policies.append(Filter( 
          Policies.is_ip() & 
          IP4DstEq(dest_net,dest_mask) &
          self.src_dest_pair_not_learned(dest_cdr)
        ) >> Policies.send_to_controller())

    return Union(policies)

  # TODO: This is a lot like send_along_preferred_path and send_along_direct_path, 
  # but in rule form
  def ingress_src_dest_pairs_policy(self):
    policies = []
    for src_dest_pair in self.nib.get_ingress_src_dest_pairs():
      (src_ip, dst_ip) = src_dest_pair
      switch = self.nib.switch_for_ip(src_ip)
      dpid = self.nib.switch_to_dpid(switch)
      port = self.nib.port_for_ip(src_ip) 
      src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
      # If this is going to the preferred network, write a rule choosing the 
      # correct route here.
      opposite_switch = self.nib.opposite_switch(switch)
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
        # Get host from src_ip
        src_pref_net = self.nib.preferred_net(switch)
        new_src = NetUtils.ip_for_network(src_pref_net, src_host)
        dest_host = NetUtils.host_of_ip(dst_ip, self.nib.actual_net_for(opposite_switch))
        new_dest = NetUtils.ip_for_network(self.nib.preferred_net(opposite_switch), dest_host)

        preferred_net_gateway = NetUtils.ip_for_network(src_pref_net, 1)
        preferred_net_port = self.nib.port_for_ip(preferred_net_gateway) 

        output_actions = SetIP4Src(new_src) >> SetIP4Dst(new_dest) >> Send(preferred_net_port)
        policies.append(
          Filter( Policies.at_switch_port(dpid, port) & Policies.is_ip_from_to(src_ip, dst_ip) ) 
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
          Filter( Policies.at_switch_port(dpid, port) & Policies.is_ip_from_to(src_ip, dst_ip) ) 
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
        new_src_ip = self.nib.translate_alternate_net(src_ip)
        output_actions = SetIP4Src(new_src_ip) >> SetIP4Dst(new_dest_ip) >> Send(direct_net_port)
        policies.append(
          Filter( SwitchEq(self.nib.switch_to_dpid(switch)) & Policies.is_ip_from_to(src_ip, dst_ip) ) 
          >> output_actions
        )
    return Union(policies)

  def policy(self):
  	return Union([ 
  		self.capture_new_source_dest_pairs_policy(), 
      self.ingress_src_dest_pairs_policy(),
      self.egress_src_dest_pairs_policy()
  	])

  def send_along_preferred_path(self, switch, src_ip, dst_ip, payload ):
    # Get host from src_ip
    src_pref_net = self.nib.preferred_net(switch)
    src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
    # Translate this to the preferred path IP
    new_src = NetUtils.ip_for_network(src_pref_net, src_host)
    # And do the same for the destination
    opposite_switch = self.nib.opposite_switch(switch)
    dest_host = NetUtils.host_of_ip(dst_ip, self.nib.actual_net_for(opposite_switch))
    new_dest = NetUtils.ip_for_network(self.nib.preferred_net(opposite_switch), dest_host)

    # What is the port on this switch that corresponds to the preferred path?
    preferred_net_gateway = NetUtils.ip_for_network(src_pref_net, 1)
    preferred_net_port = self.nib.port_for_ip(preferred_net_gateway)   

    output_actions = [
      SetIP4Src(new_src), 
      SetIP4Dst(new_dest),
      Output(Physical(preferred_net_port))
    ]
    dpid = self.nib.switch_to_dpid(switch)
    self.main_app.pkt_out(dpid, payload, output_actions)

  # TODO: This is almost like send_along_preferred_path except we don't touch the 
  # destination host address
  def send_along_direct_path(self, switch, src_ip, dst_ip, payload ):
    opposite_switch = self.nib.opposite_switch(switch)
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
    self.main_app.pkt_out(dpid, payload, output_actions)

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
      self.main_app.send_arp_request(switch, src_ip, new_dest_ip)
    else:
      direct_net_port = self.nib.port_for_ip(new_dest_ip)
      # We also need to translate the alternately-numbered net to a real one.  Otherwise the 
      # host (which only knows real networks) may not know what to do with it.
      new_src_ip = self.nib.translate_alternate_net(src_ip)
      output_actions = [
        SetIP4Src(new_src_ip),
        SetIP4Dst(new_dest_ip),
        Output(Physical(direct_net_port))
      ]
      dpid = self.nib.switch_to_dpid(switch)
      self.main_app.pkt_out(dpid, payload, output_actions)

  # Like send_to_host, but for intranet packets only which don't require rewrites.
  # Most of the time these are handled by switch intranet rules, but may get here if
  # we haven't learned the IP on our net yet.  
  def send_to_host_without_rewrite(self, switch, src_ip, dst_ip, payload ):
    # Convert dst_ip to its real form.  First find out what the egress switch actually is:
    real_net = self.nib.actual_net_for(switch)
    # If we don't know the port for this address (which might happen if the 
    # IP is on this network, but the host isn't up or doesn't exist) just send
    # an ARP request.  Alternatively, we could flood it out, but ARP has the advantage
    # of making the port get learned.  
    if not self.nib.learned_ip(dst_ip):
      arp_src_ip = NetUtils.ip_for_network(real_net, 250)
      self.main_app.send_arp_request(switch, arp_src_ip, dst_ip)
    else:
      direct_net_port = self.nib.port_for_ip(dst_ip)
      output_actions = [ Output(Physical(direct_net_port)) ]
      dpid = self.nib.switch_to_dpid(switch)
      self.main_app.pkt_out(dpid, payload, output_actions)

  def packet_in(self, dpid, port, payload):
    p_eth = NetUtils.packet(payload, 'ethernet')
    if p_eth.ethertype != 0x0800:
      return

    p_ip = NetUtils.packet(payload, 'ipv4')
    src_ip = p_ip.src
    dst_ip = p_ip.dst
    switch = self.nib.dpid_to_switch(dpid)

    # If we haven't seen this source, dest pair yet, add it, and the rule with it.
    # Which list we put it in depends on whether we're at the ingress or egress switch
    if self.nib.at_ingress_switch(switch, port):
      # TODO: If this packet is bound for hosts outside the CoSciN network, in production just forward them,
      # For now, just drop them.  
      if not self.nib.ip_in_coscin_network(dst_ip):
         logging.info("Internet-bound packet dropped in this test network")
         return
      # It's possible that this is an intra-network packet even though the rule should 've been installed
      # to handle such packets directly.  send_along_direct_path will handle it below.
      elif NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
        pass 
      elif not self.nib.seen_src_dest_pair_at_ingress(src_ip, dst_ip):
        self.nib.add_ingress_src_dest_pair(src_ip, dst_ip)
        self.nib.set_dirty()
    elif self.nib.at_egress_switch(switch, port):
      if not self.nib.seen_src_dest_pair_at_egress(src_ip, dst_ip):
        self.nib.add_egress_src_dest_pair(src_ip, dst_ip)
        self.nib.set_dirty()

    # If we have seen it, the rule should've taken care of the next packets, but it might
    # not be in effect yet so we handle it manually
    opposite_switch = self.nib.opposite_switch(switch)
    if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
      self.send_along_preferred_path( switch, src_ip, dst_ip, payload )
    elif self.nib.at_ingress_switch(switch, port):
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
        self.send_to_host_without_rewrite( switch, src_ip, dst_ip, payload )
      else: 
        self.send_along_direct_path( switch, src_ip, dst_ip, payload )
    elif self.nib.at_egress_switch(switch, port):
      self.send_to_host( switch, src_ip, dst_ip, payload )

