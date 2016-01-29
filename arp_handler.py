# ArpHandler
# Handles special ARP requests and replies, generating some for special purposes in Coscin

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

class ArpHandler():

  def __init__(self, main_app, nib):
    self.main_app = main_app
    self.nib = nib

  def gateway_ip(self, switch):
    return NetUtils.ip_for_network(self.nib.actual_net_for(switch), 1)

  def arp_reply(self, switch, port, src_mac, src_ip, target_mac, target_ip):
    e = ethernet.ethernet(dst=src_mac, src=target_mac, ethertype=ether.ETH_TYPE_ARP)
    # Note for the reply we flip the src and target, as per ARP rules
    pkt = arp.arp_ip(arp.ARP_REPLY, target_mac, target_ip, src_mac, src_ip)
    payload = self.main_app.arp_payload(e, pkt)
    self.main_app.pkt_out(self.nib.switch_to_dpid(switch), payload, [Output(Physical(port))])

  def dest_real_net(self, switch):
    net_and_mask = self.nib.actual_net_for(switch)
    (net, mask) = NetUtils.net_mask(net_and_mask)
    return IP4DstEq(net,mask)

  def policy(self):
    policies = []
    for switch in self.nib.switches_present():
      dpid = self.nib.switch_to_dpid(switch)
      # In normal mode, we capture ARP requests for IP's that don't really exist.  You can
      # think of them as symbolic links to the real IP.  We capture .1 address of
      # each of the endpoint networks, plus any real hosts on the net

      # And we capture ARP requests for the alternate paths.  These will always be for 
      # hosts that have no real estate on the imaginary link, as in 192.168.156.100 along 
      # the 192.168.156.* imaginary network.  This will be translated to the real net 192.168.56.100
      # Note: only the routers actually send these requests, not end hosts, who always send them
      # to a default gateway.  
      for ap in self.nib.alternate_paths():
        (net, mask) = NetUtils.net_mask(ap[switch])
        policies.append(Filter(Policies.at_switch(dpid) & Policies.is_arp() & IP4DstEq(net,mask)) >> Policies.send_to_controller())

    return Union(policies)

  def packet_in(self, dpid, port, payload):
    p_eth = NetUtils.packet(payload, 'ethernet')
    if p_eth.ethertype != 0x0806:
      return

    # Handle ARP requests.
    p_arp = NetUtils.packet(payload, 'arp')
    src_ip = p_arp.src_ip
    dst_ip = p_arp.dst_ip
    switch = self.nib.dpid_to_switch(dpid)
    if p_arp.opcode == arp.ARP_REQUEST:
      preferred_path = self.nib.get_preferred_path()

      # If the request is for a host in the net we're already in, just broadcast it.  The host
      # itself will answer.
      if NetUtils.ip_in_network(src_ip, self.nib.actual_net_for(switch)) and \
           NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
         real_dest_ip = None
      else:    # It's an imaginary host on one of the alternate paths
        real_dest_ip = self.nib.translate_alternate_net(dst_ip) 

      if real_dest_ip == None:
        logging.info("Flooding ARP Request")
        self.main_app.flood(switch, port, payload)
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
        self.main_app.send_arp_request(switch, src_ip, real_dest_ip)

    # We don't do anything special to ARP replies, just forward them onto their destination
    # unidirectionally
    # TODO: Can't this be handled by L2Switch, since it's bound for a real Mac?
    elif p_arp.opcode == arp.ARP_REPLY:
      # We ignore the text of ARP replies bound for us.  We just used them for learning the port.
      if p_eth.dst == self.main_app.BOGUS_MAC:
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
        self.main_app.pkt_out(dpid, payload, output_actions)

