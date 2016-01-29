# Broadcast Handler
# Handles L2 Broadcast Traffic from learned ports on switch  

import sys,logging
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
# Temporary until we merge streamlined sytnax into master
from streamlined_syntax import *
from policies import Policies
from net_utils import NetUtils

class BroadcastHandler():

  def __init__(self, main_app, nib):
    self.main_app = main_app
    self.nib = nib

  def policy(self):
    policies = []
    for switch in self.nib.switches_present():
      dpid = self.nib.switch_to_dpid(switch)

      # The router interface is no different than a regular host with regard to intranet traffic.
      learned_host_ports = [ p for (_, p, _, _) in self.nib.get_endhosts(switch)]
      learned_host_ports.append( self.nib.router_port_for_switch(switch) )

      for src_endhost_port in learned_host_ports:
        output_actions = [ Send(p) for p in self.nib.ports_on_switch(switch) if p != src_endhost_port ]
        policies.append( 
          Filter (Policies.at_switch_port(dpid, src_endhost_port) & EthDstEq("ff:ff:ff:ff:ff:ff")) >> 
          Seq(output_actions)
        )

    return Union(policies)

  # Intranet broadcast packets only come intot he controller when the port hasn't been learned yet
  def packet_in(self, dpid, port, payload):
    p_eth = NetUtils.packet(payload, 'ethernet')
    if p_eth.dst == 0xffffffffffff:
      self.main_app.flood( self.nib.dpid_to_switch(dpid), port, payload )    
