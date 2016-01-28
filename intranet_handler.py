# IntranetSwitch
# Handles traffic between two hosts on the same side of the Coscin Network.  It's
# mostly like an L2 switch, but only handles IP traffic.  

# TODO: There's really no reason this has to be IP only.  Originally I designed it that
# way so it doesn't overlap, but since we do pairwise mac rules, it doesn't really matter.

import sys
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
# Temporary until we merge streamlined sytnax into master
from streamlined_syntax import *
from policies import Policies

class IntranetHandler():

  def __init__(self, main_app, nib):
    self.main_app = main_app
    self.nib = nib

  def policy(self):
    # One rule sends all traffic from unlearned ports to controller.
    is_at_unlearned_port = []
    unlearned_ports = self.nib.get_unlearned_ports()
    for switch, ports in unlearned_ports.iteritems():
      dpid = self.nib.switch_to_dpid(switch)
      for port in ports:
        is_at_unlearned_port.append(Policies.at_switch_port(dpid,port))
    policies = [ Filter(Or(is_at_unlearned_port)) >> Policies.send_to_controller() ]

    # Output rules for each pair of learned endhosts so intranet traffic can be handled nicely on 
    # the switch.
    # TODO: If the app is restarted but hosts are hanging onto ARP cache entries, they won't be able
    # to get packets to each other.  This is hard to handle because a "Port = n AND Dest Net = this"
    # might have overlap with other rules ... I think  
    # Therefore, I'm letting this go for now because (1) intranet host
    # traffic is relatively rare (2) ARP cache entries usually timeout in 10 minutes anyway.  
    # L2Switch.policy.  
    for switch in self.nib.switches_present():
      dpid = self.nib.switch_to_dpid(switch)
      for src_endhost in self.nib.get_endhosts(switch):
        (_, src_port, _, src_ip) = src_endhost
        for dst_endhost in self.nib.get_endhosts(switch):
          (_, dst_port, _, dst_ip) = dst_endhost
          # No rule for a host to itself, obviously
          if src_ip != dst_ip:
            policies.append(
              Filter(Policies.is_ip_from_to(src_ip, dst_ip) & Policies.at_switch_port(dpid, src_port) )
              >> Send(dst_port)
            )
    return Union(policies)

  # Intranet packets never come to the controller, so nothing to do here...
  def packet_in(self, dpid, port, payload):
    pass
