# Policies
# These are nice syntactic sugar for various oft-used NetKAT policy combinations

from streamlined_syntax import *

class Policies():

  @staticmethod
  def send_to_controller():
    return SendToController("coscin_switch_app")

  @staticmethod
  def is_arp():
    return EthTypeEq(0x806)

  @staticmethod
  def is_ip():
    return EthTypeEq(0x800)

  @staticmethod
  def at_switch(dpid):
    return SwitchEq(dpid)

  @staticmethod
  def at_switch_port(dpid, port):
    return SwitchEq(dpid) & PortEq(port)

  @staticmethod
  def is_ip_from_to(src_ip, dest_ip):
    return Policies.is_ip() & IP4SrcEq(src_ip) & IP4DstEq(dest_ip)

  @staticmethod
  def is_arp_from_to(src_ip, dest_ip):
    return Policies.is_arp() & IP4SrcEq(src_ip) & IP4DstEq(dest_ip)
