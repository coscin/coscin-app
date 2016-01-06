# Streamlined Frenetic Syntax.  Once this is working, it should be merged into
# lang/pythom/syntax.py

# Note: I'm sure there's a nicer way to do this ...
import sys
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *

# These classes are syntactic sugar to reduce the number of parantheses in 
# Net apps.  They're pretty redundant, but since the NetKAT syntax doesn't 
# change often, deupification is not really warranted.

########## ___Eq

class SwitchEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(Switch(value))

	def to_json(self):
		return self.hv.to_json()

class PortEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(Location(Physical(value)))

	def to_json(self):
		return self.hv.to_json()

class EthSrcEq(Pred):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Test(EthSrc(value))

	def to_json(self):
		return self.hv.to_json()

class EthDstEq(Pred):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Test(EthDst(value))

	def to_json(self):
		return self.hv.to_json()

class VlanEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(Vlan(value))

	def to_json(self):
		return self.hv.to_json()

class VlanPcpEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(VlanPcp(value))

	def to_json(self):
		return self.hv.to_json()

class EthTypeEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(EthType(value))

	def to_json(self):
		return self.hv.to_json()

class IPProtoEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

class IP4SrcEq(Pred):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Test(IP4Src(value, mask))

	def to_json(self):
		return self.hv.to_json()

class IP4DstEq(Pred):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Test(IP4Dst(value, mask))

	def to_json(self):
		return self.hv.to_json()

class TCPSrcPortEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

class TCPDstPortEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Test(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

########## ___NotEq

class SwitchNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(Switch(value)))

	def to_json(self):
		return self.hv.to_json()

class PortNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(Location(Physical(value))))

	def to_json(self):
		return self.hv.to_json()

class EthSrcNotEq(Pred):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Not(Test(EthSrc(value)))

	def to_json(self):
		return self.hv.to_json()

class EthDstNotEq(Pred):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Not(Test(EthDst(value)))

	def to_json(self):
		return self.hv.to_json()

class VlanNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(Vlan(value)))

	def to_json(self):
		return self.hv.to_json()

class VlanPcpNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(VlanPcp(value)))

	def to_json(self):
		return self.hv.to_json()

class EthTypeNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(EthType(value)))

	def to_json(self):
		return self.hv.to_json()

class IPProtoNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(IPProto(value)))

	def to_json(self):
		return self.hv.to_json()

class IP4SrcNotEq(Pred):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Not(Test(IP4Src(value, mask)))

	def to_json(self):
		return self.hv.to_json()

class IP4DstNotEq(Pred):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Not(Test(IP4Dst(value, mask)))

	def to_json(self):
		return self.hv.to_json()

class TCPSrcPortNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(IPProto(value)))

	def to_json(self):
		return self.hv.to_json()

class TCPDstPortNotEq(Pred):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Not(Test(IPProto(value)))

	def to_json(self):
		return self.hv.to_json()

########## Set___

class SetEthSrc(Policy):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Mod(EthSrc(value))

	def to_json(self):
		return self.hv.to_json()

class SetEthDst(Policy):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Mod(EthDst(value))

	def to_json(self):
		return self.hv.to_json()

class SetVlan(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(Vlan(value))

	def to_json(self):
		return self.hv.to_json()

class SetVlanPcp(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(VlanPcp(value))

	def to_json(self):
		return self.hv.to_json()

class SetEthType(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(EthType(value))

	def to_json(self):
		return self.hv.to_json()

class SetIPProto(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

class SetIP4Src(Policy):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Mod(IP4Src(value, mask))

	def to_json(self):
		return self.hv.to_json()

class SetIP4Dst(Policy):
	def __init__(self, value, mask = None):
		assert(type(value) == str or type(value == unicode))
		if mask != None:
			assert type(mask) == int
		self.hv = Mod(IP4Dst(value, mask))

	def to_json(self):
		return self.hv.to_json()

class SetTCPSrcPort(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

class SetTCPDstPort(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 0)
		self.hv = Mod(IPProto(value))

	def to_json(self):
		return self.hv.to_json()

############### Misc.

class Send(Policy):
	def __init__(self, value):
		if (type(value)) == str:
			value = int(value)
		assert(type(value) == int and value >= 1 and value <= 65535)
		self.hv = Mod(Location(Physical(value)))

	def to_json(self):
		return self.hv.to_json()

class SendToController(Policy):
	def __init__(self, value):
		assert(type(value) == str or type(value == unicode))
		self.hv = Mod(Location(Pipe(value)))

	def to_json(self):
		return self.hv.to_json()
