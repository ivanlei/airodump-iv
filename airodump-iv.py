"""
airdump-iv is a utility which sniffs 802.11X activity

The goal of this script is to aggregate the functionality of tools like
airmon-ng and airodump-ng into a single easily extendable python tool.

Current functionality mimics airodump-ng for the most part.

Using Wireless Extensions (WE) ioctls for speedy channel changing
  WT -- http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/Tools.html
  WE -- /usr/include/linux/wireless.h
"""
import curses
import errno
import re
import scapy
import socket
import sys
import traceback

from datetime import datetime
from fcntl import ioctl
from optparse import OptionParser
from random import randint
from scapy.all import sniff
from scapy.fields import array
from scapy.fields import BitField
from scapy.fields import ByteField
from scapy.fields import ConditionalField
from scapy.fields import EnumField
from scapy.fields import Field
from scapy.fields import FieldLenField
from scapy.fields import FieldListField
from scapy.fields import FlagsField
from scapy.fields import IntField
from scapy.fields import LEFieldLenField
from scapy.fields import LEIntField
from scapy.fields import LELongField
from scapy.fields import LEShortField
from scapy.fields import LESignedIntField
from scapy.fields import PacketField
from scapy.fields import PacketLenField
from scapy.fields import PacketListField
from scapy.fields import ShortField
from scapy.fields import StrField
from scapy.fields import StrFixedLenField
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
from scapy.packet import Packet
from struct import calcsize
from struct import pack_into
from struct import unpack
from subprocess import check_call
from tempfile import SpooledTemporaryFile


BROADCAST_BSSID = 'ff:ff:ff:ff:ff:ff'

def shell_command(cmd):
	"""Shell out a subprocess and return what it writes to stdout as a string"""
	in_mem_file = SpooledTemporaryFile(max_size=2048, mode="r+")
	check_call(cmd, shell=True, stdout=in_mem_file)
	in_mem_file.seek(0)
	stdout = in_mem_file.read()
	in_mem_file.close()
	del in_mem_file
	return stdout

class SignedByteField(Field):
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<b')


class LESignedShortField(Field):
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<h')


class iw_param(Packet):
	name = 'iw_param struct'

	fields_desc = [
		LEIntField('value', 0),
		ByteField('fixed', 0),
		ByteField('disabled', 0),
		LEShortField('flags', 0)
	]


class iw_point(Packet):
	name = 'iw_point struct'

	fields_desc = [
		LEIntField('pointer', 0),
		LEShortField('length', 0),
		LEShortField('flags', 0)
	]

class iw_quality(Packet):
	name = 'iw_quality struct'

	fields_desc = [
		ByteField('qual', 0),
		ByteField('level', 0),
		ByteField('noise', 0),
		ByteField('updated', 0)
	]

class iw_freq(Packet):
	name = 'iw_freq struct'

	fields_desc = [
		LESignedIntField('m', 0),
		LESignedShortField('e', 0),
		ByteField('i', 0),
		ByteField('flags', 0)
	]

class iw_req(Packet):
	name = 'iw_req struct'

	fields_desc = [
		StrFixedLenField('iface', 0, length=16)
	]


class iw_freq_req_resp(Packet):
	name = 'iw_freq_req_resp struct'

	fields_desc = [
		StrFixedLenField('iface', 0, length=16),
		PacketLenField('iw_freq', None, iw_freq, length_from=lambda pkt: 8)
	]


class iw_range(Packet):
	name = 'iw_range struct'

	fields_desc = [
		LEIntField('throughput', 0),
		LEIntField('min_nwid', 0),
		LEIntField('max_nwid', 0),
		LEShortField('old_num_channels', 0),
		ByteField('old_num_frequency', 0),
		ByteField('scan_capa', 0),
		FieldListField('event_capa', None, LEIntField('', 0), count_from=lambda pkt: 6),
		LESignedIntField('sensitivity', 0),
		PacketLenField('max_qual', None, iw_quality, length_from=lambda pkt: 4),
		PacketLenField('avg_qual', None, iw_quality, length_from=lambda pkt: 4),
		ByteField('num_bitrates', 0),
		FieldListField('bitrate', None, LESignedIntField('', 0), count_from=lambda pkt: 32),
		LESignedIntField('min_rts', 0),
		LESignedIntField('max_rts', 0),

		LESignedIntField('min_frag', 0),
		LESignedIntField('max_frag', 0),

		LESignedIntField('min_pmp', 0),
		LESignedIntField('max_pmp', 0),
		LESignedIntField('min_pmt', 0),
		LESignedIntField('max_pmt', 0),

		LEShortField('pmp_flags', 0),
		LEShortField('pmt_flags', 0),
		LEShortField('pm_capa', 0),
		FieldListField('encoding_size', None, LEShortField('', 0), count_from=lambda pkt: 8),
		ByteField('num_encoding_sizes', 0),
		ByteField('max_encoding_tokens', 0),
		ByteField('encoding_login_index', 0),
		LEShortField('txpower_capa', 0),
		ByteField('num_txpower', 0),
		FieldListField('txpower', None, LESignedIntField('', 0), count_from=lambda pkt: 8),
		ByteField('we_version_compiled', 0),
		ByteField('we_version_source', 0),

		LEShortField('retry_capa', 0),
		LEShortField('retry_flags', 0),
		LEShortField('r_time_flags', 0),
		LESignedIntField('min_retry', 0),
		LESignedIntField('max_retry', 0),
		LESignedIntField('min_r_time', 0),
		LESignedIntField('max_r_time', 0),

		LEShortField('num_channels', 0),
		ByteField('num_frequency', 0),
		FieldListField('freq', None, PacketLenField('', None, iw_freq, length_from=lambda pkt: 8), count_from=lambda pkt: 32),
		LEIntField('enc_capa', 0)
	]

class WirelessExtension:
	IFNAMSIZ = 16

	freq_map = None

	@staticmethod
	def ioctl_get_freq_map(iface):
		if WirelessExtension.freq_map:
			return WirelessExtension.freq_map

		# Allocate an array for the response
		buff_out = array.array('B', '\0' * 2048)
		pointer, length = buff_out.buffer_info()

		req = iw_req(iface)/iw_point(pointer=pointer, length=length)
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B0B, str(req))
		sockfd.close()
		del sockfd

		resp = iw_range(buff_out.tostring())

		WirelessExtension.freq_map = {}
		for freq in resp.getfieldval('freq'):
			if freq.m:
				WirelessExtension.freq_map[str(freq.i)] = freq
		return WirelessExtension.freq_map

	@staticmethod
	def ioctl_get_channel(iface):
		req = iw_freq_req_resp(iface)
		buff_in_out = array.array('B', str(req))
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B05, buff_in_out, 1)
		sockfd.close()
		del sockfd

		resp = iw_freq_req_resp(buff_in_out.tostring())
		return min(14, max(1, (resp[iw_freq].m - 2407) / 5))

	@staticmethod
	def ioctl_set_channel(iface, channel):
		WirelessExtension.ioctl_get_freq_map(iface)
		freq = WirelessExtension.freq_map[str(channel)]

		req = iw_req(iface)/iw_freq(m=freq.m, e=freq.e, i=freq.i, flags=freq.flags)/iw_freq()
		buff_in_out = array.array('B', str(req))
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B04, buff_in_out, 0)
		sockfd.close()
		del sockfd

class Printer:
	"""A class for printing messages that respects verbosity levels"""
	verbose_level = 0

	@staticmethod
	def verbose(message, verbose_level=1):
		"""Print a message only if it is within an acceptabe verbosity level"""
		if Printer.verbose_level >= verbose_level:
			sys.stdout.write(message)
			sys.stdout.write('\n')

	@staticmethod
	def write(message):
		"""Write a message to stdout"""
		sys.stdout.write(message)
		sys.stdout.write('\n')

	@staticmethod
	def error(message):
		"""Write a message to stderr"""
		sys.stderr.write(message)
		sys.stderr.write('\n')

	@staticmethod
	def exception(e):
		"""Write a summary of an exception with a stack trace"""
		Printer.error(repr(e))
		traceback.print_exc(file=sys.stderr)


def scapy_packet_Packet_hasflag(self, field_name, value):
	"""Is the specified flag value set in the named field"""
	field, val = self.getfield_and_val(field_name)
	if isinstance(field, EnumField):
		if val not in field.i2s:
			return False
		return field.i2s[val] == value
	else:
		return (1 << field.names.index([value])) & self.__getattr__(field_name) != 0
scapy.packet.Packet.hasflag = scapy_packet_Packet_hasflag
del scapy_packet_Packet_hasflag

def scapy_fields_FieldListField_i2repr(self, pkt, x):
	"""Return a list with the representation of contained fields"""
	return repr([self.field.i2repr(pkt, v) for v in x])
FieldListField.i2repr = scapy_fields_FieldListField_i2repr
del scapy_fields_FieldListField_i2repr

class ChannelFromMhzField(LEShortField):
	def m2i(self, pkt, x):
		return min(14, max(1, (x - 2407) / 5))


class PresentFlagField(ConditionalField):
	def __init__(self, field, flag_name):
		ConditionalField.__init__(self, field, lambda pkt: pkt.hasflag('present', flag_name))


# TODO(ivanlei): This fields_desc does not cover chained present flags decode will fail in this cases
scapy.layers.dot11.RadioTap.name = '802.11 RadioTap'
scapy.layers.dot11.RadioTap.fields_desc = [
	ByteField('version', 0),
	ByteField('pad', 0),
	LEShortField('RadioTap_len', 0),
	FlagsField('present', None, -32, ['TSFT','Flags','Rate','Channel','FHSS','dBm_AntSignal',
									  'dBm_AntNoise','Lock_Quality','TX_Attenuation','dB_TX_Attenuation',
									  'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
									  'b14', 'b15','b16','b17','b18','b19','b20','b21','b22','b23',
									  'b24','b25','b26','b27','b28','b29','b30','Ext']),
	PresentFlagField(LELongField('TSFT', 0), 'TSFT'),
	PresentFlagField(ByteField('Flags', 0), 'Flags'),
	PresentFlagField(ByteField('Rate', 0), 'Rate'),
	PresentFlagField(ChannelFromMhzField('Channel', 0), 'Channel'),
	PresentFlagField(LEShortField('Channel_flags', 0), 'Channel'),
	PresentFlagField(ByteField('FHSS_hop_set', 0), 'FHSS'),
	PresentFlagField(ByteField('FHSS_hop_pattern', 0), 'FHSS'),
	PresentFlagField(SignedByteField('dBm_AntSignal', 0), 'dBm_AntSignal'),
	PresentFlagField(SignedByteField('dBm_AntNoise', 0), 'dBm_AntNoise'),
	PresentFlagField(LEShortField('Lock_Quality', 0), 'Lock_Quality'),
	PresentFlagField(LEShortField('TX_Attenuation', 0), 'TX_Attenuation'),
	PresentFlagField(LEShortField('db_TX_Attenuation', 0), 'dB_TX_Attenuation'),
	PresentFlagField(SignedByteField('dBm_TX_Power', 0), 'dBm_TX_Power'),
	PresentFlagField(ByteField('Antenna', 0), 'Antenna'),
	PresentFlagField(ByteField('dB_AntSignal', 0), 'dB_AntSignal'),
	PresentFlagField(ByteField('dB_AntNoise', 0), 'dB_AntNoise'),
	PresentFlagField(LEShortField('RX_Flags', 0), 'b14')
]

def scapy_layers_dot11_RadioTap_extract_padding(self, s):
	"""Ignore any unparsed conditionally present fields

	If all fields have been parsed, the payload length should have decreased RadioTap_len bytes
	If it has not, there are unparsed fields which should be treated as padding
	"""
	post_disset_len = len(s)
	padding = len(s) - (self.pre_dissect_len - self.RadioTap_len)
	if padding:
		return s[padding:], s[:padding]
	else:
		return s, None
scapy.layers.dot11.RadioTap.extract_padding = scapy_layers_dot11_RadioTap_extract_padding
del scapy_layers_dot11_RadioTap_extract_padding

def scapy_layers_dot11_RadioTap_pre_dissect(self, s):
	"""Cache to total payload length prior to dissection for use in finding padding latter"""
	self.pre_dissect_len = len(s)
	return s
scapy.layers.dot11.RadioTap.pre_dissect = scapy_layers_dot11_RadioTap_pre_dissect
del scapy_layers_dot11_RadioTap_pre_dissect


class Dot11EltRSN(Packet):
	"""The enc, cipher, and auth members contain the decoded 'security' details"""

	name = '802.11 RSN Information Element'

	cipher_suites = { '\x00\x0f\xac\x00': 'GROUP',
					  '\x00\x0f\xac\x01': 'WEP',
					  '\x00\x0f\xac\x02': 'TKIP',
					  '\x00\x0f\xac\x04': 'CCMP',
					  '\x00\x0f\xac\x05': 'WEP' }

	auth_suites = { '\x00\x0f\xac\x01': 'MGT',
					'\x00\x0f\xac\x02': 'PSK' }

	fields_desc = [
		LEShortField('version', 1),
		StrFixedLenField('group_cipher_suite', '', length=4),
		LEFieldLenField('pairwise_cipher_suite_count', 1, count_of='pairwise_cipher_suite'),
		FieldListField('pairwise_cipher_suite', None, StrFixedLenField('','', length=4), count_from=lambda pkt: pkt.pairwise_cipher_suite_count),
		LEFieldLenField('auth_cipher_suite_count', 1, count_of='auth_cipher_suite'),
		FieldListField('auth_cipher_suite', None, StrFixedLenField('','',length=4), count_from=lambda pkt: pkt.auth_cipher_suite_count),
		BitField('rsn_cap_pre_auth', 0, 1),
		BitField('rsn_cap_no_pairwise', 0, 1),
		BitField('rsn_cap_ptksa_replay_counter', 0, 2),
		BitField('rsn_cap_gtksa_replay_counter', 0, 2),
		BitField('rsn_cap_mgmt_frame_protect_required', 0, 1),
		BitField('rsn_cap_mgmt_frame_protect_capable', 0, 1),
		BitField('rsn_cap_reserved_1', 0, 1),
		BitField('rsn_cap_peer_key_enabled', 0, 1),
		BitField('rsn_cap_reserved_2', 0, 6),
	]

	def post_dissection(self, pkt):
		"""Parse cipher suites to determine encryption, cipher, and authentication methods"""

		self.enc = 'WPA2' # Everything is assumed to be WPA
		self.cipher = ''
		self.auth = ''

		for pairwise_cipher in self.getfieldval('pairwise_cipher_suite'):
			self.cipher = self.cipher_suites.get(pairwise_cipher, '')
			if 'GROUP' == self.cipher: # Must look at the group_cipher_suite
				for group_cipher in self.getfieldval('group_cipher_suite'):
					self.cipher = self.cipher_suites.get(group_cipher, '')
					break
			elif 'WEP' == self.cipher:
				enc = 'WEP'
			break

		for auth_cipher in self.getfieldval('auth_cipher_suite'):
			self.auth = self.auth_suites.get(auth_cipher, '')
			break


def scapy_layers_dot11_Dot11_elts(self):
	"""An iterator of Dot11Elt"""
	dot11elt = self.getlayer(Dot11Elt)
	while dot11elt and dot11elt.haslayer(Dot11Elt):
		yield dot11elt
		dot11elt = dot11elt.payload
scapy.layers.dot11.Dot11.elts = scapy_layers_dot11_Dot11_elts
del scapy_layers_dot11_Dot11_elts

def scapy_layers_dot11_Dot11_find_elt_by_id(self, id):
	"""Iterate over elt and return the first with a specific ID"""
	for elt in self.elts():
		if elt.ID == id:
			return elt
	return None
scapy.layers.dot11.Dot11.find_elt_by_id = scapy_layers_dot11_Dot11_find_elt_by_id
del scapy_layers_dot11_Dot11_find_elt_by_id

def scapy_layers_dot11_Dot11_essid(self):
	"""Return the payload of the SSID Dot11Elt if it exists"""
	elt = self.find_elt_by_id(0)
	return elt.info if elt else None
scapy.layers.dot11.Dot11.essid = scapy_layers_dot11_Dot11_essid
del scapy_layers_dot11_Dot11_essid

def scapy_layers_dot11_Dot11_sta_bssid(self):
	"""Return the bssid for a station associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr2
	else:
		return self.addr1
scapy.layers.dot11.Dot11.sta_bssid = scapy_layers_dot11_Dot11_sta_bssid
del scapy_layers_dot11_Dot11_sta_bssid

def scapy_layers_dot11_Dot11_ap_bssid(self):
	"""Return the bssid for a access point associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr1
	else:
		return self.addr2
scapy.layers.dot11.Dot11.ap_bssid = scapy_layers_dot11_Dot11_ap_bssid
del scapy_layers_dot11_Dot11_ap_bssid

def scapy_layers_dot11_Dot11_channel(self):
	"""Return the payload of the channel Dot11Elt if it exists"""
	elt = self.find_elt_by_id(3)
	if elt:
		try:
			return int(ord(elt.info))
		except Exception, e:
			Printer.error('Bad Dot11Elt channel got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.channel = scapy_layers_dot11_Dot11_channel
del scapy_layers_dot11_Dot11_channel

def scapy_layers_dot11_Dot11_rsn(self):
	"""Return the payload of the RSN Dot11Elt as a Dot11EltRSN"""
	elt = self.find_elt_by_id(48)
	if elt:
		try:
			return Dot11EltRSN(elt.info)
		except Exception, e:
			Printer.error('Bad Dot11EltRSN got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.rsn = scapy_layers_dot11_Dot11_rsn
del scapy_layers_dot11_Dot11_rsn


class Dot11ScannerOptions:
	"""A collection of options to control how the script runs"""
	def __init__(self):
		self.iface = 'mon0'
		self.packet_count = 0
		self.channel = -1
		self.channel_hop = True
		self.max_channel = -1
		self.input_file = None
		self.enable_curses = True

	@staticmethod
	def create_scanner_options():
		"""A class factory which parses command line options and returns a Dot11ScannerOptions instance"""
		parser = OptionParser()
		parser.add_option('-i', '--iface', dest='iface', default='mon0',
						  help='Interface to bind to')
		parser.add_option('-c', '--channel', dest='channel', default=-1, type='int',
						  help='Channel to bind to')
		parser.add_option('--max-channel', dest='max_channel', default=-1, type='int',
						  help='Maximum channel number')
		parser.add_option('--packet_count', dest='packet_count', default=-1, type='int',
						  help='Number of packets to capture')
		parser.add_option('-r', '--input-file', dest='input_file', default=None,
						  help='Read packets from pcap file')
		parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
						  help='Print verbose information')
		parser.add_option('--verbose-level', dest='verbose_level', default=0, type='int',
						  help='Level of verbosity')
		parser.add_option('--no-curses', dest='no_curses', default=False, action='store_true',
		                  help='Do not enable curses display')
		options, _ = parser.parse_args()

		scanner_options = Dot11ScannerOptions()
		scanner_options.iface = options.iface
		scanner_options.channel = options.channel
		scanner_options.channel_hop = (-1 == options.channel and not options.input_file)
		scanner_options.max_channel = options.max_channel
		if -1 == scanner_options.max_channel:
			try:
				# TODO(ivanlei): shelling out is slow - investigate using an ioctl
				iwlist_output = shell_command('iwlist {0} channel'.format(scanner_options.iface))
				match = re.match('\s?{0}\s+(\d+)'.format(scanner_options.iface), iwlist_output)
				scanner_options.max_channel = int(match.group(1))
				Printer.verbose('CHAN: max_channel[{0}]'.format(scanner_options.max_channel), verbose_level=1)
			except Exception, e:
				Printer.exception(e)
				raise

		scanner_options.packet_count = options.packet_count
		scanner_options.input_file = options.input_file
		scanner_options.enable_curses = not options.no_curses

		if options.verbose:
			options.verbose_level = 1
		Printer.verbose_level = options.verbose_level
		return scanner_options

class AccessPoint:
	"""Representation of an access point"""

	def __init__(self, packet):
		self.bssid = packet[Dot11].ap_bssid()
		self.beacon_count = 0
		self.sta_bssids = set()
		self.essid = ''
		self.channel = None
		self.enc = 'OPN'
		self.cipher = ''
		self.auth = ''
		self.hidden_essid = False
		self.power = 0

		self.display_row = -1

	def update(self, packet):
		essid = packet[Dot11].essid()
		if essid:
			self.essid = essid

		self.channel = packet[Dot11].channel() or packet[RadioTap].Channel
		if packet.haslayer(Dot11Beacon):
			self.beacon_count += 1
			self.hidden_essid = (not essid)

			if packet.hasflag('cap', 'privacy'):
				elt_rsn = packet[Dot11].rsn()
				if elt_rsn:
					self.enc = elt_rsn.enc
					self.cipher = elt_rsn.cipher
					self.auth = elt_rsn.auth
				else:
					self.enc = 'WEP'
					self.cipher = 'WEP'
					self.auth = ''
			else:
				self.enc = 'OPN'
				self.cipher = ''
				self.auth = ''

		elif packet.haslayer(Dot11ProbeResp):
			self.sta_bssids.add(packet[Dot11].sta_bssid())

		if self.bssid == packet[Dot11].addr2:
			power = packet[RadioTap].dBm_AntSignal
			if power:
				self.power = power

	def show(self, bssid_to_essid=None):
		if not self.essid and bssid_to_essid:
			self.essid = bssid_to_essid.get(self.bssid, self.essid)

		hidden = 'YES' if self.hidden_essid else 'NO'

		summary = '{0:<18} {1: >4d} {2: >7d} {3: >2d} {4:<4} {5:<6} {6:<4} {7: >3} {8:<32} '.format(
			self.bssid,
			self.power,
			self.beacon_count,
			self.channel,
			self.enc,
			self.cipher,
			self.auth,
			hidden,
			self.essid
		)
		#if len(self.sta_bssids):
		#	summary = '\n'.join([summary, '\t{0}'.format(' '.join(self.sta_bssids))])

		return summary


class Station:
	def __init__(self, bssid):
		self.bssid = bssid
		self.probes = {}
		self.auth_reqs = {}
		self.is_in_active_mode = False

	def _add_probe(self, packet):
		essid = packet[Dot11].essid()
		if essid in self.probes:
			self.probes[essid] += 1
		else:
			self.probes[essid] = 1

	def _add_auth_req(self, packet):
		ap_bssid = packet[Dot11].ap_bssid()
		if ap_bssid in self.auth_reqs:
			self.auth_reqs[ap_bssid] += 1
		else:
			self.auth_reqs[ap_bssid] = 1

	def update(self, packet):
		if packet.haslayer(Dot11ProbeReq):
			self._add_probe(packet)

		if packet.haslayer(Dot11Auth):
			self._add_auth_req(packet)

		if packet[Dot11].hasflag('FCfield', 'to-DS'):
			self.is_in_active_mode = packet[Dot11].hasflag('FCfield', 'pw-mgt')

	@staticmethod
	def _show_bssid(bssid, bssid_to_essid):
		if bssid_to_essid and bssid in bssid_to_essid:
			return '{0} ({1})'.format(bssid_to_essid[bssid], bssid)
		return bssid

	def show(self, bssid_to_essid=None):
		return 'STA {0:<18} probes:{1} auth_req:{2}'.format(self.bssid,
															repr(self.probes),
															repr([self._show_bssid(auth_req, bssid_to_essid) for auth_req in self.auth_reqs]))


class Dot11Scanner:

	def __init__(self, scanner_options):
		self.scanner_options = scanner_options
		self.access_points = dict()
		self.stations = dict()
		self.bssid_to_essid = dict()

	def _update_access_points(self, packet):
		show = False

		# Look for an ap or create one
		bssid = packet[Dot11].ap_bssid()
		if bssid == BROADCAST_BSSID:
			return None

		if bssid in self.access_points:
			ap = self.access_points[bssid]
		else:
			ap = self.access_points[bssid] = AccessPoint(packet)
			show = True
		ap.update(packet)

		self.bssid_to_essid[ap.bssid] = ap.essid

		if show:
			Printer.verbose(ap.show(bssid_to_essid=self.bssid_to_essid), verbose_level=1)

		return ap

	def _update_stations(self, packet):
		show = False

		bssid = packet[Dot11].sta_bssid()
		if bssid in self.stations:
			station = self.stations[bssid]
		else:
			station = self.stations[bssid] = Station(bssid)
			show = True
		station.update(packet)

		if show:
			Printer.verbose(station.show(), verbose_level=2)

		return station

	def _filter_function(self, packet):
		try:
			# Verify the RadioTap header
			if packet.haslayer(RadioTap):
				assert (self.scanner_options.input_file or (self.scanner_options.channel == packet[RadioTap].Channel)), 'got[{0}] expect[{1}]'.format(packet[RadioTap].Channel, self.scanner_options.channel)
				channel_from_ioctl = WirelessExtension.ioctl_get_channel(self.scanner_options.iface)
				assert (self.scanner_options.input_file or (self.scanner_options.channel == channel_from_ioctl)), 'got[{0}] expected[{1}]'.format(channel_from_ioctl, self.scanner_options.channel)

			# Track AP and STA
			if packet.haslayer(Dot11):
				ap = None
				if packet.haslayer(Dot11Beacon):
					ap = self._update_access_points(packet)

				elif any(packet.haslayer(layer) for layer in [Dot11ProbeReq, Dot11ProbeResp, Dot11Auth]):
					ap = self._update_access_points(packet)
					self._update_stations(packet)

				if self.display and ap:
					self.display.update(ap)

				return True

			# That's unexpected.  print for debugging
			else:
				Printer.error(packet.show())
		except Exception, exc:
			Printer.exception(exc)
		finally:
			return False

	def seconds_elapsed(self):
		time_delta = datetime.now() - self.scan_start_time
		return (time_delta.microseconds + (time_delta.seconds + time_delta.days * 24 * 3600) * 10**6) / 10**6

	def scan(self, window = None):
		self.scan_start_time = datetime.now()

		if window:
			self.display = Display(window, self)
		else:
			self.display = None

		timeout = None

		if self.scanner_options.channel_hop:
			self.scanner_options.channel = randint(1, self.scanner_options.max_channel)
			self.set_channel(self.scanner_options.channel)
			timeout = 5
		elif -1 != self.scanner_options.channel:
			self.set_channel(self.scanner_options.channel)

		while True:
			try:
				sniff(iface=self.scanner_options.iface,
					  store=False,
					  count=self.scanner_options.packet_count,
					  offline=self.scanner_options.input_file,
					  timeout=timeout,
					  lfilter=self._filter_function)
				if timeout:
					self.scanner_options.channel = ((self.scanner_options.channel + 3) % self.scanner_options.max_channel) + 1
					self.set_channel(self.scanner_options.channel)
				else:
					break

			# Exit the scan on a keyboard break
			except KeyboardInterrupt:
				break

			# Curses generates system interupt exception (EINTR) when the window is resized
			except Exception, e:
				if e.args and e.args[0] == errno.EINTR:
					pass
				else:
					raise

	def set_channel(self, channel):
		Printer.verbose('CHAN: set_channel {0}'.format(channel), verbose_level=3)
		WirelessExtension.ioctl_set_channel(self.scanner_options.iface, channel)
		if self.display:
			self.display.update_header()

	def print_results(self):
		Printer.write('\n\n')
		Printer.write('{0:<18} {1:>4} {2:<7} {3:2} {4:<4} {5:<6} {6:<4} {7:3} {8:<32}'.format('BSSID', 'PWR', 'BEACONS', 'CH', 'ENC', 'CIPHER', 'AUTH', 'HID', 'ESSID'))
		for access_point in self.access_points.values():
			Printer.write(access_point.show(bssid_to_essid=self.bssid_to_essid))

		for bssid, station in self.stations.iteritems():
			if len(station.probes) or len(station.auth_reqs):
				Printer.write(station.show(bssid_to_essid=self.bssid_to_essid))

class Display:
	def __init__(self, window, scanner):
		self.window = window
		self.scanner = scanner
		self.free_row = 2

		curses.use_default_colors()

		# not all terminals offer curs_set to adjust cursor visibility
		try:
			self.window.curs_set(0)
		except:
			try:
				self.window.curs_set(1)
			except:
				pass

		self.window.clear()
		header = '{0:<18} {1:>4} {2:<7} {3:2} {4:<4} {5:<6} {6:<4} {7:3} {8:<32}'.format('BSSID', 'PWR', 'BEACONS', 'CH', 'ENC', 'CIPHER', 'AUTH', 'HID', 'ESSID')
		self.addstr(self.free_row, header)
		self.free_row += 2
		self.window.refresh()

	def addstr(self, row, msg):
		self.window.addstr(row, 0, msg)
		self.window.clrtoeol()
		self.window.move(0,0)

	def update_header(self):
		header = ' CH {0:>2d}][ Elapsed {1:d}s][ {2:s}'.format(
			self.scanner.scanner_options.channel,
			self.scanner.seconds_elapsed(),
		    datetime.now().strftime('%x %X'))
		self.addstr(0, header)

	def update(self, access_point):

		# TODO(ivanlei) - When the # of rows exceeds the height of the window, this throws exceptions
		if -1 == access_point.display_row:
			access_point.display_row = self.free_row
			self.free_row += 1

		# Update a full line and don't leave the cursor at the end of the line
		self.addstr(access_point.display_row, access_point.show(bssid_to_essid=self.scanner.bssid_to_essid))

		# Update Headers
		self.update_header()

		# Repaint
		self.window.refresh()

scanner_options = None

def main():

	try:
		scanner_options = Dot11ScannerOptions.create_scanner_options()
		scanner = Dot11Scanner(scanner_options)

		try:
			if scanner_options.enable_curses:
				curses.wrapper(scanner.scan)
			else:
				scanner.scan()
		except Exception, e:
			Printer.exception(e)

		# Run with or without curses support, but finish in either case by printing a complete report
		if scanner:
			scanner.print_results()

	except Exception, e:
		sys.stderr.write(repr(e))
		traceback.print_exc(file=sys.stderr)


if __name__ == '__main__':
	main()