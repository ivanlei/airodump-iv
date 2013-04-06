"""
airdump-iv is a utility which sniffs 802.11X activity

The goal of this script is to aggregate the functionality of tools like
airmon-ng and airodump-ng into a single easily extendable python tool.

Current functionality mimics airodump-ng for the most part.
"""
import curses
import errno
import scapy
import sys
import traceback

from datetime import datetime
from optparse import OptionParser
from random import randint
from scapy.all import sniff
from scapy.fields import array, BitField, EnumField, FieldListField, LEFieldLenField, LEShortField, StrFixedLenField
from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap
from scapy.packet import Packet
from struct import unpack
from subprocess import call


DEFAULT_BSSID = 'ff:ff:ff:ff:ff:ff' # default BSSID when real BSSID is unknown

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

# Field lens and data types found on:
# http://www.radiotap.org/defined-fields
scapy.layers.dot11.RadioTap.present_fields_with_len = [
	('TSFT',              8, '<Q'),
	('Flags',             1, '<B'),
	('Rate',              1, '<B'),
	('Channel',           4, '<HH'),
	('FHSS',              2, '<BB'),
	('dBm_AntSignal',     1, '<b'),
	('dBm_AntNoise',      1, '<b'),
	('Lock_Quality',      2, '<H'),
	('TX_Attenuation',    2, '<H'),
	('dB_TX_Attenuation', 2, '<H'),
	('dBm_TX_Power',      1, '<b'),
	('Antenna',           1, '<B'),
	('dB_AntSignal',      1, '<B'),
	('dB_AntNoise',       1, '<B')
]

def scapy_layers_dot11_RadioTap_present_field_val(self, name):
	"""Return an array of vales for the named present field or None if the field is not present"""
	if self.hasflag('present', name):
		byte_offset = 0
		for flag_name, flag_byte_len, flag_unpack_specifier in self.present_fields_with_len:
			if name == flag_name:
				try:
					str_val = self.notdecoded[byte_offset:byte_offset+flag_byte_len]
					vals = unpack(flag_unpack_specifier, array.array('B', str_val))
				except Exception, e:
					Printer.error('name[{0}] flags{1}'.format(name, flag_unpack_specifier))
					Printer.exception(e)
					raise
				return vals
			elif self.hasflag('present', flag_name):
				byte_offset += flag_byte_len
	return None
scapy.layers.dot11.RadioTap.present_field_val = scapy_layers_dot11_RadioTap_present_field_val
del scapy_layers_dot11_RadioTap_present_field_val

def scapy_layers_dot11_RadioTap_channel(self, default=-1):
	"""Return the channel reported in the RadioTap header

	This is the channel the interface is listening on, not the channel a packet was sent on"""
	vals = self.present_field_val('Channel')
	if vals:
		# The actual map between channels and mhz is not linear but this formula works for 802.1 b/g/n
		# TODO(ivanlei): read the flags(vals[1]) to determine how to interpret the mhz for the channel
		delta = vals[0] - 2407
		return min(14, max(1, delta / 5))
	return default
scapy.layers.dot11.RadioTap.channel = scapy_layers_dot11_RadioTap_channel
del scapy_layers_dot11_RadioTap_channel

def scapy_layers_dot11_RadioTap_antenna_signal_power(self):
	"""Return the antenna_signal_power for the sender of the packet"""
	vals = self.present_field_val('dBm_AntSignal')
	if vals:
		return vals[0]
	return None
scapy.layers.dot11.RadioTap.antenna_signal_power = scapy_layers_dot11_RadioTap_antenna_signal_power
del scapy_layers_dot11_RadioTap_antenna_signal_power


class Dot11EltRSN(Packet):
	"""Defined by IEEE Std 802.11i and contains 'security' details"""

	name = '802.11 RSN Information Element'

	cipher_suites = { '\x00\x0f\xac\x00': 'GROUP',
					  '\x00\x0f\xac\x01': 'WEP',
					  '\x00\x0f\xac\x02': 'TKIP',
					  '\x00\x0f\xac\x04': 'CCMP',
					  '\x00\x0f\xac\x05': 'WEP' }

	auth_suites = { '\x00\x0f\xac\x01': 'MGT',
					'\x00\x0f\xac\x02': 'PSK' }

	fields_desc = [ LEShortField('version', 1),
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

	def get_enc_cipher_auth(self):
		"""Return a triple of friendly names for encryption type, cipher suite, and authentication"""

		enc = 'WPA2' # Everything is assumed to be WPA
		cipher = ''
		auth = ''

		for pairwise_cipher in self.getfieldval('pairwise_cipher_suite'):
			cipher = self.cipher_suites.get(pairwise_cipher, '')
			if 'GROUP' == cipher: # Must look at the group_cipher_suite
				for group_cipher in self.getfieldval('group_cipher_suite'):
					cipher = self.cipher_suites.get(group_cipher, '')
					break
			elif 'WEP' == cipher:
				enc = 'WEP'
			break

		for auth_cipher in self.getfieldval('auth_cipher_suite'):
			auth = self.auth_suites.get(auth_cipher, '')
			break

		return enc, cipher, auth

def scapy_layers_dot11_Dot11_elts(self):
	"""An iterator of Dot11Elt"""
	dot11elt = self.getlayer(Dot11Elt)
	while dot11elt:
		yield dot11elt
		dot11elt = dot11elt.payload
scapy.layers.dot11.Dot11.elts = scapy_layers_dot11_Dot11_elts
del scapy_layers_dot11_Dot11_elts

def scapy_layers_dot11_Dot11_find_elt_by_id(self, id):
	"""Iterator over elt and return the first with a specific ID"""
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

def scapy_layers_dot11_Dot11_channel(self, default=-1):
	"""Return the payload of the channel Dot11Elt if it exists or default otherwise"""
	elt = self.find_elt_by_id(3)
	if elt:
		try:
			return int(ord(elt.info))
		except:
			Printer.error('Bad Dot11Elt channel got[%s]' % elt.info)
	return default
scapy.layers.dot11.Dot11.channel = scapy_layers_dot11_Dot11_channel
del scapy_layers_dot11_Dot11_channel

def scapy_layers_dot11_Dot11_rsn(self):
	"""Return the payload of the RSN Dot11Elt as a Dot11EltRSN"""
	elt = self.find_elt_by_id(48)
	if elt:
		try:
			return Dot11EltRSN(elt.info)
		except:
			Printer.error('Bad Dot11EltRSN got[%s]' % elt.info)
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
		self.max_channel = 11
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
		parser.add_option('--max-channel', dest='max_channel', default=11, type='int',
						  help='Maximum channel number')
		parser.add_option('--packet_count', dest='packet_count', default=0, type='int',
						  help='Number of packets to capture')
		parser.add_option('--input-file', dest='input_file', default=None,
						  help='pcap file to read from')
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
		scanner_options.packet_count = options.packet_count
		scanner_options.input_file = options.input_file
		scanner_options.enable_curses = not options.no_curses

		if options.verbose:
			options.verbose_level = 1
		Printer.verbose_level = options.verbose_level
		return scanner_options

class AccessPoint:
	def __init__(self, packet, channel=-1):
		self.bssid = packet[Dot11].ap_bssid()
		self.beacon_count = 0
		self.sta_bssids = set()
		self.essid = ''
		self.channel = packet[Dot11].channel(default=channel)
		self.enc = 'OPN'
		self.cipher = ''
		self.auth = ''
		self.hidden_essid = False
		self.power = 0

		self.display_row = -1

	def update(self, packet, channel=-1):
		essid = packet[Dot11].essid()
		if essid:
			self.essid = essid

		self.channel = packet[Dot11].channel(default=channel)
		if packet.haslayer(Dot11Beacon):
			self.beacon_count += 1
			self.hidden_essid = (not essid)

			if packet.hasflag('cap', 'privacy'):
				elt_rsn = packet[Dot11].rsn()
				if elt_rsn:
					self.enc, self.cipher, self.auth = elt_rsn.get_enc_cipher_auth()
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
			power = packet[RadioTap].antenna_signal_power()
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

	def __init__(self, scanner_options, window=None):
		self.scanner_options = scanner_options
		self.access_points = dict()
		self.stations = dict()
		self.bssid_to_essid = dict()
		if window:
			self.display = Display(window, self)
		else:
			self.display = None

	def _update_access_points(self, packet, channel=-1):
		show = False

		# Look for an ap or create one
		bssid = packet[Dot11].ap_bssid()
		if bssid == DEFAULT_BSSID:
			return None

		if bssid in self.access_points:
			ap = self.access_points[bssid]
		else:
			ap = self.access_points[bssid] = AccessPoint(packet, channel=channel)
			show = True
		ap.update(packet, channel=channel)

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
				assert (self.scanner_options.input_file or (self.scanner_options.channel == packet[RadioTap].channel()))

			# Track AP and STA
			if packet.haslayer(Dot11):
				ap = None
				if packet.haslayer(Dot11Beacon):
					ap = self._update_access_points(packet, channel=self.scanner_options.channel)

				elif any(packet.haslayer(layer) for layer in [Dot11ProbeReq, Dot11ProbeResp, Dot11Auth]):
					ap = self._update_access_points(packet, channel=self.scanner_options.channel)
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
		td = datetime.now() - self.start_time
		return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6

	def scan(self):
		self.start_time = datetime.now()

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
		Printer.verbose('CHAN: set_channel %d' % channel, verbose_level=3)
		call('/sbin/iwconfig %s channel %d' % (self.scanner_options.iface, channel), shell=True)
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
	scanner_options = Dot11ScannerOptions.create_scanner_options()

	def run_scan(window=None):
		try:
			scanner = Dot11Scanner(scanner_options, window)
			scanner.scan()
		except Exception, e:
			Printer.exception(e)
		finally:
			if scanner:
				scanner.print_results()

	try:
		if scanner_options.enable_curses:
			curses.wrapper(run_scan)
		else:
			run_scan()

	except Exception, e:
		sys.stderr.write(repr(e))
		traceback.print_exc(file=sys.stderr)


if __name__ == '__main__':
	main()
