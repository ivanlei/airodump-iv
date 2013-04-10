"""
Utilities for using Wireless Extensions (WE) ioctls
  WT -- http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/Tools.html
  WE -- /usr/include/linux/wireless.h

As set of scapy Packet classes model the structs from wireless.h
"""
import socket

from fcntl import ioctl
from scapy.fields import array
from scapy.fields import ByteField
from scapy.fields import FieldListField
from scapy.fields import LEIntField
from scapy.fields import LEShortField
from scapy.fields import LESignedIntField
from scapy.fields import PacketLenField
from scapy.fields import StrFixedLenField
from scapy.packet import Packet

from scapy_ex import LESignedShortField

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
	"""A singleton for getting/caching/setting data with WE IOCTLS"""

	# Dict to map [channel -> iw_freq]
	_freq_map = None

	# Maximum available channel
	_max_channel = -1

	@staticmethod
	def _ioctl_get_freq_map(iface):
		"""Populate an iw_range with data and introspect the frequency data"""
		if WirelessExtension._freq_map:
			return WirelessExtension._freq_map

		# Allocate an array for the response
		buff_out = array.array('B', '\0' * 2048)
		pointer, length = buff_out.buffer_info()

		req = iw_req(iface)/iw_point(pointer=pointer, length=length)
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B0B, str(req))
		sockfd.close()
		del sockfd

		resp = iw_range(buff_out.tostring())

		WirelessExtension._freq_map = {}
		for freq in resp.getfieldval('freq'):
			if freq.m:
				WirelessExtension._freq_map[str(freq.i)] = freq
				if freq.i > WirelessExtension._max_channel:
					WirelessExtension._max_channel = freq.i

		return WirelessExtension._freq_map

	@staticmethod
	def get_max_channel(iface):
		"""Get the maximum channel supported by the interface"""
		WirelessExtension._ioctl_get_freq_map(iface)
		return WirelessExtension._max_channel


	@staticmethod
	def get_channel(iface):
		"""Get the current channel for the interface"""
		req = iw_freq_req_resp(iface)
		buff_in_out = array.array('B', str(req))
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B05, buff_in_out, 1)
		sockfd.close()
		del sockfd

		resp = iw_freq_req_resp(buff_in_out.tostring())
		return min(14, max(1, (resp[iw_freq].m - 2407) / 5))

	@staticmethod
	def set_channel(iface, channel):
		"""Set the current channel for the interface"""
		WirelessExtension._ioctl_get_freq_map(iface)
		freq = WirelessExtension._freq_map[str(channel)]

		req = iw_req(iface)/iw_freq(m=freq.m, e=freq.e, i=freq.i, flags=freq.flags)/iw_freq()
		buff_in_out = array.array('B', str(req))
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), 0x8B04, buff_in_out, 0)
		sockfd.close()
		del sockfd
