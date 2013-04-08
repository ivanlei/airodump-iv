airodump-iv
===========

A python implementation of airodump-ng - the classic wifi sniffing tool.

airodump-iv is probably inferior in a lot of ways to airodump-ng but is being written as a learning tool.  It might also be useful to python developers interested in wifi sniffing.

Currently the only feature in airodump-iv not in airodump-ng is clearly identifying the SSIDs for hidden networks (when possible).

airodump.py is being developed in a BackTrack 5  R3 VM with an Alpha AWUS036H wireless case
* For more BackTrack: http://www.backtrack-linux.org/
* For more Alpha AWUS036H: https://www.google.com/search?q=Alpha+AWUS036H
``TODO``

airodump.py makes uses of scapy	for sniffing and protocol/structure parsing
* For more scapy: http://www.secdev.org/projects/scapy/
* For better scapy docs: http://fossies.org/dox/scapy-2.2.0/index.html

My interest in this project was kicked off by a wifi penetration class @ Blackhat EU.  Since then I've read quite a few protocol documents.
* For more on the class: http://www.blackhat.com/eu-13/training/advanced-wifi-penetration-testing.html
* 802.11 base spec - http://standards.ieee.org/getieee802/download/802.11-2012.pdf
* 802.11i security spec - http://standards.ieee.org/getieee802/download/802.11i-2004.pdf
* Radiotap Headers - http://www.radiotap.org/
* Wireless Extensions IOCTL - ``less /usr/include/linux/wireless.h``

Installation & Running
======================

Currently under	active development, airodump-iv	has no installer.

Steps to run include:
* Set wireless card into monitor mode:
  * ``sudo airmon-ng check kill``
  * ``sudo airmon-ng start wlan0``
* Once the card	is in monitor mode:
  * ``sudo python	airodump-iv.py``

Useful options include:
* ``--iface=IFACE`` - Set the interface	to sniff on.  By default ``mon0``.
* ``--channel=CHANNEL`` - Monitor a single channel.  By default airodump-iv will channel-hop
* ``--max-channel=MAX_CHANNEL``	- Set maximum channel during hopping.  By default uses maximum ch\
annel reported by ``iwlist IFACE channel``.
* ``--packet_count=PACKET_COUNT`` - Number of packets to capture.  By default unlimited.
* ``--input-file=INPUT_FILE`` -	Read from PCAP file.
* ``-v`` - Verbose mode.  Does not play	well with curses mode.
* ``--no-curses`` - Disable the curses interface.

Interesting TODOs
=================
* Remove all calls to ``subprocess.check_call`` - with basic IOCTL support in place, this should be easy
* Create proper package - split scapy extensions from ioctl support from sniffer
* Fix curses mode display to not have quite so many bugs
* Display total # of data packets per AP
* Display maximum support rate per AP
* Improve station display
* Test in clean install of BackTrack 5
* Test in clean install of Kali Linux
* Document setup necessary on clean install of lucid/precise
* Test with other wifi cards
* Write unit tests
* Cleanup code
* World peace
