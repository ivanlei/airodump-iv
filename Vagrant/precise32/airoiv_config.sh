#!/bin/bash

# Update the OS
sudo apt-get -y -q update
#sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade

# Install prereqs and useful tools for wireless
sudo apt-get -y -q install git-core make python-scapy iw wireless-tools

# Install aircrack - airodump-iv.py still depends on running airomon-ng
# Set Wno-error during compilationto keep undefined variables 
# from making the build error out
wget -q http://download.aircrack-ng.org/aircrack-ng-1.1.tar.gz
tar -zxvf aircrack-ng-1.1.tar.gz
pushd ./aircrack-ng-1.1
CFLAGS=-Wno-error make strip
sudo make install
popd
sudo airodump-ng-oui-update

# Cleanup
rm ./aircrack-ng-1.1.tar.gz
rm -rf ./aircrack-ng-1.1

# And now, with a clean environment, get a copy of airodump-iv
git clone git://github.com/ivanlei/airodump-iv.git

