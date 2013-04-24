# Class: aircrack-ng
#
# This class installs aircrack-ng tools
#
# Actions:
#   - Add the unofficial aircrack-ng repo to sources.list
#   - Allow apt-get install to pull from repos without a key
#       This is necessary as the aircrack-ng repo is unkeyed
#   - Installs the aircrack-ng package
#
# Sample Usage:
#  class { 'aircrack-ng': }
#
class aircrack-ng {
    include apt

    apt::source { 'aircrackng-unstable':
      location => 'http://repo.degeneratedlabs.net/debian/',
      repos => 'aircrackng-unstable/',
      release => '',
      before => Package['aircrack-ng'],
    }

    apt::conf { 'aircrackng-unstable' :
      content => 'APT::Get::AllowUnauthenticated "true";',
      priority => 70,
      before => Package['aircrack-ng'],
    }

    package { 'aircrack-ng':
      ensure => latest,
    }
}
