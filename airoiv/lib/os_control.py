import subprocess
from shlex import split

class Control(object):
    """Control the underlying OS"""

    def __init__(self, nic):
        self.nic = nic


    def iwDriver(self):
        """Determine driver in use"""
        p1 = subprocess.Popen(split("grep '^DRIVER=' '/sys/class/net/%s/device/uevent'" % self.nic),
                              stdout = subprocess.PIPE)
        p2 = subprocess.Popen(split('cut -d= -f2'),
                              stdin = p1.stdout,
                              stdout = subprocess.PIPE)
        return p2.communicate()[0].strip()
