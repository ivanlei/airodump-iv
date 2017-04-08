import subprocess
from shlex import split

class Control(object):
    """Control the underlying OS"""
    def __init__(self, nic):
        self.nic = nic

    def iwSet(self, channel):
        """Set the wifi channel"""
        proc = subprocess.Popen(['iwconfig', self.nic, 'channel', str(channel)],
                                stdout = subprocess.PIPE,
                                shell = False)
        proc.communicate()


    def iwGet(self):
        """Show the current wifi channel"""
        p1 = subprocess.Popen(split('iwlist %s channel' % self.nic),
                              stdout = subprocess.PIPE)
        p2 = subprocess.Popen(split('tail -n 2'),
                              stdin = p1.stdout,
                              stdout = subprocess.PIPE)
        p3 = subprocess.Popen(split('head -n 1'),
                              stdin = p2.stdout,
                              stdout = subprocess.PIPE)
        return p3.communicate()[0].strip()
    
        
    def iwDriver(self):
        """Determine driver in use"""
        p1 = subprocess.Popen(split("grep 'DRIVER=' '/sys/class/net/%s/device/uevent'" % self.nic),
                              stdout = subprocess.PIPE)
        p2 = subprocess.Popen(split('cut -d= -f2'),
                              stdin = p1.stdout,
                              stdout = subprocess.PIPE)
        return p2.communicate()[0].strip()
    