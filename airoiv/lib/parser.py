class Names(object):
    """This class helps airodump-iv to parse
    
    Parsing is done by way of dictionaries
    This is sort of a reverse way to look at scapy
    """

    def drivers(self, val):
        """Driver offsets for RadioTap Headers"""
        typeDict = {'ath9k': 19,
                    'ath9k_htc': 19,
                    'wl12xx': 11}
        return typeDict.get(val)
