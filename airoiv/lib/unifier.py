from parser import Names

pParser = Names()

class Unify(object):
    """This class acts a singular point of contact for tracking purposes"""

    def __init__(self, iwDriver):

        ## Set the driver
        self.iwDriver = iwDriver
        
        ## Notate driver offset
        self.pParser = Names()
        self.offset = self.pParser.drivers(self.iwDriver)
