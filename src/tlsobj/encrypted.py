import os
import sys
from tlsobj.pktinfo import Pktinfo


class Encrypted(object):
    """docstring for encrypted"""

    def __init__(self, size=None, time=None, pktinfo=None):
        super(Encrypted, self).__init__()
        self.size = size  # handshake_length
        self.pktinf = pktinfo

    def parseEncrypted(self, pkt, size):
        self.size = size
        info = Pktinfo()
        info.parsePktInfo(pkt)
        self.pktinf = info
