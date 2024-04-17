import os
import shlex
import sys
import tempfile
import pyshark
from tlsobj.handshake import Handshake
from tlsobj.chello import CHello
from tlsobj.serverdata import Serverdata
from tlsobj.certificate import Certificate
from tlsobj.certificateverify import Certificateverify
from tlsobj.finished import Finished
from tlsobj.encrypted import Encrypted

size = 0

"""
    This function skips packets that the filter might not ignore
    checkings to avoid "attribute error" 
"""


def skipUnrelatedTLSPackets(pkt):
    if not hasattr(pkt, 'tls'):
        return 1
    if not hasattr(pkt.tls, 'field_names'):
        return 1
    if "QUIC Connection information" in str(pkt.tls):  # skip
        return 1
    if hasattr(pkt.tls, 'handshake_session_ticket'):
        return 1  # ignoring session ticket
    if "Client Master Key (2)" in str(pkt.tls):
        return 1  # sslv2 crashes the parser
    return 0

# returns how many handshake_types are in a packet


def getHSTypes(pkt):
    listtypes = []
    listLayers = pkt.get_multiple_layers("tls")
    for l in listLayers:
        if hasattr(l, 'handshake_type'):
            for k in l.handshake_type.fields:
                listtypes.append(int(k.show))
        elif hasattr(l, 'handshake'):
            if l.handshake == 'Handshake Protocol: Encrypted Handshake Message':
                listtypes.append(l.handshake)
        # else:	#app data; discard
    return listtypes


"""
	Entry point: returns an object with the corresponding pkt data
"""


def getTLSObjectList(pkt):
    returnlist = []  # ?

    hstypes = getHSTypes(pkt)
    for t in hstypes:  # https://datatracker.ietf.org/doc/html/rfc8446 section 4
        # CHello
        global size
        if t == 1:
            size = 0
            chobj = CHello()
            chobj.parseClientHello(pkt)
            returnlist.append(chobj)
        # SHello and auth
        elif t == 2:
            shobj = Serverdata()
            shobj.parseSHello(pkt)
            returnlist.append(shobj)
        elif t == 11:
            if not hasattr(pkt.tls, 'x509af_algorithm_id'):
                returnlist = []
                break
            certobj = Certificate()
            certobj.parseCertificate(pkt)
            returnlist.append(certobj)
        elif t == 15:
            certverobj = Certificateverify()
            certverobj.parseCertVerify(pkt)
            returnlist.append(certverobj)
        # Finished
        elif t == 20:
            finobj = Finished()
            finobj.parseFinished(pkt)
            # if clientFinished:
            returnlist.append(finobj)
            # else:
        elif t == 'Handshake Protocol: Encrypted Handshake Message':
            encrypt = Encrypted()
            size = size + int(pkt.tls.record_length)
            encrypt.parseEncrypted(pkt, size)
            returnlist.append(encrypt)

    return returnlist


"""
	Alternative entry point: returns CH-SH pairs when no keylog file is provided
"""


def getTLSPublicData(cap):
    print("Start parsing without keylog file...")
    tlsobjects = []  # ?
    for pkt in cap:

        if skipUnrelatedTLSPackets(pkt):
            continue

        hstypes = getHSTypes(pkt)
        for t in hstypes:

            # CHello
            if t == 1:
                chobj = CHello()
                chobj.parseClientHello(pkt)
                tlsobjects.append(chobj)
            # SHello and auth
            elif t == 2:
                shobj = Serverdata()
                shobj.parseSHello(pkt)
                tlsobjects.append(shobj)

    hslist = []
    hs = Handshake()
    hspair = 0
    for ob in tlsobjects:
        if isinstance(ob, CHello):
            setattr(hs, "chello", ob)
            hspair = 1
        elif isinstance(ob, Serverdata):
            setattr(hs, "serverdata", ob)
            setattr(hs, "ciphersuite", ob.hsciphersuite)
            # set empty certificate, cert verify and finished data
            certobj = Certificate()
            certverobj = Certificateverify()
            finobj = Finished()
            certobj.setNotProvidedInfo()
            certverobj.setNotProvidedInfo()
            finobj.setNotProvidedInfo()

            setattr(hs, "certificatedata", certobj)
            setattr(hs, "certificateverify", certverobj)
            setattr(hs, "finished", finobj)
            hspair = hspair + 1

        if hspair == 2:
            hs.hstime = 0
            hs.hssize = hs.chello.size + hs.serverdata.size
            hslist.append(hs)
            hs = Handshake()

    return hslist
