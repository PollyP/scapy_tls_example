# MIT License
#
#	Copyright 2023 P.S.Powledge
#
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#	of this software and associated documentation files(the "Software"), to deal
#	in the Software without restriction, including without limitation the rights
#	to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
#	copies of the Software, and to permit persons to whom the Software is
#	furnished to do so, subject to the following conditions :
#
#	The above copyright notice and this permission notice shall be included in all
#	copies or substantial portions of the Software.
#
#	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
#	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#	SOFTWARE.

# requires 2.5+ scapy
from scapy.all import *
from datetime import datetime
import enum
import http.client
import logging
import os
import random
import ssl
from time import sleep
#from IPython import embed
#from pdb import set_trace

mycount = 40
NSS_SECRETS_LOG = "secrets.log"

IFACE = "lo"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
GET_PATH = "/index.html"
MYFILTER = "tcp and port %s" % SERVER_PORT

logging.basicConfig(level=logging.DEBUG)

#
# the tl_ssession object needs to be mirrored with every direction change.
# these utility classes keep track of that.
#
class Direction(Enum):
    UNINITIALIZED = 0
    to_client = 1
    to_server = 2

class DirectionManager:
    def __init__( self, ):
        self.prevdirection = Direction.UNINITIALIZED
        self.direction = Direction.UNINITIALIZED
    def update( self, pkt ):
        self.prevdirection = self.direction
        if pkt['IP'].dst == SERVER_HOST and pkt['TCP'].dport == SERVER_PORT:
            self.direction = Direction.to_server
        else:
            self.direction = Direction.to_client
    def has_changed_direction( self ):
        if self.prevdirection == Direction.UNINITIALIZED: return False
        if self.direction == Direction.UNINITIALIZED: return False
        return self.prevdirection != self.direction
    def to_client( self ):
        return self.direction == Direction.to_client
    def to_server( self ):
        return self.direction == Direction.to_server

class TLSSessionManager:
    def __init__( self, directionManager ):
        self.direction_manager = directionManager
        self.tls_session = None
    def init_session( self, client_hello_tls_session ):
        self.tls_session = client_hello_tls_session
    def get_session( self ):
        if self.direction_manager.has_changed_direction():
            return self.tls_session.mirror()
        else:
            return self.tls_session
    def set_nss_keys( self, nss_keys ):
        self.tls_session.nss_keys = nss_keys

#
# take an input packetlist and return just the non-duplicated TCP packets in a new packetlist
#
def filter_packet_list( pl ):
    filtered_pl = PacketList()
    ip_packets_seen = {}
    logging.info("filtering out duplicate and non-TCP packets from sniffed packets === ")
    for idx,pkt in enumerate(pl):
        # filter out non-IP and non-TCP packets
        if not pkt.haslayer('IP') or not pkt.haslayer('TCP'):
            logging.info("dropping non-TCP packet #%d, summary=%s" % (idx,pkt.summary()))
            continue
        # filter out duplicate IP packets
        if pkt.haslayer('IP') and pkt['IP'].id in ip_packets_seen:
            logging.info("dropping duplicate packet #%d, id=%d summary=%s" % (idx,pkt['IP'].id,pkt.summary()))
            continue
        ip_packets_seen[ pkt['IP'].id ] = True
        filtered_pl.append( pkt )
        logging.info("keeping packet #%d, id=%d summary=%s" % (idx,pkt['IP'].id,pkt.summary()))
    logging.info("=== filtering out duplicate and non-TCP packets from sniffed packets\n")
    return filtered_pl

#
# for a TLS layer input, return a list of the contained TLS record classes
#
def get_tls_record_names(tls_layer):

    # this is some sort of strange psuedo array that you need to
    # detect the end of by catching an IndexError?!?
    # reference: https://stackoverflow.com/questions/61304869/how-to-read-a-packet-tls-meta-data-with-scapy-python
    i = 0
    returned_classes = []
    logging.info("enumerating TLS content records === ")
    while True:
        try:
            logging.info(" %s" % tls_layer[i].summary())
            returned_classes.append( tls_layer[i].msg[0].__class__ )
        except AttributeError as e:
            # subcomponent of a TLS section. keep on trucking.
            pass
        except IndexError as e:
            break
        i = i + 1
    logging.info("=== end enumerating TLS content records\n")
    return returned_classes

#
# sniff pcount packets and return them as a packetlist value in a dictionary
#
def sniff_traffic(pcount,results):

    # sniff traffic until we get pcount packets
    #myprn = lambda x:x.summary()
    myprn = ""
    sniff_out = sniff(filter=MYFILTER,prn=myprn,count=pcount,iface=IFACE)

    # return sniffed packets
    results['sniffed_packets'] = sniff_out
    return

def send_https_request_and_capture_traffic(server_host,server_port,get_path,pcount):
    thread_results = dict()

    # put SSLKEYLOGFILE into the environment so that I can capture SSL keys
    #if os.path.isfile(NSS_SECRETS_LOG): os.remove(NSS_SECRETS_LOG)
    os.environ["SSLKEYLOGFILE"] = NSS_SECRETS_LOG
    logging.info("NSS secrets log set to %s" % NSS_SECRETS_LOG)

    # start another thread that sniffs the generated traffic
    t = threading.Thread(target=sniff_traffic, args=(pcount,thread_results))
    t.start()

    # wait for the sniffing thread to get going
    time.sleep(3)

    try:
        # use python requests to make a HTTPS connection to SERVER_HOST
        # the unverified context parameter is used so Requests will still work with a self signed cert,
        # which my test server uses.
        logging.info("opening HTTPS connection to host %s, port %d" % (server_host,server_port)) 
        conn = http.client.HTTPSConnection(server_host, server_port, context=ssl._create_unverified_context())
        logging.info("sending command %s" % get_path)
        conn.request('GET', get_path)
        r = conn.getresponse()
        logging.info("https response ===")
        logging.info(r.read())
        logging.info("=== end https response\n")

    except http.client.HTTPException as e:
        logging.critical("Exception: %s" % str(e))
        sys.exit(1)

    # wait for the sniff thread to finish up
    t.join()

    logging.debug("sniffing finished")
    raw_pl = thread_results['sniffed_packets']

    # scapy's tls notebook at https://github.com/secdev/scapy/blob/master/doc/notebooks/tls/notebook3_tls_compromised.ipynb
    # gives us two choices for decrypting the tls output. the first is to update the conf with the now-generated
    # nss key file, write the packetlist to a pcap file, and then read the pcap file. the second way is update the tls_session
    # with the nss keys, and then pass the session when parsing the TLS layer to get the decrypted version. this demonstrates the second way.
    # note that the session-passing approach means that as the conversation swings back and # forth, the session needs to be mirrored.
    # this happens under the hood in the TlsSessionManager class.

    # we've got a secrets log now, so apply it to the conf
    logging.debug("updating conf contents with NSS secrets === ")
    conf.tls_nss_filename = NSS_SECRETS_LOG
    conf.tls_nss_keys = load_nss_keys(NSS_SECRETS_LOG)
    logging.debug(conf)
    logging.debug("=== end updating conf contents with NSS secrets\n")

    # throw out duplicates and non-TCP packets
    filtered_pl = filter_packet_list(raw_pl)

    # initialize everything pre-parsing
    logging.info("starting to process filtered sniffed packets\n")
    tls_pl = PacketList()
    direction_manager = DirectionManager()
    tls_session_manager = TLSSessionManager( direction_manager )

    for idx,pkt in enumerate(filtered_pl):

        logging.debug("looking at TCP packet #%d %s ===" % (idx,pkt.summary()))
        # skip packets that don't have loads that can be converted into TLS
        if not hasattr(pkt,'load'):
            logging.debug("not TCP or doesn't have a load -- skipping\n")
            continue

        # turn the TCP packet's payload into a TLS layer
        tls_r = TLS(pkt.load)
        if not isinstance(tls_r,scapy.layers.tls.record.TLS):
            logging.error("failed to turn this packet into TLS?\n")
            continue

        logging.info("turned this into a TLS layer: %s" % tls_r.summary())

        # update direction info and get a list of the contained TLS record classes
        direction_manager.update(pkt)
        #embed()
        tls_record_names = get_tls_record_names(tls_r)

        # step through each phase of the TLS conversation, updating the tls_session as we go
        # tls 1.2 protocol reference: https://tls12.xargs.org/
        if scapy.layers.tls.handshake.TLSClientHello in tls_record_names:
            logging.info("==> client -> server: client hello")
            tls_session_manager.init_session( tls_r.tls_session )
        elif scapy.layers.tls.handshake.TLSServerHelloDone in tls_record_names:
            logging.info("==> server -> client: server hello, server certificate, server key exchange, server hello done")
            # reparse with client_hello's session
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
            # add the captured NSS keys to session for decrypting rest of connection 
            tls_session_manager.set_nss_keys( conf.tls_nss_keys )
        elif scapy.layers.tls.record.TLSChangeCipherSpec in tls_record_names and direction_manager.to_client():
            logging.info("==> client -> server: client key exchange, client change cipher spec, client handshake finished")
            # reparse with server_hello's session
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
        elif scapy.layers.tls.record.TLSChangeCipherSpec in tls_record_names and direction_manager.to_server():
            logging.info("==> server -> client: new session ticket, server change cipher spec, server handshake finished")
            # reparse with client's change cipher spec session
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
        elif scapy.layers.tls.record.TLSApplicationData in tls_record_names and direction_manager.to_client():
            logging.info("==> client -> server: application data")
            # reparse with server's change cipher spec session
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
            logging.info("data: %s" % tls_r[0].msg[0].data)
        elif scapy.layers.tls.record.TLSApplicationData in tls_record_names and direction_manager.to_server():
            logging.info("==> server -> client: application data")
            # reparse with client's application data
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
            logging.info("data: %s" % tls_r[0].msg[0].data)
        elif scapy.layers.tls.record.TLSAlert in tls_record_names:
            # haven't seen this in the wild. might need some tinkering when i do see it.
            tls_r = TLS(pkt.load, tls_session=tls_session_manager.get_session())
            logging.info(tls_r.show())
            logging.warning("==> tls alert received")
        else:
            logging.error("what is this?!???")
        tls_pl.append(tls_r)
        logging.debug("=== end looking at TCP packet %d %s\n" % (idx,pkt.summary()))

    logging.debug("finished w filtered_pl")
    return tls_pl

load_layer("http")
load_layer("tls")

# conf commands from https://github.com/secdev/scapy/pull/3374
conf.tls_session_enable = True

logging.debug("scapy version: %s" % scapy.__version__)
logging.debug("conf contents ===")
logging.debug(conf)
logging.debug("=== conf contents\n")

tls_results = send_https_request_and_capture_traffic(server_host=SERVER_HOST,server_port=SERVER_PORT,get_path=GET_PATH,pcount=mycount)
logging.info("TLS results ===")
logging.info(tls_results)
logging.info("=== end TLS results")



