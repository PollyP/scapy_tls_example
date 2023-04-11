#   MIT License
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
import argparse
import binascii
from datetime import datetime
import enum
import http.client
import logging
import os
import random
import ssl
import subprocess
from time import sleep
from IPython import embed
from pdb import set_trace

####################################################################################################################################################
#
# constants
#
####################################################################################################################################################

mycount = 25
NSS_SECRETS_LOG = "secrets"
RAW_SNIFF_FILENAME = "raw_sniff"
PROCESSED_TLS_FILENAME = "processed_tls_packets"

# default server settings. can override at command line
server_details = { 'iface': 'eth1', 'host': 'httpbin.org', 'port': 443, 'path': '/' }

logging.basicConfig(level=logging.DEBUG)

CONFIG = { 'nss_secrets_log_file_name' : "" }

####################################################################################################################################################
#
# Direction class keeps track if we are talking to client/server and if the conversation direction has changed
#
####################################################################################################################################################
class Direction(Enum):
    UNINITIALIZED = 0
    to_client = 1
    to_server = 2

class DirectionManager:
    def __init__( self, server_host, server_port ):
        self.prevdirection = Direction.UNINITIALIZED
        self.direction = Direction.UNINITIALIZED
        self.server_host = server_host
        self.server_port = server_port
    def has_changed_direction( self, pkt ):
        '''Returns True direction has changed from previous packet, False if it hasn't'''
        self.prevdirection = self.direction
        # FIXME dns ip lookup issue here
        if pkt['IP'].src != self.server_host and pkt['IP'].dst != self.server_port:
            logging.info("can't match on %s, just using port matching instead" % self.server_host)
            to_server_match = pkt['TCP'].dport == self.server_port
        else:
            to_server_match = pkt['IP'].dst == self.server_host and pkt['TCP'].dport == self.server_port
        if to_server_match:
            self.direction = Direction.to_server
        else:
            self.direction = Direction.to_client
        logging.info("direction manager updated : %s" % str(self))
        return self._has_changed_direction()
    def _has_changed_direction( self ):
        if self.prevdirection == Direction.UNINITIALIZED: return False
        if self.direction == Direction.UNINITIALIZED: return False
        logging.info("just before has changed dir check: %s" % str(self))
        return self.prevdirection != self.direction
    def to_client( self ):
        return self.direction == Direction.to_client
    def to_server( self ):
        return self.direction == Direction.to_server
    def __str__(self):
        return "direction manager state: prev dir = %s dir = %s" % (self.prevdirection.name,self.direction.name)

####################################################################################################################################################
#
# TLSSessionManager class keeps track of the TLS session and handles the mirroring. The master key also gets stored here until we have a
# live session to load it into
#
####################################################################################################################################################
class TLSSessionManager:
    def __init__( self ):
        self.tls_session = None
        self.master_key = None
    def update_session_direction( self ):
        if self.tls_session:
            logging.info("session MIRROR")
            self.tls_session = self.tls_session.mirror()
    def get_session( self ):
        if not self.tls_session:
            logging.debug("get_session: no tls session set yet")
            return None
        return self.tls_session
    def update_session( self, new_tls_session ):
        logging.debug("updated session")
        self.tls_session = new_tls_session
    def set_master_key( self, masterkey ):
        self.master_key = masterkey
    def __str__(self):
        if self.tls_session:
            nss_key_data = ""
            if self.tls_session.master_secret:
                nss_key_data = nss_key_data + " master secret %s" % binascii.hexlify(self.tls_session.master_secret)
            if self.tls_session.sid:
                nss_key_data = nss_key_data + " sid %s" % binascii.hexlify(self.tls_session.sid)
            return "tls session = %s session nss key fields: %s" % (self.tls_session, nss_key_data)
        elif self.master_key:
            return "tls session not set yet. stored master key: %s" % binascii.hexlify(self.master_key)
        else:
            return "no tls session or master key set yet"


####################################################################################################################################################
#
# TLSRecordsExtractor class takes a TLS layer and returns TLS records. It handles PDUs split across packets seamlessly.
#
####################################################################################################################################################

TLS_HDR_LEN_IN_B = 5 # tls header len in bytes: msgtype, version, payload len. tls header len + len(tls payload) should be same as containing tcp payload len

class ReassemblyType(Enum):
    WHOLE_RECORD = 0,
    INCOMPLETE_RECORD = 1,
    REASSEMBLED_RECORD = 2

class TLSRecordsExtractor:
    def __init__( self ):
        self.tls_records_list = []
        self.tls_rec_len = 0                # if we know the length of the first pdu in the bytestream, this is > 0
                                            # potentialy different from the length of the bytestream itself, which may be larger
        self.tls_bytestream = b''           # the current bytestream, pre-parsing

    # this the main public-facing interface of this class
    def do_extract( self, tls_l ):
        '''this returns a list of tuples, one for each tls record found in the layer. The record can be as a self-contained pdu from the layer, 
        or the last chunk of a continued pdu that's spread across multiple TLS layers.

        Each tuple has three parts: (1) the extracted record layer, (2) an enclosing TLS layer, and (3) a status indicator that
        says if the pdu was complete or not.'''

        # the indexing system for TLS layers with multiple TLS records looks like this:
        # 0: all TLS records, 1: 1st TLS record + its subrecords, 2: 1st TLS record's 1st subrecord, ...
        # n: 1st TLS record's last subrecord, n+1: all subsequent TLS records, n+2: the 2nd TLS record ...

        # strategy: only TLS records are top level records, so step through all indexes and just
        # return TLS records. Also need special handling for raw packets, since those are partial
        # pdus that need to be reassembled.
        i = 0
        returned_records = []
        logging.info("enumerating TLS content records === ")

        while True:
            try:
                logging.info("%d %s" % (i,tls_l[i].summary()))
                if isinstance(tls_l[i],scapy.layers.tls.record.TLS) or issubclass(tls_l[i].__class__,scapy.layers.tls.record.TLS):
                    logging.info("got a TLS class")
                    # now pull out all the TLS records inside it
                    if hasattr(tls_l[i],"msg") and len(tls_l[i].msg) > 0:
                        for j in range(len(tls_l[i].msg)):
                            if self.tls_rec_len > 0:
                                # bytes leftover from previous pdu processing?
                                # assume this is just a continuation of a partial record
                                logging.info("continuation of a pdu! (from TLS)")
                                assembled_recs = self.update_pdu_assembler( tls_l[i].msg[j].original )
                                for ar in assembled_recs:
                                    # FIXME doesn't cover case of (partial),(end-of-partial,wholerecord)
                                    returned_records.append( (ar,ReassemblyType.REASSEMBLED_RECORD) )
                                logging.info(self)
                                continue

                            # filter out tls 13 packets of all kinds
                            if is_layer_tls13( tls_l[i].msg[j] ):
                                logging.error("got some TLS 1.3 records?!?:")
                                continue

                            # is this a raw record? probably a partial record
                            if isinstance(tls_l[i].msg[j], scapy.packet.Raw):
                                logging.info("found partial? pdu len=%d deciphered_len=%d" % (tls_l[i].len, tls_l[i].deciphered_len) )
                                tcp_payload_len = tls_l[i].len + TLS_HDR_LEN_IN_B
                                assembled_recs = self.start_new_pdu( tcp_payload_len, tls_l[i].original )
                                for ar in assembled_recs:
                                    returned_records.append( (ar,ReassemblyType.WHOLE_RECORD) )
                                    logging.error("THIS SHOULD NOT HAPPEN")
                                logging.info(self)
                            # plain vanilla TLS record that doesn't need reassembly
                            else:
                                returned_records.append( (tls_l[i].msg[j],ReassemblyType.WHOLE_RECORD) )
                                continue
                elif isinstance(tls_l[i],scapy.layers.tls.record._TLSEncryptedContent):
                    if self.tls_rec_len > 0:
                        logging.info("continuation of a pdu! (from TLSEncrypted)")
                        assembled_recs = self.update_pdu_assembler( tls_l[i].original )
                        for ar in assembled_recs:
                            # FIXME doesn't cover case of (partial),(end-of-partial,wholerecord)
                            returned_records.append( (ar,ReassemblyType.REASSEMBLED_RECORD) )
                            #returned_records.append( ar )
                        logging.info(self)
                    else:
                        logging.info("got tlsencryptedcontent, but not a pdu continuation?!?")
                else:
                    logging.info("not a TLS/TLSEncryptedContent and not a PDU continuation")
            except AttributeError as e:
                # subcomponent of a TLS section. keep on trucking.
                logging.info(e)
                pass
            except IndexError as e:
                break
            i = i + 1
        logging.info("=== end enumerating TLS content records\n")
        #embed()
        if len(returned_records) > 0:
            self.tls_records_list += returned_records
        return returned_records

    # this is the other public-facing interface in use here
    def get_records_list( self ):
        return self.tls_records_list

    # all these functions are utility functions and aren't mean to be public-facing
    def reset_pdu_assembler( self ):
        self.tls_rec_len = 0
        self.tls_bytestream = b''

    def start_new_pdu( self, ttlpdulen, newbytes ):
        ret = None
        self.tls_rec_len = ttlpdulen
        self.tls_bytestream = newbytes
        logging.info("start new pdu: ttl pdu length is %d" % self.tls_rec_len )
        logging.info("start new pdu: num bytes in this packet %d" % len(newbytes))
        return self.parse_tls_recs()

    def update_pdu_assembler( self, newbytes ):
        logging.info("update_pdu_assembler: num bytes in this packet %d" % len(newbytes))
        self.tls_bytestream = self.tls_bytestream + newbytes
        return self.parse_tls_recs()

    def parse_tls_recs( self ):
        '''keep parsing messages until we run out of them.'''
        returned_tls_recs = []
        while True:
            recs = self.parse_tls_rec()
            if recs:
                logging.info("found a complete tls record")
                #returned_tls_recs.append( rec )
                [returned_tls_recs.append( r ) for r in recs ]
            else: 
                break
        return returned_tls_recs

    def parse_tls_rec( self ):
        '''logic to parse pdu bytestreams into tls records.'''
        if self.tls_rec_len == 0 or len(self.tls_bytestream) < self.tls_rec_len:
            # not enough bytes yet
            return None

        # yes, enough bytes to turn into a tls record
        ret = self.build_tls_rec(self.tls_bytestream[:self.tls_rec_len])

        # do we have leftover bytes? 
        leftover_bytes = self.tls_bytestream[self.tls_rec_len:]
        if len(leftover_bytes) == 0:
            # nope. just zero out assembler fields and return with what we've got
            self.reset_pdu_assembler()
            return ret
        # update with new left over data
        if len(leftover_bytes) > 5:
            # yes.
            # FIXME check first three bytes for tls-ness
            self.tls_rec_len = int.from_bytes( leftover_bytes[3:5], byteorder='big' ) + 5
            self.tls_bytestream = leftover_bytes
        else:
            # we have leftover bytes, but not enough to read a tls header
            logging.error("dont know how to parse this!?")
        return ret

    def build_tls_rec( self, bytesin ):
        # ''build a TLS but return a list of the record layers'''
        ret = []
        tls_obj = TLS(bytesin)
        if tls_obj:
            if hasattr(tls_obj,"msg"):
                for i in range(len(tls_obj.msg)):
                    ret.append(tls_obj.msg[i])
            else:
                ret.append(tls_obj)
        return ret

    def __str__(self):
        return "num records = %d ttl_pdu_len = %d bytestream len %d first 10 bytes as hex %s" % (len(self.tls_records_list), self.tls_rec_len, len(self.tls_bytestream), binascii.hexlify(self.tls_bytestream[:10]))

####################################################################################################################################################
#
# various utility functions
#
####################################################################################################################################################

def is_layer_tls( layer ):
    if isinstance(layer,scapy.layers.tls.record.TLS) or isinstance(layer,scapy.layers.tls.record._TLSEncryptedContent) or issubclass(layer.__class__,scapy.layers.tls.record.TLS):
        return True
    if issubclass(layer.__class__,scapy.layers.tls.record._TLSHandshake):
        return True
    return False

def is_layer_tls13( layer ):
    if isinstance(layer,scapy.layers.tls.record_tls13.TLS13) or isinstance(layer,scapy.layers.tls.record_tls13.TLSInnerPlaintext):
        return True
    # FIXME need to add handshake tls13 packets too
    return False

def is_layer_tlsencryptedcontent( layer ):
    if isinstance(layer,scapy.layers.tls.record._TLSEncryptedContent):
        return True
    return False

def is_handshake_type( record ): 
    if record._name.startswith( 'TLS Handshake' ):
        return True
    return False

def create_file_name_ts( ):
    return ".%s" % (datetime.now().strftime("%Y%m%d.%H%m"))

def embed_nss_keys_in_pcap( pcap_fname, secrets_log_fname ):
    # reference: https://wiki.wireshark.org/TLS#embedding-decryption-secrets-in-a-pcapng-file
    secrets_arg = "tls,%s" % secrets_log_fname
    pcap_with_keys = "dsb-%s" % pcap_fname
    cp = subprocess.run(["editcap","--inject-secrets", secrets_arg, pcap_fname, pcap_with_keys])
    if cp.stderr != "":
        logging.error("ran %s, stdout = %s stderr = %s" % (cp.args, cp.stdout, cp.stderr))
    else:
        logging.info("ran %s, stdout = %s stderr = %s" % (cp.args, cp.stdout, cp.stderr))

def build_new_tls_packets( full_packets_and_tls_records_list ):
    '''we have a list of original packets and possibly-reassembled tls records. graft the
    tls records onto the original packets TCP layer so we can store them in a pcap.

    if this is a reassembled tls record, the IP layer's len field and the frame's len
    fields will be off. so fix up those fields.

    the sequence/ack fields are likely off too, and that will cause wireshark to complain.
    the workaround to that is to go into wireshark preferences and disable sequence 
    checking in the TCP protocol.'''

    tls_pl = PacketList()
    for (full_packet,tls_records_list) in full_packets_and_tls_records_list:
        logging.info("build a new packet below %s" % full_packet.comment)
        if len(tls_records_list) > 0:

            # graft our processed TLS records onto the Ether/IP/TCP layers
            pkt = full_packet
            pkt['TCP'].payload = tls_records_list[0]

            # if the TLS record is reassembled, then the packet's length fields
            # will be out of sync with the new payload and wireshark will tag
            # this as a malformed packet and won't display the TLS records.

            # update the IP layer's len field (includes IP header length) 
            pkt['IP'].len = (pkt['IP'].ihl * 4) + len(pkt['IP'].payload)
            # update the frame's len field
            pkt.wirelen = len(pkt)

            # FIXME: fix up seq numbers to prevent wireshark complaints
            # workaround in wireshark preferences, disable seq checking in TCP

            logging.info("appending %s" % pkt.show())
            tls_pl.append( pkt )

    return tls_pl

def write_processed_tls_packets( new_full_packets, processed_packets_file_name ):
    '''write reconstituted tls packets as a pcap'''

    logging.info("storing processed TLS packets at %s" % processed_packets_file_name)
    wrpcapng(processed_packets_file_name, new_full_packets)

def get_tls_record_names(tls_layer):
    # for a TLS layer input, return a list of the contained TLS record classes

    # this is some sort of strange psuedo array that you need to
    # detect the end of by catching an IndexError?!?
    # reference: https://stackoverflow.com/questions/61304869/how-to-read-a-packet-tls-meta-data-with-scapy-python
    i = 0
    returned_classes = []
    logging.info("enumerating TLS content records === ")
    while True:
        try:
            logging.info(" %s" % tls_layer[i].summary())
            if hasattr(tls_layer[i],"msg") and len(tls_layer[i].msg) > 0:
                # TLS| some TLS record
                returned_classes.append( tls_layer[i].msg[0].__class__ )
            else:
                # _TLSEncryptedContent
                returned_classes.append( tls_layer[i].__class__ )
        except AttributeError as e:
            # subcomponent of a TLS section. keep on trucking.
            pass
        except IndexError as e:
            break
        i = i + 1
    logging.info("=== end enumerating TLS content records\n")
    return returned_classes

####################################################################################################################################################
#
# process a TLS layer, applying the TLS session as we go
# return a list of dictionaries, with each dictionary containing the processed tls_layer and a status code
# the status code indicates the record's reassembly state
#
####################################################################################################################################################

def handle_tls_layer( tls_l, manager_args ):

        tls_session_manager = manager_args['tls_session_manager']
        direction_manager = manager_args['direction_manager']
        tls_records_extractor = manager_args['tls_records_extractor']
        logging.debug("%s" % str(tls_session_manager))
        logging.debug("%s" % str(direction_manager))
        logging.debug("%s" % str(tls_records_extractor))
        ret = []

        # get a list of the contained TLS record classes
        #tls_record_names = get_tls_record_names(tls_r)
        tls_records = tls_records_extractor.do_extract( tls_l )
        tls_record_types = [ c[0].__class__ for c in tls_records ]
        logging.debug("tls record types: %s" % tls_record_types)
        if len( tls_record_types ) == 0:
            logging.error("could not get complete records from %s" % tls_l.summary())
            return [ { 'tls_layer': tls_l, 'status': ReassemblyType.INCOMPLETE_RECORD }, ]

        # for each record found, update the tls_session
        for (rec,status) in tls_records:

            # tls 1.2 protocol reference: https://tls12.xargs.org/
            # another good non-scapy reference: https://wiki.wireshark.org/TLS

            new_tls = None
            if isinstance(rec,scapy.layers.tls.handshake.TLSClientHello):
                logging.info("==> client -> server: client hello")
                new_tls = TLS(tls_l.original)
            if isinstance(rec,scapy.layers.tls.handshake.TLSServerHello):
                logging.info("at server hello")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
                # add the captured client secret from the loaded nss file to session for decrypting rest of connection 
                new_tls.tls_session.master_secret = tls_session_manager.master_key
            if isinstance(rec,scapy.layers.tls.handshake.TLSCertificate):
                logging.info("tls certificate")
                new_tls = TLSCertificate(rec.original)
            if isinstance(rec,scapy.layers.tls.handshake.TLSServerKeyExchange):
                logging.info("tls server key exchange")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.handshake.TLSServerHelloDone):
                logging.info("==> server -> client: server hello done")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.handshake.TLSClientKeyExchange):
                logging.info("==> tls client key exchange")
                new_tls= TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.record.TLSChangeCipherSpec) and direction_manager.to_client():
                logging.info("==> server -> client: change cipher spec")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.handshake.TLSCertificateURL):
                logging.info("==> certificate url")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.handshake.TLSNewSessionTicket):
                logging.info("==> new session ticket")
                new_tls= TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.record.TLSChangeCipherSpec) and direction_manager.to_server():
                logging.info("==> client -> server: server change cipher spec")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.handshake.TLSHelloRequest):
                logging.info("==> tls hello request")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
            if isinstance(rec,scapy.layers.tls.record.TLSApplicationData) and direction_manager.to_server():
                logging.info("==> client -> server: application data")
                new_tls= TLS(tls_l.original, tls_session=tls_session_manager.get_session())
                logging.info("new_tls: %s" % new_tls.show())
            if isinstance(rec,scapy.layers.tls.record.TLSApplicationData) and direction_manager.to_client():
                logging.info("==> server -> client: application data")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
                logging.info("new_tls: %s" % new_tls.show())
            if isinstance(rec,scapy.layers.tls.record._TLSEncryptedContent):
                logging.info("encrypted content ")
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
                #embed()
            if isinstance(rec,scapy.layers.tls.record.TLSAlert):
                new_tls = TLS(tls_l.original, tls_session=tls_session_manager.get_session())
                logging.info(new_tls.show())
                logging.warning("==> tls alert received level %s desc %s" % (new_tls.msg[0].level, new_tls.msg[0].descr))

            logging.info("finished with records reparsing")

            if status == ReassemblyType.REASSEMBLED_RECORD:
                # if this record was assembled across multiple tls packets, we need to build a new TLS wrapper for the record
                tls_type = 0x17 # application data type
                if is_handshake_type(new_tls): 
                    tls_type = 0x16 # handshake type
                #wrapper_tls_len = len(new_tls) + TLS_HDR_LEN_IN_B
                wrapper_tls_len = len(new_tls) 
                wrapper_tls = TLS(type=tls_type,version=0x0303,len=wrapper_tls_len)
                wrapper_tls.msg.append( new_tls )
                new_tls = TLS(raw(wrapper_tls), tls_session=tls_session_manager.get_session())
                logging.info("created wrapper tls layer, length = %x" % wrapper_tls_len )

            if new_tls:
                tls_session_manager.update_session( new_tls.tls_session )
                ret.append( { 'tls_layer': new_tls, 'status': status } )
            else:
                #logging.error("what is this?!??? %s" % str(rec))
                logging.error("what is this?!??? ")
                embed()

        return ret

####################################################################################################################################################
#
# given a raw packetlist, pull out the TLS layers and decrypt them. returns a list of tuples, where the first item is the packet associated
# with the record(s), and the second item is a (possibly empty) list of records
#
####################################################################################################################################################

def process_tls_layers( server_host, server_port, raw_pl ):

    # scapy's tls notebook at https://github.com/secdev/scapy/blob/master/doc/notebooks/tls/notebook3_tls_compromised.ipynb
    # gives us two choices for decrypting the tls output. the first is to update the conf with the now-generated
    # nss key file, write the packetlist to a pcap file, and then read the pcap file. 
    # the second way is update the tls_session with the nss keys, and then pass the session when parsing the TLS layer to 
    # get the decrypted version. this code demonstrates the second approach.

    # initialize everything pre-parsing
    logging.info("starting to process sniffed packets\n")
    direction_manager = DirectionManager(server_host, server_port)
    tls_session_manager = TLSSessionManager()
    tls_records_extractor = TLSRecordsExtractor()
    ret = []

    # if a secrets log exists, store the master key for later decryption
    if os.path.exists(CONFIG["nss_secrets_log_file_name"]):
        nss_keys = load_nss_keys(CONFIG["nss_secrets_log_file_name"])
        if "CLIENT_RANDOM" in nss_keys and "Secret" in nss_keys["CLIENT_RANDOM"]:
            tls_session_manager.set_master_key( nss_keys["CLIENT_RANDOM"]["Secret"] )
        else:
            logging.warning("cannot find master secret in %s" % str(nss_keys) )
    else:
        logging.warning("secrets log %s not found!" % CONFIG["nss_secrets_log_file_name"])


    for pidx,pkt in enumerate(raw_pl):

        if not pkt.haslayer(TCP):
            logging.info("pkt summary %s" % pkt.summary())
            logging.debug("not a TCP packet. skipping")
            continue

        if pkt.haslayer(Padding):
            logging.info("pkt summary %s" % pkt.summary())
            logging.debug("TCP padding packet. skipping")
            continue

        logging.debug("\n\nlooking at TCP packet #%d %s ===" % (pidx,pkt.summary()))

        # find the TLS layer
        # FIXME extract multiple tls layers?
        # if not TLS layer but there is a pkt.load, try to turn that into a TLS record 
        if pkt.haslayer(TLS):
            logging.debug("found a TLS layer")
            tls_l = pkt[TLS]
        else:
            # if not TLS layer but there is a pkt.load, try to turn that into a TLS record 
            if hasattr(pkt,"load"):
                logging.info("can't find TLS layer but converted a load into a TLS record")
                tls_l = TLS(pkt.load)
                if not is_layer_tls( tls_l ):
                    logging.info("can't find TLS layer and can't convert pkt.load into a TLS record. givng up on this packet.")
                    logging.debug("=== end looking at TCP packet %d %s\n" % (pidx,pkt.summary()))
                    continue
            else:
                logging.info("can't find TLS layer and can't convert pkt.load into a TLS record. givng up on this packet.")
                logging.debug("=== end looking at TCP packet %d %s\n" % (pidx,pkt.summary()))
                continue

        # FIXME handle this: <SSLv2  len=6562 padlen=None mac=b'' msg=[<SSLv2Error  msgtype=error code=65314 |>, <Raw  load='\x12\\xc6N\x0e\\xb6@\x16\\xe5{\x1d@q\\x93 @\\x83q\\xad\\xfbJ5oåe\\xe5K\x02\x00\\x90\\xc3\\xc8-G)\x7f]\\xa8pFKq\x15g\x19\\xc5[䃠\\xddF\\xd2\\xfcx\\xf3\\x88\\x9c\\xf3\x17\\xe9\\xdf\\xc9\\xdf\\xe58\\x971\\x95\\xfa\\xea\\xd0\x14\x1b\\xce\\xd24X\\xd4\\xc4\\xf9K[\\xe8\\xaci\\xf4F\x19\\xe8\x08\\x9b\\xe3\\xff\\xd0|\\xbb\\xc2\\xd8߾\\xceI\\x99\\xc1\x1cN\\xa6\\xb4>\t\x11\\xb1\\xbd\\xa7\\xfaVK/\\xd1#\\x9dc\\xe9\x11n\x0b6\x19\\x90\\xd96\\xedF\\xae\x19\\xb8\\xd1\\xfe\\xc3u\\xf4\r\\xa2\\x9c\\xfc\\x95\x07\\xf6\\xe5\x06\x03Ӗ \\xb7up^\\xd0\\xffd\\xcb\\xe5\\x96\x1c\\xe9{\\xe5\\xc18It\x10\\x97\\x9e\\xd7\x1b\\x98\\x9fb\\xe1\\xfe\\xa0\\x9b5\x19\\x95\\xb8\x16M\\x99\\x82\\xbc:\\x90d~>\x1a\\xe9\x7fȅ*sF\x7fC\\xb6\\xf1\\x94fQ\\xbb\x08\x16\\x97\\xf8@j\\xaf e(\\x83\\x8b?={9\\xa3Z\\xf2\\xb3\t}\\xb1\\xa6}mɪJ\\x99\x1d\\xf6r\x13\\xd4@\'j\\xbc\\x98\\xf3x\\xfd\\xd9\\xe8x{Q\'\x01\\xfd\\xf1Z5\\xa5\\xe2\\xc0\\xae\x0ep\x06Gz\\x8bL0&H\\xe22\\x94\\xc3ꌻ]<VI\\x91rY\\xe4\x1b\\xecߩE;\\xa1\\xf7\x01\\xff\\x89\x19\x14\\xf24\\xf9Սlv\\xf62\u05ed\tvg\\xa8\\xf8\\xc9\x15\\xe51t1Ja\\xca\x18\x1b\x0e\\xfd8\\xff\\xd978\\xf0\x0cV\\x83\\x8d\\x90\\x90\\xb1\\xe7\x05\\x90L\x1f:\x11\\xfb\\xaa\\x9d\\xe46\\xf5z\\xf3\\xe2\\x9fy\\x8b\\x84\\xbf\\xf3\x1bb\\x9ar{\\x97\\xacL\x1a\\xc2Ʈ<wd\\xb5&,\\x9f\x1dɧh81\\x82\\x9c\\xa1\\xfdt\\x95\\xf0\x06ߓ\\xed\x1c\\xfc\\x85\\x86I\\xcfLd^?\\xc1\\xbf\\x9br-\\xa8\x7f\\xfdq\x07\x1b\x01\x1eɶ\\xa6\\xeddhv\x1b,\\xc0$\\xaa\\xf2\x0b\x17{\\x80\\xd5\\xc7\\xee\\xe9\\xd8ÎU\\xaf\\xdaox9\\xbc\\xa2\\xf3B\\xd7\\xc2\x18\\xcc&\r?\x14\x1bX\\x8d8\x15\\xcd{E\\xca\\xe4\\xf9\\xfe\\xc6D\\xfc_\\xa1<\\xda\\xfd\\x8faN\\xd4\x12\x10\\xd2\r\\xb5^\\xb8\\xfa\\xfa\\x81\\xc1\\x89)\\xfe\\xc8\\xe5\\xde\\\x15e\\xd8~\\xa8\x04\\x88n\\xb3\\x91\\xbc\\xb1?\\xe5r\\xfc\\xbfMŒ]Qÿ/q\\x9dZ\\xbb@"\\x82\\xf2\\xc0R۱\\xdfߦ\\xa2\\x97E\\xac\x03\\xd6\\xd7ڛ\\xb9\\xc8H\\xa8\\x9a\x7f\\xed\x05\\xb1\\x8fa(\\x86m\x18\\xcd-\\x9e1\\x91o\\xa9\x11\\x99\\x9f&\\xe8ri\\xcd0\\xcf@F\\xb3\\xaf\\xa5\\xedi\\xc8\x16\x03\x00\x1e\\xc1/\\xb7Q\\xb8\\xc4;1V\\xaeze\\x9d,\'M\\xed\\xcdA\\xe1\\x99\x19\\xb5\\x96\x00O&\\x86\\x80Y\\xac\\xe4\\x94\x02<pvye.T\\xc5\x1c\\xcb):n\\xa5\\xd9\\xcf\x05\x1e#\x0f\\xad\x11\x18\x17\\x8e\n\\x81\x07/\\xa4\\xf1\\xde\\\x0bg\\xaa,\\xe9\\xa2\r\\xbb\\x98O\\x91\\x933\\x84V\\xe3\\xc0\\xd0i\\xd2\\xf6\\xb4\\x9f\\xe8W\\xef*6Pti1qx\\xe9\x04\\xc6T\x04{JO^\\xf3\\xad\x170\\xb5QL\\xba|Z\\xe2\\xc6\\xf6\\xf6\x10\\xcfD5\\xb4\\x97@,A3q\\x8f\\xb5\\xe3\\xe4(f\\xdcu$\\xcd\x15\x04Q\\x86\\x8f/\\xee<i=\\xc0qʑsvx+g_\\xa0\x0e(D\\xb7\\x96\\x84^\\xb5\\x8b[^\\xd4\x0b\r\\x80I\\xe5\x14\\xf4C$!~ \\x98\\xcfa\\xf6\\xc3\\xf9sϢ\r\\xf1\\xa2\x0brMu\x18\\xb5\x17\\xbe\x19\\xccP0t\\x88<\\x88\\xa1\\xbc\\x892u\\xeeM\ne\\xac\\xa4\\xaf\\xf9\\xa9>\\xa0D\\xf8\\xce\\xdc\\xc4V߹\x08\x

        # process the TLS layer
        if direction_manager.has_changed_direction(pkt) == True:
            # if direction changed, mirror the tls session
            tls_session_manager.update_session_direction() 
        logging.info(">>> before handle: %s" % tls_l.tls_session)
        manager_args = { 'tls_session_manager': tls_session_manager, 'direction_manager': direction_manager, 'tls_records_extractor': tls_records_extractor }
        decrypted_tls_data = handle_tls_layer( tls_l, manager_args = manager_args )

        # sometimes there are multiple tls layers returned. stuff them all into the same packet
        tls_records = []
        for dtd in decrypted_tls_data:
            decrypted_tls_l = dtd['tls_layer']
            status = dtd['status']

            if status == ReassemblyType.INCOMPLETE_RECORD:
                # don't append the partial record in the tls layer - it will just confuse wireshark
                logging.debug("incomplete record: no tls layers processed")
            elif status == ReassemblyType.REASSEMBLED_RECORD:
                # bug/feature: if we have the end of an incomplete record followed by a whole
                # record, we will show only the comment for the incomplete
                pkt.comment = "input pkt #%d, tls record reassembled" % pidx
                tls_records.append( decrypted_tls_l )
                logging.debug("adding: %s" % decrypted_tls_l.show())
            elif status == ReassemblyType.WHOLE_RECORD:
                pkt.comment = "input pkt #%d, tls record processed" % pidx
                tls_records.append( decrypted_tls_l )
                logging.debug("adding: %s" % decrypted_tls_l.show())

        ret.append( [ pkt, tls_records ] )

        logging.debug("=== end looking at TCP packet %d %s\n" % (pidx,pkt.summary()))

    # return all the TLS layers and associated Ether/IP/TCP packets we found
    logging.debug("\n\n\n==> finished extracting tls records")
    return ret

####################################################################################################################################################
#
# sniff pcount packets and return them as a packetlist
#
####################################################################################################################################################

def sniff_traffic(iface,mycount,results):

    # sniff traffic until we get pcount packets
    #myprn = lambda x:x.summary()
    myprn = ""
    MYFILTER = "tcp and port %s" % server_details['port']
    sniff_out = sniff(filter=MYFILTER,prn=myprn,count=mycount,iface=iface)

    # return sniffed packets
    results['sniffed_packets'] = sniff_out
    return

####################################################################################################################################################
#
# make a https GET call and sniff the traffic as it happens on a separate thread
#
####################################################################################################################################################

def send_https_request_and_capture_traffic(server_details,mycount):
    thread_results = dict()

    # put SSLKEYLOGFILE into the environment so that I can capture SSL keys
    os.environ["SSLKEYLOGFILE"] = CONFIG["nss_secrets_log_file_name"]
    logging.info("NSS secrets log env var set to %s" % os.environ["SSLKEYLOGFILE"])

    # start another thread that sniffs the generated traffic
    t = threading.Thread(target=sniff_traffic, args=(server_details['iface'],mycount,thread_results))
    t.start()

    # wait for the sniffing thread to get going
    time.sleep(3)

    try:
        # use python requests to make a HTTPS connection to SERVER_HOST
        logging.info("opening HTTPS connection to host %s, port %d" % (server_details['host'],server_details['port'])) 

        # a ssl context based on the unverified context is needed to work with self-signed certs
        # the options are there to force a TLS 1.2 connection. this code does not support TLS 1.3
        # reference: https://docs.python.org/3/library/ssl.html#module-ssl
        mysslcontext = ssl._create_unverified_context()
        mysslcontext.options |= ssl.OP_NO_TLSv1_3
        mysslcontext.minimum_version = ssl.TLSVersion.TLSv1
        # you can set supported ciphers
        # reference: https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html
        #supported_ciphers = "ECDHE-RSA-AES128-GCM-SHA256"
        #mysslcontext.set_ciphers( supported_ciphers )
        logging.info("using sslcontext %s" % str(mysslcontext))

        conn = http.client.HTTPSConnection(server_details['host'], server_details['port'], context=mysslcontext)
        logging.info("sending command %s" % server_details['path'])
        conn.request('GET', server_details['path'])
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
    # raw_pl is a packlet list of sniffed results
    raw_pl = thread_results['sniffed_packets']
    return raw_pl

####################################################################################################################################################
#
# run the decrypting code on a PCAP and NSS secrets file
#
####################################################################################################################################################

def use_pcap_as_input( pcap_filename ):

    packet_list = rdpcapng( pcap_filename )

    for idx,pkt in enumerate(packet_list):
        logging.info("idx: %d pkt=%s" % (idx,pkt.summary()))

    return packet_list

####################################################################################################################################################
#
# main
#
####################################################################################################################################################

# load required scapy layers
load_layer("http")
load_layer("tls")

# conf commands from https://github.com/secdev/scapy/pull/3374
conf.tls_session_enable = True

# dump scapy version, configuration info
logging.debug("scapy version: %s" % scapy.__version__)
logging.debug("initial conf contents ===")
logging.debug(conf)
logging.debug("=== end initial conf contents\n")

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', required=False, type=str, help="network interface (default: eth1)" )
parser.add_argument('-p', '--path', required=False, type=str, help="server path (default: /)" )
parser.add_argument('-rp', '--replay-pcap-file', required=False, type=str, help="analyze am existing pcap file" )
parser.add_argument('-rs', '--replay-secrets-log', required=False, type=str, help="apply an existing secrets.log file to a replay pcap" )
parser.add_argument('-sh', '--server-host', required=False, type=str, help="server hostname or IP address (default: httpbin.org)" )
parser.add_argument('-sp', '--server-port', required=False, type=str, help="server port (default: 443)" )
parser.add_argument('-xe', '--dont-embed-nss-keys', required=False, help="don't embed generated nss keys in saved pcap file" )
args = parser.parse_args()

CONFIG['embed-nss-keys-in-pcap'] = True
if args.dont_embed_nss_keys:
    CONFIG['embed-nss-keys-in-pcap'] = False

# two modes: live network capture and decode, or replace an existing pcap file
if not args.replay_pcap_file:
    # do a live network capture

    # build the CONFIG dictionary
    filename_ts = create_file_name_ts()
    secrets_log_file_name = "%s_%s.log" % (NSS_SECRETS_LOG,filename_ts)
    CONFIG['nss_secrets_log_file_name'] = secrets_log_file_name
    sniff_pcap_file_name = "%s_%s.pcapng" % (RAW_SNIFF_FILENAME,filename_ts)
    CONFIG['sniff_pcap_file_name'] = sniff_pcap_file_name
    processed_pcap_file_name = "%s_%s.pcapng" % (PROCESSED_TLS_FILENAME,filename_ts)
    CONFIG['processed_pcap_file_name'] = processed_pcap_file_name

    # if specified, update with non-default server settings
    if args.interface:
        server_details['interface'] = args.interface
    if args.path:
        server_details['path'] = args.path
    if args.server_host:
        server_details['host'] = args.host
    if args.server_port:
        server_details['port'] = args.port
    if args.server_path:
        server_details['path'] = args.path

    # do the https request and sniff the network traffic
    raw_pl = send_https_request_and_capture_traffic(server_details,mycount)
    # write the raw sniff traffic to a pcap file
    wrpcapng(CONFIG["sniff_pcap_file_name"], raw_pl)
    # build the tls packet list
    full_packets_and_tls_records_list = process_tls_layers( server_details["host"], server_details["port"], raw_pl )

else:
    # replay an existing pcap file

    if not args.dest_ip or not args.dest_port:
        logging.info("to replace a pcap file you need to set the server ip and port with the 0d and -dp arguments")
        sys.exit(1)

    server_details['host'] = args.server_host
    server_details['port'] = args.server_port

    # build the CONFIG dictionary
    if args.replay_secrets_log:
        CONFIG['nss_secrets_log_file_name'] = args.replay_secrets_log
        logging.info("doing a replay using pcap file %s and secret file %s" % (args.replay_pcap_file,args.replay_secrets_log))
    else:
        logging.info("doing a replay using pcap file %s and NO secret file %s" % (args.replay_pcap_file))

    # FIXME decoding broken on replay

    filename_ts = create_file_name_ts()
    processed_pcap_file_name = "%s_%s.pcapng" % (PROCESSED_TLS_FILENAME,filename_ts)
    CONFIG['processed_pcap_file_name'] = processed_pcap_file_name

    # read the pcap file in
    raw_pl = use_pcap_as_input( args.replay_pcap_file )
    # build the tls packet list
    full_packets_and_tls_records_list = process_tls_layers( server_details['host'], server_details['port'], raw_pl )

# build a pcap file with the processed/assembled data
new_full_packets = build_new_tls_packets( full_packets_and_tls_records_list )
write_processed_tls_packets( new_full_packets, CONFIG["processed_pcap_file_name"] )
logging.info("processed tls packets written to %s" % CONFIG["processed_pcap_file_name"] )

if CONFIG['embed-nss-keys-in-pcap']:
    embed_nss_keys_in_pcap( CONFIG['processed_pcap_file_name'], CONFIG['nss_secrets_log_file_name'] )



