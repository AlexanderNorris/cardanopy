#!/usr/bin/python3
'''
Common CDDL definitions

; The Codecs a r e p ol y m o r p hi c i n t h e d at a t y p e s f o r bl o c k s , p o i n t s , s l o t
; numbers e t c . .

b lo c k = [ blockHeader , blockBody ]

blockHeader = [ headerHash , chainHash , heade rSlot , headerBlockNo , headerBodyHash ]
headerHash = i n t
chainHash = genesisHash / blockHash
 genesisHash = [ ]
 blockHash = [ i n t ]
 blockBody = t s t r
 heade rSlot = word64
 headerBlockNo = word64
 headerBodyHash = i n t

 p o i n t = o r i g i n / blockHeaderHash
 o r i g i n = [ ]
 blockHeaderHash = [ slotNo , i n t ]
 slotNo = word64

 t r a n s a c t i o n = i n t
 reje ctRea son = i n t

 word16 = 0..65535
 word32 = 0..4294967295
 word64 = 0..18446744073709551615
'''
import struct
import sys
import cbor2
import time
import logging
import socket
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
network_magic = 764824073
# LAST_BYRON_BLOCK = {'slot': 4492799, 'hash': b'f8084c61b6a238acec985b59310b6ecec49c0ab8352249afd7268da5cff2a457'}
LAST_BYRON_BLOCK = [4492799, b'f8084c61b6a238acec985b59310b6ecec49c0ab8352249afd7268da5cff2a457']

class Node:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.last_response = 0

        # Create the socket
        self.socket = self.endpoint_connect(host, port)

    def __del__(self):
        # Breakdown the socket
        logging.info('Closing socket down')
        self.socket.close()

    def pack_u32(self, n):
        return struct.pack('>I', n)

    def unpack_u32(self, s):
        return struct.unpack('>I', s)[0]

    def recv_data(self, n):
        # Helper function to recv n bytes where n should be the header['length'] or 8 to parse headers
        data = self.socket.recv(n)
        return data

    def node_response(self):
        # Receive complete node response
        resp = self.recv_data(8)
        if len(resp) == 0:
            raise NodeException()
        headers = self.parse_headers(resp)
        logging.debug(headers)
        data = self.recv_data(headers['length'])
        return cbor2.loads(data)

    def endpoint_connect(self, host, port):
        logging.info('Opening a TCP connection to %s:%d' % (host, port))
        # Open a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock

    def convert_bits(self, data):
        '''
        Used to convert bytes to bits for deconstructing headers
        '''
        bits = ''
        for my_byte in data:
            bits += f'{my_byte:0>8b}'
        return bits

    def parse_headers(self, resp):
        '''
        Parse protocol headers to retrieve 
        - Timestamp: Bytes 0 to 3
        - Mode & Mini Protocol Version: Bytes 4 and 5, first bit (Mode) & 15 bit remainder (Version) 
        - Length: Bytes 6 and 7
        '''
        headers = dict()
        # Obtain Mode and Mini Protocol Version
        mode_mini_protcol = self.convert_bits(resp[4 : 6])
        # Build headers dictionary
        logging.info(len(resp))
        headers['length'] = int(resp[6 :].hex(), 16)
        headers['timestamp'] = str(self.unpack_u32(resp[:4]))[:4] + '.' + str(self.unpack_u32(resp[:4]))[4:]
        headers['mode'] = mode_mini_protcol[0]
        headers['mini_protocol'] = int(mode_mini_protcol[1:], 2)
        return headers

    def add_headers(self, obj):
        '''
        Applies standard Node headers to an object
        '''
        # Create the object for verison proposal
        start_time = int(time.monotonic() * 1000)
        self.last_response = start_time
        # Object as CBOR
        cbor_obj = cbor2.dumps(obj)
        # Time in milliseconds
        cbor_time = struct.pack('>I', start_time)
        # Length of payload
        length = struct.pack('>I', len(cbor_obj))
        msg = cbor_time + length + cbor_obj
        logging.debug('Timestamp: ' + str(start_time) + ' ' + cbor2.dumps(cbor_obj).hex())
        logging.debug('Length: ' + str(len(cbor_obj)) + ' ' + length.hex())
        logging.debug('Version Options: ' + str(obj) + ' ' + cbor2.dumps(cbor_obj).hex())
        logging.debug('Constructed Payload: ' + msg.hex())
        return msg

    def handshake(self):
        '''
        Handshake with the Cardano Node
        '''
        # You can propose all of the versions
        obj = [0, {1 : network_magic, 2: network_magic, 3: network_magic, 4: [network_magic, False], 5: [network_magic, False], 6: [network_magic, False], 7: [network_magic, False], 8: [network_magic, False]}]
        msg = self.add_headers(obj)
        # STATE: PROPOSE
        logging.info('>>> Version Proposal: ' + str(obj))
        self.socket.send(msg)
        data = self.node_response()
        logging.info('<<< Version: ' + str(data))
        return

    def find_intersect(self):
        '''
        Find intersection in blockchain
        '''
        # Create the object for verison proposal
        start_time = int(time.monotonic() * 1000)
        # finds the intersection from the end of Byron
        obj = [4, LAST_BYRON_BLOCK] # First ever intersect
        msg = self.add_headers(obj)
        # STATE: msgFindIntersect
        logging.info('>>> Intersection Request: ' + str(msg))
        self.socket.send(msg)
        data = self.node_response()
        logging.info('<<< Intersection: ' + str(data))
        return

class NodeException(Exception):
    def __init__(self):
        self.message = 'No response was received from the node'
        super().__init__(self.message)
    
    def __str__(self):
        return self.message
