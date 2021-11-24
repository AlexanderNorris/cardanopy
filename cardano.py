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
import bitstring

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
network_magic = 764824073
LAST_BYRON_BLOCKS = [[4492799, bytes.fromhex('F8084C61B6A238ACEC985B59310B6ECEC49C0AB8352249AFD7268DA5CFF2A457')], [1598399, bytes.fromhex('7e16781b40ebf8b6da18f7b5e8ade855d6738095ef2f1c58c77e88b6e45997a4')], [359, bytes.fromhex('9c0fe75b6a0499e9576a09589a5777e7021824e8a6d037065829423f861a9bb6')]]

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

    def mode_bit_manipulation(self, protocol_id: int, mode: int):
        protocol_two_byte_bits = self.convert_bits(protocol_id.to_bytes(2, 'big'))
        protocol_bitarray = bitstring.BitArray(bin=protocol_two_byte_bits)
        protocol_binary = protocol_bitarray.bin[1:]
        mode_binary = bitstring.BitArray(bin=str(mode)).bin
        mode_mini_protocol_binary = bitstring.BitArray(bin=mode_binary + protocol_binary)
        return mode_mini_protocol_binary.tobytes()

    def add_headers(self, obj, protocol_id: int, mode: int = 0):
        '''
        Create the object for verison proposal
        Time: Monotonic time that increments constantly
        Mode: 1 or 0, the first bit of the 2 protocol ID bytes
        Protocol ID: last 15 bits of the protocol ID bytes
        Length: last two bytes of header representing the length of the payload
        '''
        # # Object as CBOR
        cbor_obj = cbor2.dumps(obj)
        header = dict()
        # # Time in milliseconds
        header['time'] = struct.pack('>I', int(time.monotonic() * 1000))
        header['mode'] = mode # unused but available for reference
        header['protocol_id'] = str(self.convert_bits(protocol_id.to_bytes(2, 'big')))[:15] # unusued but available for reference
        # # Mode Mini protocol
        header['mode_mini_protocol_id'] = self.mode_bit_manipulation(protocol_id, mode)
        # # Length of payload
        header['length'] = len(cbor_obj).to_bytes(2, 'big')
        logging.debug(header)
        logging.debug('Request Time Binary: ' + self.convert_bits(header['time']))
        logging.debug('Request Mode Binary: ' + self.convert_bits(header['mode_mini_protocol_id']))
        logging.debug('Length: ' + self.convert_bits(header['length']))
        msg = header['time'] + header['mode_mini_protocol_id'] + header['length'] + cbor_obj
        return msg

    def handshake(self):
        '''
        Handshake with the Cardano Node
        '''
        # You can propose all of the versions
        obj = [0, {1 : network_magic, 2: network_magic, 3: network_magic, 4: [network_magic, False], 5: [network_magic, False], 6: [network_magic, False], 7: [network_magic, False], 8: [network_magic, False]}]
        protocol_id = 0
        msg = self.add_headers(obj, protocol_id)
        # STATE: PROPOSE
        logging.info('>>> Version Proposal: ' + str(obj))
        logging.debug('>>> Version Proposal: ' + str(msg))
        self.socket.send(msg)
        data = self.node_response()
        logging.info('<<< Version: ' + str(data))
        return

    def find_intersect(self):
        '''
        Find intersection in blockchain
        Start from the final blocks within Byron
        '''
        # Create the object for verison proposal
        start_time = int(time.monotonic() * 1000)
        # finds the intersection from the end of Byron
        obj = [4, LAST_BYRON_BLOCKS] # First ever intersect
        protocol_id = 2
        msg = self.add_headers(obj, protocol_id)
        # STATE: msgFindIntersect
        logging.info('>>> Intersection Request: ' + str(obj))
        logging.debug('>>> Intersection Request: ' + str(msg))
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
