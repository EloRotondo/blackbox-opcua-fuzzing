import struct
import sys
from calendar import timegm
from datetime import datetime
from pathlib import Path

from boofuzz import (
    s_initialize, s_bytes, s_dword, Session, s_get, s_block, Target, s_size, s_qword, exception, ProcessMonitor,
    TCPSocketConnection, s_byte
)

from parse.crash import merge_boofuzz_data, store_crash_information, convert_boofuzz_sqlite_to_dict
from parse.packet import ENDPOINT_STRING

# Weird OPC time stuff
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


def setup_session(ip: str, port: int, target_path: str) -> Session:
    '''
    The current number of mutations for each definition is
    - Hello 2261
    - OpenChannel 5287
    - CloseChannel 844
    - FindServers 2624
    - GetEndpoints 2624
    - FindServersOnNetwork 1264
    - RegisterServer2 6845
    - CreateSession 5984
    - ActivateSession 4032
    Total mutations: 31765

    You can narrow the fuzzing by using these values to set index_start and index_end in the Session definition.
    '''
    if target_path:
        procmon = ProcessMonitor('127.0.0.1', 26002)
        procmon.set_options(start_commands=[target_path.split(), ], capture_output=True)

        target = Target(
            connection=TCPSocketConnection(ip, port),
            monitors=[procmon, ]
        )
    else:
        target = Target(
            connection=TCPSocketConnection(ip, port),
        )

    return Session(
        target=target,
        sleep_time=0,
        index_start=0,
        index_end=None,
        receive_data_after_fuzz=True,
        keep_web_open=False,
        web_port=None
    )


def get_weird_opc_timestamp():
    now = datetime.now()
    ft = EPOCH_AS_FILETIME + (timegm(now.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (now.microsecond * 10)


def set_channel_parameter_from_open(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, policy_len = struct.unpack('ii', recv[8:16])
        sequence_offset = 24 + policy_len
        seq_num, req_id = struct.unpack('ii', recv[sequence_offset:sequence_offset + 8])

        request_header_length = 8 + 4 + 4 + 1 + 4 + 3
        token_offset = sequence_offset + 8 + 4 + request_header_length + 4
        sec_channel_id, token_id = struct.unpack('ii', recv[token_offset:token_offset + 8])
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')
    else:
        node.stack[1].stack[0]._default_value = sec_channel_id
        node.stack[1].stack[1]._default_value = token_id
        node.stack[1].stack[2]._default_value = seq_num + 1
        node.stack[1].stack[3]._default_value = req_id + 1


def set_channel_parameter_from_create(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, token_id, seq_num, req_id = struct.unpack('iiii', recv[8:24])
        global authToken_id 
        authToken_id = recv[62:66]

        
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')

    else:
        node.stack[1].stack[0]._default_value = channel_id
        node.stack[1].stack[1]._default_value = token_id
        node.stack[1].stack[2]._default_value = seq_num + 1
        node.stack[1].stack[3]._default_value = req_id + 1
        node.stack[1].stack[7]._default_value = authToken_id

def set_channel_parameter_from_activate(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, token_id, seq_num, req_id = struct.unpack('iiii', recv[8:24])
        
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')

    else:
        node.stack[1].stack[0]._default_value = channel_id
        node.stack[1].stack[1]._default_value = token_id
        node.stack[1].stack[2]._default_value = seq_num + 1
        node.stack[1].stack[3]._default_value = req_id + 1
        node.stack[1].stack[7]._default_value = authToken_id


def set_channel_parameter_from_browse(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, token_id, seq_num, req_id = struct.unpack('iiii', recv[8:24])
        continuationP_id = recv[64:72]
        
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')

    else:
        node.stack[1].stack[0]._default_value = channel_id
        node.stack[1].stack[1]._default_value = token_id
        node.stack[1].stack[2]._default_value = seq_num + 1
        node.stack[1].stack[3]._default_value = req_id + 1
        node.stack[1].stack[7]._default_value = authToken_id
        node.stack[1].stack[17]._default_value = continuationP_id
        


def hello_definition():
    s_initialize('Hello')

    with s_block('h-header'):
        s_bytes(b'HEL', name='Hello magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('h-body', offset=8, name='body size', fuzzable=False)

    with s_block('h-body'):
        s_dword(0, name='Protocol version')
        s_dword(65536, name='Receive buffer size')
        s_dword(65536, name='Send buffer size')
        s_dword(0, name='Max message size')
        s_dword(0, name='Max chunk count')
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='Url length')
        s_bytes(endpoint, name='Endpoint url')

def open_channel_definition():
    '''
    Note: Message will be chunked. So chunk header included....
    '''
    s_initialize('OpenChannel')

    with s_block('o-header'):
        s_bytes(b'OPN', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('o-body', offset=8, name='body size', fuzzable=False)

    with s_block('o-body'):
        s_dword(0, name='channel id', fuzzable=False)

        # chunking encryption
        policy_uri = 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')
        s_dword(len(policy_uri), name='uri length')
        s_bytes(policy_uri, name='security policy uri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint')

        # chunking sequence
        s_dword(1, name='sequence number')
        s_dword(1, name='request id')

        # type id: OpenSecureChannel
        s_bytes(b'\x01\x00\xbe\x01', name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # open channel parameter
        s_dword(0, name='client protocol version')
        s_dword(0, name='request type')
        s_dword(1, name='security mode')
        s_bytes(b'\x00\x00\x00\x00', name='client nonce')
        s_dword(3600000, name='requested lifetime')


def close_channel_definition():
    s_initialize('CloseChannel')

    with s_block('c-header'):
        s_bytes(b'CLO', name='Close channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('c-body', offset=8, name='body size', fuzzable=False)

    with s_block('c-body'):
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 452), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(10000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')


def activate_session_definition():
    s_initialize('ActivateSession')

    with s_block('a-header'):
        s_bytes(b'MSG', name='Activate session magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('a-body', offset=8, name='body size', fuzzable=False)

    with s_block('a-body'):
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        # type id: OpenSecureChannel
        s_bytes(b'\x01\x00' + struct.pack('<H', 467), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='encoding mask guid')
        s_bytes(b'\x00\x00', name='namespace idx')
        s_dword(0,name='authentication token id')  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(2, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # client signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client algorithm')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client signature')

        s_bytes(b'\x00\x00\x00\x00', name='locale id')
        s_bytes(b'\x00\x00\x00\x00', name='client software certificates')

        # UserIdentityToken
        s_bytes(b'\x01\x00' + struct.pack('<H', 321), name='user type id', fuzzable=False)
        s_bytes(b'\x01', name='binary body')

        policy_id = 'anonymous'.encode('utf-8')
        s_dword(len(policy_id) + 4 + 4 + 4 + 4, name='length user id token')
        s_dword(len(policy_id), name='id length')
        s_bytes(policy_id, name='policy id')


        # user token signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user sign algorithm')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user signature')


def discovery_service_definition(service_name: str, request_type: int):
    s_initialize(service_name)

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', request_type), name='Type id', fuzzable=False)

        # # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='url length')
        s_bytes(endpoint, name='endpoint url')
        s_bytes(b'\x00\x00\x00\x00', name='locale ids')
        s_bytes(b'\x00\x00\x00\x00', name='profile ids')


def find_servers_on_network_definition():
    s_initialize('FindServersOnNetwork')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 12208), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        s_dword(0, name='starting record id')
        s_dword(0, name='max records to return')
        s_bytes(b'\x00\x00\x00\x00', name='server capability filter')


def register_server_2_definition():
    s_initialize('RegisterServer2')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 12211), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        server_uri = 'urn:opcua.server'.encode('utf-8')
        s_dword(len(server_uri), name='server length')
        s_bytes(server_uri, name='server uri')

        product_uri = 'http://my.opcua-implementation.code'.encode('utf-8')
        s_dword(len(product_uri), name='product length')
        s_bytes(product_uri, name='product uri')

        # ('ServerNames', 'ListOfLocalizedText'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerNames')

        s_dword(0, name='server type')

        # ('GatewayServerUri', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')

        s_dword(1, name='Number of discovery uris')
        discovery_uri = ENDPOINT_STRING
        s_dword(len(discovery_uri), name='discovery length')
        s_bytes(discovery_uri, name='discovery url')

        # ('SemaphoreFilePath', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SemaphoreFilePath')

        s_byte(1, name='is online')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='discovery configuration')


def create_session_definition():
    s_initialize('CreateSession')

    with s_block('cs-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('cs-body', offset=8, name='body size', fuzzable=False)

    with s_block('cs-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 461), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # application description
        application = 'urn:unconfigured:application'.encode('utf-8')
        s_dword(len(application), name='UriLength')
        s_bytes(application, name='ApplicationUri')

        s_bytes(b'\xFF\xFF\xFF\xFF', name='ProductUri')
        s_byte(0, name='ApplicationName')
        s_dword(1, name='ApplicationType')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryUrls')

        # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri')
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='UrlLength')
        s_bytes(endpoint, name='EndpointUrl')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SessionName')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientNonce')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate')
        s_bytes(struct.pack('d', 1200000.0), name='RequestedSessionTimeout')
        s_dword(2147483647, name='MaxResponseMessageSize')


def close_session_definition():
    s_initialize('CloseSession')

    with s_block('c-header'):
        s_bytes(b'MSG', name='Close session message', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('c-body', offset=8, name='body size', fuzzable=False)

    with s_block('c-body'):
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

      
        s_bytes(b'\x01\x00' + struct.pack('<H', 473), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='encoding mask')
        s_bytes(b'\x00\x00', name='namespace index',)
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(4, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
        s_bytes(b'\x00', name='delete subscription (false)')

def browse_node_definition(node_id: int):
    s_initialize('Browse')

    with s_block('g-header'):
        s_bytes(b'MSG', name='browse magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 527), name='Type id', fuzzable=False)

        # request header
        #authentification token
        s_bytes(b'\x02', name='encoding mask')
        s_bytes(b'\x00\x00', name='namespace index')
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle')
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        #request parameter
        s_bytes(b'\x00', name='view encodingmask')
        s_bytes(b'\x00', name='view id')
        s_qword(0, name='view timestamp')
        s_dword(0, name='view version')
        s_dword(10, name='requested max references per node')
        s_dword(1, name='array size (nodes to browse)')

        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)')
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)')
            s_bytes(b'\x00', name='namespace id')
            
        s_bytes(struct.pack('<H', node_id), name='node id')
        s_dword(2, name='browse direction')
        s_bytes(b'\x00\x00', name='referenceTypeId')
        s_bytes(b'\x00', name='include subtypes')
        s_bytes(b'\xFF\x00\x00\x00', name='node class mask')
        s_bytes(b'\x3F\x00\x00\x00', name='result mask')

def browse_next_definition():
    s_initialize('BrowseNext')

    with s_block('g-header'):
        s_bytes(b'MSG', name='browse magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 533), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='encoding mask')
        s_bytes(b'\x00\x00', name='namespace index')
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(4, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        #request parameter
        s_bytes(b'\x00', name='releaseContinuationPoints (false)')
        s_dword(1, name='array size (continuaionPoints)')
        s_dword(8, name='mystery bytes')
        s_qword(0,name='continuationPoints',fuzzable=False)  # will be overwritten


def read_node_definition(node_id: int, attribute: int):
    s_initialize('Read')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 631), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='encoding mask')
        s_bytes(b'\x00\x00', name='namespace index')
        s_dword(0, name='authentification token id', fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        s_qword(0, name='max age')
        s_dword(3, name='timestampsToReturn')
        s_dword(1, name='Number of nodes to read')
        s_bytes(b'\x00', name='node id encoding mask')
        
        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)')
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)')
            s_bytes(b'\x00', name='namespace id')

        s_bytes(struct.pack('<H', node_id), name='node id')
        s_dword(attribute, name='AttributeId')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='IndexRange')
        s_bytes(b'\x00\x00', name='data encoding id')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='data encoding name')

def write_node_definition(node_id: int, buildInId: int, value: any):
    s_initialize('Write')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic')
        s_bytes(b'F', name='Chunk type')
        s_size('g-body', offset=8, name='body size')

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 673), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='authentification token encoding mask')
        s_bytes(b'\x00\x00', name='authentification token namespace index')
        s_dword(0, name='authentification token id', fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(5000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        s_dword(1, name='array size')
       
        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)')
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)')
            s_bytes(b'\x00', name='namespace id')

        s_bytes(struct.pack('<H', node_id), name='node id')
        s_bytes(b'\x0d\x00\x00\x00', name='attribute id')
        s_bytes(b'\xff\xff\xff\xff', name='IndexRange')
        s_bytes(b'\x05', name='value encodingmask')
        s_bytes(struct.pack('<H', buildInId), name='variant type')

        if buildInId == 1:
                s_bytes(struct.pack('<?', value), name='value to write (boolean)')
        elif buildInId ==  2 or buildInId == 3:
                s_bytes(value, name='value to write (sbyte and byte)')
        elif buildInId == 4:
                s_bytes(struct.pack('<h', value), name='value to write(Int16) ')
        elif buildInId == 5:
                s_bytes(struct.pack('<H', value), name='value to write (UInt16)')
        elif buildInId == 6:
                s_bytes(struct.pack('<i', value), name='value to write (Int32)')
        elif buildInId == 7:
                s_bytes(struct.pack('<I', value), name='value to write (UInt32)')
        elif buildInId == 8:
                s_bytes(struct.pack('<q', value), name='value to write (Int64)')
        elif buildInId == 9:
                s_bytes(struct.pack('<Q', value), name='value to write (UInt64)')
        elif buildInId == 10:
                s_dword(struct.pack('<f', value), name='value to write (float)')
        elif buildInId == 11:
                s_qword(struct.pack('<d', value), name='value to write (double)')
        elif buildInId == 12:
               s_bytes(value.encode('utf-8'), name='value to write (string)')

        s_qword(get_weird_opc_timestamp(), name='source timestamp')

def fuzz_opcua(file_path: Path) -> str:
    session = setup_session('127.0.0.1', 4840, str(file_path.absolute()))

    hello_definition()
    open_channel_definition()
    close_channel_definition()
    create_session_definition()
    activate_session_definition()
    close_session_definition()

    browse_node_definition(node_id=2041)
    browse_next_definition()
    read_node_definition(node_id=84,attribute=1)
    write_node_definition(node_id=1003,buildInId=11,value=42)

    discovery_service_definition(service_name='FindServers', request_type=422)
    discovery_service_definition(service_name='GetEndpoints', request_type=428)
    find_servers_on_network_definition()
    register_server_2_definition()

    session.connect(s_get('Hello'))
    session.connect(s_get('Hello'), s_get('OpenChannel'))
    session.connect(s_get('OpenChannel'), s_get('CloseChannel'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('FindServers'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('GetEndpoints'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('FindServersOnNetwork'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('RegisterServer2'), callback=set_channel_parameter_from_open)

    session.connect(s_get('OpenChannel'), s_get('CreateSession'), callback=set_channel_parameter_from_open)
    session.connect(s_get('CreateSession'), s_get('ActivateSession'), callback=set_channel_parameter_from_create)
    session.connect(s_get('ActivateSession'), s_get('CloseSession'), callback=set_channel_parameter_from_activate)
    session.connect(s_get('ActivateSession'), s_get('Browse'), callback=set_channel_parameter_from_activate)
    session.connect(s_get('Browse'), s_get('BrowseNext'), callback=set_channel_parameter_from_browse)
    session.connect(s_get('ActivateSession'), s_get('Read'), callback=set_channel_parameter_from_activate)
    #session.connect(s_get('ActivateSession'), s_get('Write'), callback=set_channel_parameter_from_activate)

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass

    boofuzz_log = convert_boofuzz_sqlite_to_dict(session._run_id)
    crashes = merge_boofuzz_data(boofuzz_log, session._run_id)
    store_crash_information(session._run_id, crashes)

    return session._run_id
