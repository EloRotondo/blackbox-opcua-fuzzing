import struct
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
        #authToken_id = struct.unpack('i', recv[62:66])
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
        


# def hello_definition():
#     s_initialize('Hello')

#     with s_block('h-header'):
#         s_bytes(b'HEL', name='Hello magic', fuzzable=False)
#         s_bytes(b'F', name='Chunk type', fuzzable=False)
#         s_size('h-body', offset=8, name='body size', fuzzable=False)

#     with s_block('h-body'):
#         s_dword(0, name='Protocol version')
#         s_dword(65536, name='Receive buffer size')
#         s_dword(65536, name='Send buffer size')
#         s_dword(0, name='Max message size')
#         s_dword(0, name='Max chunk count')
#         endpoint = ENDPOINT_STRING
#         s_dword(len(endpoint), name='Url length')
#         s_bytes(endpoint, name='Endpoint url')

def hello_definition():
    s_initialize('Hello')

    with s_block('h-header'):
        s_bytes(b'HEL', name='Hello magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('h-body', offset=8, name='body size', fuzzable=False)

    with s_block('h-body'):
        s_dword(0, name='Protocol version', fuzzable=False)
        s_dword(65536, name='Receive buffer size', fuzzable=False)
        s_dword(65536, name='Send buffer size', fuzzable=False)
        s_dword(0, name='Max message size', fuzzable=False)
        s_dword(0, name='Max chunk count', fuzzable=False)
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='Url length', fuzzable=False)
        s_bytes(endpoint, name='Endpoint url', fuzzable=False)        


# def open_channel_definition():
#     '''
#     Note: Message will be chunked. So chunk header included....
#     '''
#     s_initialize('OpenChannel')

#     with s_block('o-header'):
#         s_bytes(b'OPN', name='Open channel magic', fuzzable=False)
#         s_bytes(b'F', name='Chunk type', fuzzable=False)
#         s_size('o-body', offset=8, name='body size', fuzzable=False)

#     with s_block('o-body'):
#         s_dword(0, name='channel id')

#         # chunking encryption
#         policy_uri = 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')
#         s_dword(len(policy_uri), name='uri length')
#         s_bytes(policy_uri, name='security policy uri')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint')

#         # chunking sequence
#         s_dword(1, name='sequence number')
#         s_dword(1, name='request id')

#         # type id: OpenSecureChannel
#         s_bytes(b'\x01\x00\xbe\x01', name='Type id')

#         # request header
#         s_bytes(b'\x00\x00', name='authentication token')
#         s_qword(get_weird_opc_timestamp(), name='timestamp')
#         s_dword(1, name='request handle')
#         s_dword(0, name='return diagnostics')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
#         s_dword(1000, name='timeout hint')
#         s_bytes(b'\x00\x00\x00', name='additional header')

#         # open channel parameter
#         s_dword(0, name='client protocol version')
#         s_dword(0, name='request type')
#         s_dword(1, name='security mode')
#         s_bytes(b'\x00\x00\x00\x00', name='client nonce')
#         s_dword(3600000, name='requested lifetime')

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
        s_dword(0, name='channel id')

        # chunking encryption
        policy_uri = 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')
        s_dword(len(policy_uri), name='uri length', fuzzable=False)
        s_bytes(policy_uri, name='security policy uri', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint', fuzzable=False)

        # chunking sequence
        s_dword(1, name='sequence number', fuzzable=False)
        s_dword(1, name='request id', fuzzable=False)

        # type id: OpenSecureChannel
        s_bytes(b'\x01\x00\xbe\x01', name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # open channel parameter
        s_dword(0, name='client protocol version', fuzzable=False)
        s_dword(0, name='request type', fuzzable=False)
        s_dword(1, name='security mode', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='client nonce', fuzzable=False)
        s_dword(3600000, name='requested lifetime', fuzzable=False)


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


# def activate_session_definition():
#     s_initialize('ActivateSession')

#     with s_block('a-header'):
#         s_bytes(b'MSG', name='Activate session magic', fuzzable=False)
#         s_bytes(b'F', name='Chunk type', fuzzable=False)
#         s_size('a-body', offset=8, name='body size', fuzzable=False)

#     with s_block('a-body'):
#         s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
#         s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
#         s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
#         s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

#         # type id: OpenSecureChannel
#         s_bytes(b'\x01\x00' + struct.pack('<H', 467), name='Type id', fuzzable=False)

#         # request header
#         s_dword(4, name='encoding mask guid')
#         s_bytes(b'\x01\x00', name='namespace idx')
#         s_bytes(b'\xcc\x8c\x09\xf9\x7b\x93\xd1\xb3\x10\xc1\x2c\x62\x3c\x43\x04\xb0', name='identifier guid')
#         s_qword(get_weird_opc_timestamp(), name='timestamp')
#         s_dword(1, name='request handle')
#         s_dword(0, name='return diagnostics')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
#         s_dword(600000, name='timeout hint')
#         s_bytes(b'\x00\x00\x00', name='additional header')

#         # client signature
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='client algorithm')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='client signature')

#         s_bytes(b'\xFF\xFF\xFF\xFF', name='locale id')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='client software certificates')

#         # user identity token
#         s_bytes(b'\x01\x00' + struct.pack('<H', 324), name='user type id', fuzzable=False)
#         s_bytes(b'\x01', name='binary body')

#         policy_id = 'open62541-username-policy'.encode('utf-8')
#         username = 'user1'.encode('utf-8')
#         password = 'password'.encode('utf-8')

#         s_dword(len(policy_id) + len(username) + len(password) + 4 + 4 + 4 + 4,
#                 name='length user id token')  # 3 length fields + algorithm

#         s_dword(len(policy_id), name='id length')
#         s_bytes(policy_id, name='policy id', fuzzable=False)
#         s_dword(len(username), name='username length')
#         s_bytes(username, name='username')
#         s_dword(len(password), name='password length')
#         s_bytes(password, name='password')

#         s_bytes(b'\xFF\xFF\xFF\xFF', name='encryption algorithm')

#         # user token signature
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='user sign algorithm')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='user signature')

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
        s_bytes(b'\x02', name='encoding mask guid', fuzzable=False)
        #s_dword(2, name='encoding mask guid', fuzzable=False)
        s_bytes(b'\x00\x00', name='namespace idx', fuzzable=False)
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        #s_bytes(b'\xcc\x8c\x09\xf9\x7b\x93\xd1\xb3\x10\xc1\x2c\x62\x3c\x43\x04\xb0', name='identifier guid', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp', fuzzable=False)
        s_dword(2, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # client signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client algorithm', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client signature', fuzzable=False)

        s_bytes(b'\x00\x00\x00\x00', name='locale id', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='client software certificates', fuzzable=False)

        # user identity token
        # s_bytes(b'\x01\x00' + struct.pack('<H', 324), name='user type id', fuzzable=False)
        # s_bytes(b'\x01', name='binary body', fuzzable=False)

        # policy_id = 'open62541-username-policy'.encode('utf-8')
        # username = 'user1'.encode('utf-8')
        # password = 'password'.encode('utf-8')

        # s_dword(len(policy_id) + len(username) + len(password) + 4 + 4 + 4 + 4,
        #         name='length user id token', fuzzable=False)  # 3 length fields + algorithm

        # s_dword(len(policy_id), name='id length', fuzzable=False)
        # s_bytes(policy_id, name='policy id', fuzzable=False)
        # s_dword(len(username), name='username length', fuzzable=False)
        # s_bytes(username, name='username', fuzzable=False)
        # s_dword(len(password), name='password length', fuzzable=False)
        # s_bytes(password, name='password', fuzzable=False)

        # s_bytes(b'\xFF\xFF\xFF\xFF', name='encryption algorithm', fuzzable=False)

        # UserIdentityToken
        s_bytes(b'\x01\x00' + struct.pack('<H', 321), name='user type id', fuzzable=False)
        s_bytes(b'\x01', name='binary body', fuzzable=False)

        policy_id = 'anonymous'.encode('utf-8')
        s_dword(len(policy_id) + 4 + 4 + 4 + 4, name='length user id token', fuzzable=False)
        s_dword(len(policy_id), name='id length', fuzzable=False)
        s_bytes(policy_id, name='policy id', fuzzable=False)


        # user token signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user sign algorithm', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user signature', fuzzable=False)


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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # request parameter
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='url length', fuzzable=False)
        s_bytes(endpoint, name='endpoint url', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='locale ids', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='profile ids', fuzzable=False)


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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # request parameter
        s_dword(0, name='starting record id', fuzzable=False)
        s_dword(0, name='max records to return', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='server capability filter', fuzzable=False)


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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        server_uri = 'urn:opcua.server'.encode('utf-8')
        s_dword(len(server_uri), name='server length', fuzzable=False)
        s_bytes(server_uri, name='server uri', fuzzable=False)

        product_uri = 'http://my.opcua-implementation.code'.encode('utf-8')
        s_dword(len(product_uri), name='product length', fuzzable=False)
        s_bytes(product_uri, name='product uri', fuzzable=False)

        # ('ServerNames', 'ListOfLocalizedText'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerNames', fuzzable=False)

        s_dword(0, name='server type', fuzzable=False)

        # ('GatewayServerUri', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri', fuzzable=False)

        s_dword(1, name='Number of discovery uris', fuzzable=False)
        discovery_uri = ENDPOINT_STRING
        s_dword(len(discovery_uri), name='discovery length', fuzzable=False)
        s_bytes(discovery_uri, name='discovery url', fuzzable=False)

        # ('SemaphoreFilePath', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SemaphoreFilePath', fuzzable=False)

        s_byte(1, name='is online', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='discovery configuration', fuzzable=False)


# def create_session_definition():
#     s_initialize('CreateSession')

#     with s_block('cs-header'):
#         s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
#         s_bytes(b'F', name='Chunk type', fuzzable=False)
#         s_size('cs-body', offset=8, name='body size', fuzzable=False)

#     with s_block('cs-body'):
#         # security
#         s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
#         s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
#         s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
#         s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

#         s_bytes(b'\x01\x00' + struct.pack('<H', 461), name='Type id', fuzzable=False)

#         # request header
#         s_bytes(b'\x00\x00', name='authentication token')
#         s_qword(get_weird_opc_timestamp(), name='timestamp')
#         s_dword(1, name='request handle')
#         s_dword(0, name='return diagnostics')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
#         s_dword(1000, name='timeout hint')
#         s_bytes(b'\x00\x00\x00', name='additional header')

#         # application description
#         application = 'urn:unconfigured:application'.encode('utf-8')
#         s_dword(len(application), name='UriLength')
#         s_bytes(application, name='ApplicationUri')

#         s_bytes(b'\xFF\xFF\xFF\xFF', name='ProductUri')
#         s_byte(0, name='ApplicationName')
#         s_dword(1, name='ApplicationType')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryUrls')

#         # create session parameter
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri')
#         endpoint = ENDPOINT_STRING
#         s_dword(len(endpoint), name='UrlLength')
#         s_bytes(endpoint, name='EndpointUrl')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='SessionName')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientNonce')
#         s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate')
#         s_bytes(struct.pack('d', 1200000.0), name='RequestedSessionTimeout')
#         s_dword(2147483647, name='MaxResponseMessageSize')

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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # application description
        application = 'urn:unconfigured:application'.encode('utf-8')
        s_dword(len(application), name='UriLength', fuzzable=False)
        s_bytes(application, name='ApplicationUri', fuzzable=False)

        s_bytes(b'\xFF\xFF\xFF\xFF', name='ProductUri', fuzzable=False)
        s_byte(0, name='ApplicationName', fuzzable=False)
        s_dword(1, name='ApplicationType', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryUrls', fuzzable=False)

        # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri', fuzzable=False)
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='UrlLength', fuzzable=False)
        s_bytes(endpoint, name='EndpointUrl', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SessionName', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientNonce', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate', fuzzable=False)
        s_bytes(struct.pack('d', 1200000.0), name='RequestedSessionTimeout', fuzzable=False)
        s_dword(2147483647, name='MaxResponseMessageSize', fuzzable=False)


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
        s_dword(5000, name='timeout hint',fuzzable=False)
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
        s_bytes(b'\x02', name='encoding mask', fuzzable=False)
        s_bytes(b'\x00\x00', name='namespace index', fuzzable=False)
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        #request parameter
        s_bytes(b'\x00', name='view encodingmask', fuzzable=False)
        s_bytes(b'\x00', name='view id', fuzzable=False)
        s_qword(0, name='view timestamp', fuzzable=False)
        s_dword(0, name='view version', fuzzable=False)
        s_dword(10, name='requested max references per node', fuzzable=False)
        s_dword(1, name='array size (nodes to browse)', fuzzable=False)

        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)', fuzzable=False)
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)', fuzzable=False)
            s_bytes(b'\x00', name='namespace id', fuzzable=False)
            
        s_bytes(struct.pack('<H', node_id), name='node id', fuzzable=False)
        s_dword(2, name='browse direction', fuzzable=False)
        s_bytes(b'\x00\x00', name='referenceTypeId', fuzzable=False)
        s_bytes(b'\x00', name='include subtypes', fuzzable=False)
        s_bytes(b'\xFF\x00\x00\x00', name='node class mask', fuzzable=False)
        s_bytes(b'\x3F\x00\x00\x00', name='result mask', fuzzable=False)

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
        s_bytes(b'\x02', name='encoding mask', fuzzable=False)
        s_bytes(b'\x00\x00', name='namespace index', fuzzable=False)
        s_dword(0,name='authentication token id',fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(4, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        #request parameter
        s_bytes(b'\x00', name='releaseContinuationPoints (false)', fuzzable=False)
        s_dword(1, name='array size (continuaionPoints)', fuzzable=False)
        s_dword(8, name='mystery bytes', fuzzable=False)
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
        s_bytes(b'\x02', name='encoding mask', fuzzable=False)
        s_bytes(b'\x00\x00', name='namespace index', fuzzable=False)
        s_dword(0, name='authentification token id', fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # request parameter
        s_qword(0, name='max age', fuzzable=False)
        s_dword(3, name='timestampsToReturn', fuzzable=False)
        s_dword(1, name='Number of nodes to read', fuzzable=False)
        s_bytes(b'\x00', name='node id encoding mask', fuzzable=False)
        
        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)', fuzzable=False)
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)', fuzzable=False)
            s_bytes(b'\x00', name='namespace id', fuzzable=False)

        s_dword(attribute, name='AttributeId', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='IndexRange', fuzzable=False)
        s_bytes(b'\x00\x00', name='data encoding id', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='data encoding name', fuzzable=False)

def write_node_definition(node_id: int, buildInId: int, value: any):
    s_initialize('Write')

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

        s_bytes(b'\x01\x00' + struct.pack('<H', 673), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x02', name='authentification token encoding mask', fuzzable=False)
        s_bytes(b'\x00\x00', name='authentification token namespace index', fuzzable=False)
        s_dword(0, name='authentification token id', fuzzable=False)  # will be overwritten
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(3, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(5000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        # request parameter
        s_qword(1, name='array size')
        s_bytes(b'\x01\x01', name='node id encodingmask + namspace index', fuzzable=False)
       
        if(0 < node_id < 255):
            s_bytes(b'\x00', name='nodes to browse encodingmask (2 bytes)', fuzzable=False)
        else:
            s_bytes(b'\x01', name='nodes to browse encodingmask (4 bytes)', fuzzable=False)
            s_bytes(b'\x00', name='namespace id', fuzzable=False)

        s_dword(bytes([buildInId]), name='buildInType id', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='IndexRange', fuzzable=False)
        s_bytes(b'\x05', name='value encodingmask', fuzzable=False)
        s_bytes(bytes([buildInId]), name='variant type', fuzzable=False)
        s_qword(bytes([value]), name='value to write', fuzzable=False)
        s_qword(get_weird_opc_timestamp(), name='source timestamp', fuzzable=False)

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
    write_node_definition(node_id=84,buildInId=11,value=42)

    discovery_service_definition(service_name='FindServers', request_type=422)
    discovery_service_definition(service_name='GetEndpoints', request_type=428)
    find_servers_on_network_definition()
    register_server_2_definition()

    session.connect(s_get('Hello'))
    session.connect(s_get('Hello'), s_get('OpenChannel'))
    # session.connect(s_get('OpenChannel'), s_get('CloseChannel'), callback=set_channel_parameter_from_open)
    # session.connect(s_get('OpenChannel'), s_get('FindServers'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('GetEndpoints'), callback=set_channel_parameter_from_open)
    #session.connect(s_get('OpenChannel'), s_get('FindServersOnNetwork'), callback=set_channel_parameter_from_open)
    #session.connect(s_get('OpenChannel'), s_get('RegisterServer2'), callback=set_channel_parameter_from_open)

    #Change SOPC_MAX_SESSIONS_PER_SECURE_CONNECTION in sopc_toolkit_config_constants.h
    # session.connect(s_get('OpenChannel'), s_get('CreateSession'), callback=set_channel_parameter_from_open)
    # session.connect(s_get('CreateSession'), s_get('ActivateSession'), callback=set_channel_parameter_from_create)
    #session.connect(s_get('ActivateSession'), s_get('CloseSession'), callback=set_channel_parameter_from_activate)
    
    #session.connect(s_get('ActivateSession'), s_get('Browse'), callback=set_channel_parameter_from_activate)
    #session.connect(s_get('Browse'), s_get('BrowseNext'), callback=set_channel_parameter_from_browse)
    #session.connect(s_get('BrowseNext'), s_get('CloseSession'), callback=set_channel_parameter_from_activate)

    #session.connect(s_get('ActivateSession'), s_get('Read'), callback=set_channel_parameter_from_activate)
    #session.connect(s_get('ActivateSession'), s_get('Write'), callback=set_channel_parameter_from_activate)


    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass

    boofuzz_log = convert_boofuzz_sqlite_to_dict(session._run_id)
    crashes = merge_boofuzz_data(boofuzz_log, session._run_id)
    store_crash_information(session._run_id, crashes)

    return session._run_id
