#! /usr/bin/env python3

import socket
import sys
import os
import io
import struct

def connect_to_server(server_pid):
    path = "/var/tmp/dpdk_net_mlx5_%d" % server_pid
    if(os.path.exists(path) == False):                                      
        print("DPDK doesn't support steering dump trigger", file=sys.stderr)
        sys.exit(1)                                                         

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as msg:
        print("failed to connect to DPDK server: %s" % msg, file=sys.stderr)
        sys.exit(1)
    return sock

def request_dump(sock, port, fd):
    sock.sendmsg([struct.pack('H', port)],
                 [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i',fd))])
    msg,ancdata,flags,addr = sock.recvmsg(struct.calcsize('i'))
    ret = struct.unpack('i', msg)[0]
    if ret:
        print("server error: %s" % os.strerror(ret))

def trigger_dump(s_pid, s_port, path):
    global port
    global server_pid

    port = s_port
    server_pid = s_pid

    try:
        file = io.open(path , 'w')
    except IOError as msg:
        print("failed to open dump file: %s" % msg, file=sys.stderr)
        sys.exit(1)

    sock = connect_to_server(server_pid)
    request_dump(sock, port, file.fileno())
    file.close() 
    sock.close()
    return path 
