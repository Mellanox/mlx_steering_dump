# Copyright (c) 2020 Mellanox Technologies, Inc.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import io
import os
import socket
import struct
import sys


def connect_to_server(server_pid):
    path = "/var/tmp/dpdk_net_mlx5_%d" % server_pid
    if os.path.exists(path) is False:
        print("DPDK doesn't support steering dump trigger", file=sys.stderr)
        return None

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as msg:
        print("failed to connect to DPDK server: %s" % msg, file=sys.stderr)
        return None
    return sock


def request_dump(sock, port, fd):
    sock.sendmsg([struct.pack('H', port)],
                 [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', fd))])
    msg, ancdata, flags, addr = sock.recvmsg(struct.calcsize('i'))
    ret = struct.unpack('i', msg)[0]
    if ret:
        print("server error: %s" % os.strerror(ret))


def trigger_dump(s_pid, s_port, path):
    global port
    global server_pid

    port = s_port
    server_pid = s_pid

    try:
        file = io.open(path, 'w')
    except IOError as msg:
        print("failed to open dump file: %s" % msg, file=sys.stderr)
        return None

    sock = connect_to_server(server_pid)
    if sock is None:
        file.close()
        return None

    request_dump(sock, port, file.fileno())

    file.close()
    sock.close()
    return path
