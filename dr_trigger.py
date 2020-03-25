import socket
import sys
import os
import struct
from ctypes import *

# struct iovec {
#    void  *iov_base;    /* Starting address */
#    size_t iov_len;     /* Number of bytes to transfer */
# };
class iovec(Structure):
    _fields_ = [('iov_base', c_void_p), ('iov_len', c_size_t)]

# struct msghdr {
# 	void		*msg_name;	/* ptr to socket address structure */
# 	int		msg_namelen;	/* size of socket address structure */
# 	struct iov_iter	msg_iter;	/* data */
# 	void		*msg_control;	/* ancillary data */
# 	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
# 	unsigned int	msg_flags;	/* flags on received message */
# 	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
# };
class msghdr(Structure):
    _fields_ = [('msg_name', c_void_p), ('msg_namelen', c_uint), ('msg_iov', POINTER(iovec)), ('msg_iovlen', c_size_t),
                ('msg_control', c_void_p), ('msg_controllen', c_size_t), ('msg_flags', c_int)]

# struct cmsghdr {
#    size_t cmsg_len;    /* Data byte count, including header
# 						  (type is socklen_t in POSIX) */
#    int    cmsg_level;  /* Originating protocol */
#    int    cmsg_type;   /* Protocol-specific type */
# /* followed by
#   unsigned char cmsg_data[]; */
# };
class cmsghdr(Structure):
    _fields_ = [('cmsg_len', c_size_t), ('cmsg_level', c_int), ('cmsg_type', c_int)]

    @classmethod
    def create(cls, cmsg_len, cmsg_level, cmsg_type, cmsg_data):
        CHAR_ARRAY = c_ubyte * sizeof(cmsg_data)
        cmsg_data = CHAR_ARRAY(*bytearray(cmsg_data))

        class cmsghdr_with_data(Structure):
            _fields_ = cls._fields_ + [('cmsg_data', CHAR_ARRAY)]

        return cmsghdr_with_data(cmsg_len, cmsg_level, cmsg_type,cmsg_data)

#define CMSG_LEN(len) (sizeof(struct cmsghdr) + (len))
def CMSG_LEN(c_len):
    return c_size_t(sizeof(cmsghdr) + c_len)


def fd_msg(fd, port, prevent_py_gc):
    fd = c_int(fd)
    port = bytearray(chr(port), 'utf-8') + bytearray('\0', 'utf-8')

    # create c bytes buffer of size iov_len that contains the port as string
    iov_len = c_int * 20
    iov_base = iov_len(*port)

    ptr_iovec = POINTER(iovec)
    iov = iovec(addressof(iov_base),c_size_t(sizeof(iov_base)))
    prevent_py_gc['iov'] = iov
    prevent_py_gc['iov_base'] = iov_base

    SCM_RIGHTS = 0x01
    struct_cmsghdr = cmsghdr.create(CMSG_LEN(sizeof(fd)), socket.SOL_SOCKET, SCM_RIGHTS, fd)
    prevent_py_gc['cmsghdr'] = struct_cmsghdr

    return msghdr(None, 0, ptr_iovec(iov), 1, addressof(struct_cmsghdr), c_size_t(sizeof(struct_cmsghdr)))

def connect_to_server(server_pid):
    path = "/var/tmp/dpdk_net_mlx5_%d" % server_pid
    if(os.path.exists(path) == False):                                      
        print("DPDK doesn't support steering dump trigger")
        sys.exit(1)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as msg:
        print("failed to connect to DPDK server: %s" % msg)
        sys.exit(1)
    return sock

def request_dump(sock, port, dump_file):
    try:
        #link to c code of sendmsg
        libc = CDLL('libc.so.6')
    except:
        print("failed to link function sendmsg from libc.so.6")
        return

    c_sendmsg = libc.sendmsg
    c_sendmsg.argtypes = [c_int, POINTER(msghdr), c_int]
    c_sendmsg.restype = c_int

    #this variable used to prevent python garbage collector from disposing some resources.
    prevent_py_gc = {}

    sock_num = c_int(sock.fileno())
    msg = fd_msg(dump_file.fileno(), port, prevent_py_gc)

    ret = c_sendmsg(sock_num, msg, 0)
    if ret == -1:
        print("failed to request dump")

    sock.recv(1024)

def trigger_dump(s_pid, s_port, path):
    global port
    global server_pid

    port = s_port
    server_pid = s_pid

    try:
        dump_file = open(path , 'w')
    except IOError as msg:
        print("failed to open dump file: %s" % msg)
        sys.exit(1)

    sock = connect_to_server(server_pid)
    request_dump(sock, port, dump_file)
    dump_file.close() 
    sock.close()
    return path 
