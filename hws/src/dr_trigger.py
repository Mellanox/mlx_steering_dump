import socket
import sys
import os
import struct
from ctypes import *
import binascii


# struct iovec {
#    void  *iov_base;    /* Starting address */
#    size_t iov_len;     /* Number of bytes to transfer */
# };
class iovec(Structure):
    _fields_ = [('iov_base', c_char_p), ('iov_len', c_size_t)]


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

        return cmsghdr_with_data(cmsg_len, cmsg_level, cmsg_type, cmsg_data)


# define CMSG_LEN(len) (sizeof(struct cmsghdr) + (len))
def CMSG_LEN(c_len):
    return c_size_t(sizeof(cmsghdr) + c_len)


def fd_msg(flow_ptr, fd, port, prevent_py_gc):
    fd = c_int(fd)

    if (flow_ptr != 0):
        if (flow_ptr > 0xFFFFFFFF):
            print('too large flow ptr ,exit!')
            sys.exit(1)
    # Dump single/all flow(s): struct { uint32_t port_id; uint64_t flow_ptr; }
    # Native endian format can used, all exchange is within the same host
    # Unified mesaage format - previous DPDK versions did not check the message length
    # The newer ones check the flow_ptr field for the NULL
    iop = struct.pack('=LQ', port, flow_ptr)
    iob = c_char_p(bytes(iop))
    ptr_iovec = POINTER(iovec)
    iov = iovec(iob, c_size_t(len(iop)))
    prevent_py_gc['iop'] = iop
    prevent_py_gc['iob'] = iob
    prevent_py_gc['iov'] = iov

    SCM_RIGHTS = 0x01
    struct_cmsghdr = cmsghdr.create(CMSG_LEN(sizeof(fd)), socket.SOL_SOCKET, SCM_RIGHTS, fd)
    prevent_py_gc['cmsghdr'] = struct_cmsghdr

    return msghdr(None, 0, ptr_iovec(iov), 1, addressof(struct_cmsghdr), c_size_t(sizeof(struct_cmsghdr)))


def connect_to_server(server_pid):
    path = "/var/tmp/dpdk_net_mlx5_%d" % server_pid
    if (os.path.exists(path) == False):
        print("DPDK doesn't support steering dump trigger")
        sys.exit(1)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as msg:
        print("failed to connect to DPDK server: %s" % msg)
        sys.exit(1)
    return sock


def request_dump(sock, port, dump_file, flow_ptr):
    try:
        # link to c code of sendmsg
        libc = CDLL('libc.so.6')
    except:
        print("failed to link function sendmsg from libc.so.6")
        return

    c_sendmsg = libc.sendmsg
    c_sendmsg.argtypes = [c_int, POINTER(msghdr), c_int]
    c_sendmsg.restype = c_int

    # this variable used to prevent python garbage collector from disposing some resources.
    prevent_py_gc = {}

    sock_num = c_int(sock.fileno())
    msg = fd_msg(flow_ptr, dump_file.fileno(), port, prevent_py_gc)

    ret = c_sendmsg(sock_num, msg, 0)
    if ret == -1:
        print("failed to request dump")

    sock.recv(1024)


def trigger_dump(s_pid, s_port, path, s_flow_ptr):
    global port
    global server_pid
    global flow_ptr

    # DPDK support dumping all ports if uint16_max is used
    if s_port == -1:
        s_port = int(0xffff)

    port = s_port
    server_pid = s_pid
    flow_ptr = s_flow_ptr

    try:
        dump_file = open(path, 'w')
    except IOError as msg:
        print("failed to open dump file: %s" % msg)
        sys.exit(1)

    sock = connect_to_server(server_pid)
    request_dump(sock, port, dump_file, flow_ptr)
    dump_file.close()
    sock.close()
    return path

def main():
    if len(sys.argv) < 4:
        print("Example:\n\tpython dr_trigger.py <DPDK_PID> <DPDK_PORT> <dump_file>")
        sys.exit(1)

    pid = int(sys.argv[1])
    port = int(sys.argv[2])
    dump_path = sys.argv[3]
    _flow_ptr = 0
    trigger_dump(pid, port, dump_path, _flow_ptr)

    print("Done.")

if __name__ == "__main__":
    main()
