#!/usr/bin/env python3

import sys
import os
import argparse
import subprocess as sp

_projects = {
    "4123" : "negev",
    "4125" : "arava",
    "4127" : "tamar",
    "4129" : "carmel",
    "41686" : "viper",
}

def parse_args():
    parser = argparse.ArgumentParser(description="rd.py", add_help=False)
    parser.add_argument("-d", dest="device", default="", help="Device, /dev/mst/<DEVICE>", required=True)
    parser.add_argument("-v", dest="vhca_id", default="", help="The virtual HCA (host channel adapter, NIC) ID", required=False)
    parser.add_argument("-s", dest="segment", default="", help="The segment to dump", required=False)
    parser.add_argument("-i1", dest="i_1", default="", help="The first context index to dump (if supported for this segment)", required=False)
    parser.add_argument("-i2", dest="i_2", default="", help="The second context index to dump (if supported for this segment)", required=False)
    parser.add_argument("-n1", dest="n_1", default="", help="The number of objects to be dumped (if supported for this segment). accepts: [\"all\", \"active\", number, depends on the capabilities]", required=False)
    parser.add_argument("-n2", dest="n_2", default="", help="The number of objects to be dumped (if supported for this segment). accepts: [\"all\", \"active\", number, depends on the capabilities]", required=False)
    parser.add_argument("-de", dest="depth", default="", help="The depth of walking through reference segments. 0 stands for flat, 1 allows crawling of a single layer down the struct, etc. \"inf\" for all", required=False)
    parser.add_argument("-b", dest="bin_file", default="", help="The output to a binary file that replaces the default print in hexadecimal, a readable format", required=False)
    parser.add_argument("-m", dest="mem", default="", help="Perform the dump through memory (ofed with rdma-core dependency). optionally accepts: [rdma device (for example \"mlx5_4\")]", required=False)
    parser.add_argument("--query", action="store_true", default=False, dest="query", help="Query device resourcedump segments.")
    parser.add_argument("--parse", action="store_true", default=False, dest="parse", help="parse resourcedump output.")
    parser.add_argument("-a", dest="adabe", default="", help="Adabe file if not passed will try to get it automatically", required=False)
    parser.add_argument("--verbose", action="count", dest="verbose", default=0, help="Increase output verbosity - v")
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help='Show this help message and exit.')

    return parser.parse_args()

def get_adb(args):
    cmd = 'mlxfwmanager -d %s' % args.device

    if args.verbose > 0:
        print(cmd)

    status, output = sp.getstatusoutput(cmd)
    if status != 0:
        print(output)
        exit(1)

    arr = output.split()
    sz = len(arr)
    fw = ''
    for i in range(0, sz):
        if (arr[i] == 'FW') and ((i + 1) < sz):
            fw = arr[i + 1]
            break

    if fw == '':
        print("Error cannot find FW version")
        print(output)
        exit(1)

    fw = fw.split('.')

    if ((len(fw) > 2) and (int(fw[2][-1], 10) % 2 == 1)):
        fw[2] = '%s%s' % (fw[2][:-1], str(int(fw[2][-1], 10) - 1))

    mst_dev = args.device.split('/')[3].split('_')[0]
    mst_dev = mst_dev[2:]
    if _projects.get(mst_dev) == None:
        print("Please provide an adabe file")
        exit(1)

    adb_params = (mst_dev, mst_dev, fw[0], fw[1], fw[2], _projects.get(mst_dev))
    adb = '/.autodirect/mswg/release/BUILDS/fw-%s/fw-%s-rel-%s_%s_%s/../etc/%s_segments.adb' % adb_params
    return adb


def rd_query(args):
    return 'resourcedump query -d %s' % args.device

def rd_dump(args, adb):
    cmd = 'resourcedump dump -d %s' % args.device

    if args.vhca_id != '':
        cmd += ' --virtual-hca-id %s' % args.vhca_id

    if args.segment != '':
        cmd += ' --segment %s' % args.segment

    if args.i_1 != '':
        cmd += ' --index1 %s' % args.i_1

    if args.i_2 != '':
        cmd += ' --index2 %s' % args.i_2

    if args.n_1 != '':
        cmd += ' --num-of-obj1 %s' % args.n_1

    if args.n_2 != '':
        cmd += ' --num-of-obj2 %s' % args.n_2

    if args.depth != '':
        cmd += ' --depth %s' % args.depth

    if args.bin_file != '':
        cmd += ' --bin %s' % args.bin_file

    if args.mem != '':
        cmd += ' --mem %s' % args.mem

    if adb != '':
        cmd += ' --parse adb -a %s' % adb

    return cmd

if __name__ == "__main__":
    args = parse_args()
    cmd = ''
    if args.query:
        cmd = rd_query(args)
    else:
        adb = ''
        if args.parse:
            adb = get_adb(args)

        cmd = rd_dump(args, adb)

    if args.verbose > 0:
        print(cmd)

    status, output = sp.getstatusoutput(cmd)
    print(output)
