#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

import sys
import argparse
import csv

from hw_steering_src import dr_trigger
from hw_steering_src.dr_common import *
from hw_steering_src.dr_context import *
from hw_steering_src.dr_table import *
from hw_steering_src.dr_matcher import *
from hw_steering_src.dr_definer import *


# mapping csv records types to it's relevant parser function
switch_csv_res_type = {
    MLX5DR_DEBUG_RES_TYPE_CONTEXT: dr_parse_context,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR: dr_parse_context_attr,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS: dr_parse_context_caps,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE: dr_parse_context_send_engine,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING: dr_parse_context_send_ring,
    MLX5DR_DEBUG_RES_TYPE_TABLE: dr_parse_table,
    MLX5DR_DEBUG_RES_TYPE_MATCHER: dr_parse_matcher,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR: dr_parse_matcher_attr,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX: dr_parse_matcher_nic,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX: dr_parse_matcher_nic,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE: dr_parse_matcher_template,
    MLX5DR_DEBUG_RES_TYPE_DEFINER: dr_parse_definer,
}

unsupported_obj_list = []

def print_unsupported_obj_list():
    if len(unsupported_obj_list) == 0:
        return None
    _str = "Unsupported objects detected:"
    for o in unsupported_obj_list:
        _str = _str + " " + str(o) + ","

    print(_str[:-1])


def dr_csv_get_obj(line):
    res_type = line[0]
    if res_type not in switch_csv_res_type.keys():
        return None

    parser = switch_csv_res_type[line[0]]
    return parser(line)

def dr_parse_csv_file(csv_file):
    global DEFINERS
    ctx = None
    last_table = None
    last_matcher = None
    last_send_engine = None
    last_matcher_template = None
    csv_reader = csv.reader(csv_file)
    for line in csv_reader:
        obj = dr_csv_get_obj(line)
        if line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT:
            ctx = obj
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR:
            ctx.add_attr(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS:
            ctx.add_caps(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE:
            last_send_engine = obj
            ctx.add_send_engine(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING:
            last_send_engine.add_send_ring(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_TABLE:
            last_table = obj
            ctx.add_table(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER:
            last_matcher = obj
            last_table.add_matcher(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR:
            last_matcher.add_attr(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX:
            last_matcher.add_nic_rx(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX:
            last_matcher.add_nic_tx(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE:
            last_matcher_template = obj
            last_matcher.add_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_DEFINER:
            last_matcher_template.add_definer(obj)
            DEFINERS[obj.get_definer_obj_id()] = obj
        else:
            if line[0] not in unsupported_obj_list:
                unsupported_obj_list.append(line[0])

    return ctx

def parse_args():
    parser = argparse.ArgumentParser(description="hw_steering_parser.py - HW Steering dump tool",
                                     epilog="Note: This parser is still under developement, so not all the args are supported yet.")
    parser.add_argument("-f", dest="FILEPATH", default="", help="Input steering dump file path")
    parser.add_argument("-v", action="count", dest="verbose", default=0, help="Increase output verbosity - v, vv & vvv for extra verbosity")
    parser.add_argument("-hw", action="store_true", default=False, dest="dump_hw_resources",
                        help="Dump HW resources (must provide device with -d)")
    parser.add_argument("-d", dest="device", type=str, default="",
                        help="Provide device")
    parser.add_argument("-pid", dest="dpdk_pid", type=int, default=-1,
                        help="Trigger DPDK app <PORT> (must provide PID with -p)")
    parser.add_argument("-port", dest="dpdk_port", type=int, default=0,
                        help="Trigger DPDK app <PORT> (must provide PID with -p)")
    parser.add_argument("-no-parse", action="store_true", default=False, dest="no_parse",
                        help="Skip parsing stage")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if (args.FILEPATH == ""):
        print("No input steering dump file provided (-f FILEPATH)\n")
        sys.exit(0)
    if (args.dump_hw_resources):
        print("-hw is not supported yet.")
        sys.exit(0)
    if (args.dpdk_pid > 0):
        if dr_trigger.trigger_dump(args.dpdk_pid, args.dpdk_port, args.FILEPATH, 0) is None:
            sys.exit(-1)

    csv_file = open(args.FILEPATH)
    obj = dr_parse_csv_file(csv_file)
    verbose = args.verbose
    if verbose > 3:
        verbose = 3
    print(obj.tree_print(verbose, ""))

    if verbose > 0:
        print_unsupported_obj_list()
