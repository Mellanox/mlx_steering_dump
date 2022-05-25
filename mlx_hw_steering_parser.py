#!/usr/bin/env python3

#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

import sys
import os
import argparse
import csv

from hw_steering_src import dr_trigger
from hw_steering_src.dr_common import *
from hw_steering_src.dr_context import *
from hw_steering_src.dr_table import *
from hw_steering_src.dr_matcher import *
from hw_steering_src.dr_definer import *
from hw_steering_src.dr_dump_hw import *
from hw_steering_src.dr_rule import *
from hw_steering_src.dr_hw_resources import *
from hw_steering_src.dr_ste import *
from hw_steering_src.dr_db import _config_args


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
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE: dr_parse_matcher_template,
    MLX5DR_DEBUG_RES_TYPE_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_FW_STE: dr_parse_fw_ste,
    MLX5DR_DEBUG_RES_TYPE_STE: dr_parse_ste,
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

def dr_parse_csv_file(csv_file, load_to_db):
    ctx = None
    last_table = None
    last_matcher = None
    last_send_engine = None
    last_matcher_template = None
    csv_reader = csv.reader(csv_file)
    for line in csv_reader:
        obj = dr_csv_get_obj(line)
        if line[0] == MLX5DR_DEBUG_RES_TYPE_STE:
            obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT:
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
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE:
            last_matcher_template = obj
            last_matcher.add_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_DEFINER:
            last_matcher_template.add_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START:
            if not(load_to_db):
                return ctx
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_FW_STE:
            if load_to_db:
                obj.init_fw_ste_db()
        else:
            if line[0] not in unsupported_obj_list:
                unsupported_obj_list.append(line[0])

    return ctx


#Check environment capabilities
def env_caps():
    p_v = sys.version[0:1]
    dump_hw_res = _config_args.get("dump_hw_resources")
    if p_v != '3' and dump_hw_res:
        print('Can not Dump HW resources, need Python3')
        exit()


#Parse user command args, and save them to _config_args.
def parse_args():
    parser = argparse.ArgumentParser(description="mlx_hw_steering_parser.py - HW Steering dump tool.",
                                     epilog="Note: This parser is still under developement, so not all the args are supported yet.",
                                     add_help=False)
    parser.add_argument("-f", dest="file_path", default="", help="Input steering dump file path.")
    parser.add_argument("-v", action="count", dest="verbose", default=0, help="Increase output verbosity - v, vv, vvv & vvvv for extra verbosity.")
    parser.add_argument("-hw", action="store_true", default=False, dest="dump_hw_resources",
                        help="Dump HW resources (must specify a device with -d).")
    parser.add_argument("-d", dest="device", type=str, default="",
                        help="Provide MST device.")
    parser.add_argument("-pid", dest="dpdk_pid", type=int, default=-1,
                        help="Trigger DPDK app <PID>.")
    parser.add_argument("-port", dest="dpdk_port", type=int, default=0,
                        help="Trigger DPDK app <PORT> (must provide PID with -pid).")
    parser.add_argument("-hw_parse", action="store_true", default=False, dest="hw_parse",
                        help="Parse HW dumped resources.")
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    args = parser.parse_args()

    if (args.file_path == ""):
        print("No input steering dump file provided (-f FILEPATH)")
        sys.exit(0)
    else:
        _config_args["file_path"] = args.file_path

    if (args.dump_hw_resources):
        _config_args["dump_hw_resources"] = True
        if (args.device == ""):
            print("must specify a device with -d when using -hw flag")
            sys.exit(0)
        else:
            _config_args["device"] = args.device
    else:
        _config_args["dump_hw_resources"] = False

    if (args.hw_parse):
        _config_args["parse_hw_resources"] = True
        _config_args["load_hw_resources"] = True
    else:
        _config_args["parse_hw_resources"] = False
        _config_args["load_hw_resources"] = False

    if (args.dpdk_pid > 0):
        if dr_trigger.trigger_dump(args.dpdk_pid, args.dpdk_port, args.file_path, 0) is None:
            sys.exit(-1)
        _config_args["dpdk_pid"] = args.dpdk_pid

    if (os.stat(args.file_path).st_size == 0):
        print("Empty input file, no data to parse")
        sys.exit(0)

    if args.verbose > 4:
        _config_args["verbose"] = 4
    else:
        _config_args["verbose"] = args.verbose


if __name__ == "__main__":
    parse_args()
    env_caps()
    file_path = _config_args.get("file_path")
    verbose = _config_args.get("verbose")

    csv_file = open(file_path, 'r+')
    obj = dr_parse_csv_file(csv_file, _config_args.get("load_hw_resources"))
    csv_file.close()

    if dump_hw_resources:
        csv_file = open(_config_args.get("file_path"), 'a+')
        dr_hw_data_engine(obj, csv_file)
        csv_file.close()

    print(obj.tree_print(verbose, ""))

    if verbose > 0:
        print_unsupported_obj_list()
