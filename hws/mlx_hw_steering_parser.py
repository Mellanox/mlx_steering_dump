#!/usr/bin/env python3

#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

import sys
import os
import argparse
import csv
import time

from src import dr_trigger
from src.dr_common import *
from src.dr_context import *
from src.dr_table import *
from src.dr_matcher import *
from src.dr_definer import *
from src.dr_dump_hw import *
from src.dr_rule import *
from src.dr_hw_resources import *
from src.dr_ste import *
from src.dr_db import _config_args, _stc_indexes_arr, _term_dest_db


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
    MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE: dr_parse_matcher_match_template,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE: dr_parse_matcher_action_template,
    MLX5DR_DEBUG_RES_TYPE_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_FW_STE: dr_parse_fw_ste,
    MLX5DR_DEBUG_RES_TYPE_STE: dr_parse_ste,
    MLX5DR_DEBUG_RES_TYPE_ADDRESS: dr_parse_address,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_STC: dr_parse_stc,
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
    last_fw_ste = None
    min_ste_addr = ''
    max_ste_addr = ''
    csv_reader = csv.reader(csv_file)
    for line in csv_reader:
        obj = dr_csv_get_obj(line)
        if line[0] == MLX5DR_DEBUG_RES_TYPE_STE:
            obj.load_to_db()
            ste_addr = obj.get_addr()
            if ste_addr < min_ste_addr:
                min_ste_addr = ste_addr
            if ste_addr > max_ste_addr:
                max_ste_addr = ste_addr
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_ADDRESS:
            if load_to_db:
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
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE:
            last_matcher_template = obj
            last_matcher.add_match_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE:
            last_matcher.add_action_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_DEFINER:
            last_matcher_template.add_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_STC:
            obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START:
            if not(load_to_db):
                return ctx
            _config_args["hw_resources_present"] = True
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_FW_STE:
            if last_fw_ste != None:
                last_fw_ste.add_stes_range(min_ste_addr, max_ste_addr)
            obj.init_fw_ste_db()
            max_ste_addr = '0x00000000'
            min_ste_addr = '0xffffffff'
            last_fw_ste = obj
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END:
            if last_fw_ste != None:
                last_fw_ste.add_stes_range(min_ste_addr, max_ste_addr)
        else:
            if line[0] not in unsupported_obj_list:
                unsupported_obj_list.append(line[0])

    return ctx


#General env initialization
def env_init():
    if _config_args.get("resourcedump_mem_mode"):
        tmp_file_path = ''
        file_path_arr = _config_args.get("file_path").split('/')
        for i in range(0, len(file_path_arr) - 1):
            tmp_file_path += file_path_arr[i] + '/'

        tmp_file_path += 'tmp_' + str(time.time()) + '.bin'

        _config_args["tmp_file_path"] = tmp_file_path
        _config_args["tmp_file"] = None


def env_destroy():
    tmp_file = _config_args.get("tmp_file")
    if tmp_file != None:
        tmp_file.close()


#Check and validate environment capabilities
def validate_env_caps():
    p_v = sys.version[0:1]
    dump_hw_res = _config_args.get("dump_hw_resources")
    if dump_hw_res:
        if p_v != '3':
            print('Can not Dump HW resources <-hw>, need Python3')
            exit()

        output = sp.getoutput('resourcedump -v')
        output = output.split(', ')
        if output[0] != 'resourcedump':
            print('Can not Dump HW resources, no MFT')
            exit()

        mft_version = output[1]
        if mft_version >= MEM_MODE_MIN_MFT_VERSION:
            _config_args["resourcedump_mem_mode"] = True


#Parse user command args, and save them to _config_args.
def parse_args():
    parser = argparse.ArgumentParser(description="mlx_hw_steering_parser.py - HW Steering dump tool.",
                                     epilog="Note: This parser is still under developement, so not all the args are supported yet.",
                                     add_help=False)
    parser.add_argument("-f", dest="file_path", default="", help="Input steering dump file path.")
    parser.add_argument("-v", action="count", dest="verbose", default=0, help="Increase output verbosity - v, vv, vvv & vvvv for extra verbosity.")
    parser.add_argument("-skip_hw", action="store_false", default=True, dest="dump_hw_resources",
                        help="Skip HW resources dumping.")
    parser.add_argument("-skip_parse", action="store_false", default=True, dest="hw_parse",
                        help="Skip HW dumped resources parsing.")
    parser.add_argument("-d", dest="device", type=str, default="",
                        help="Provide MST device for HW resources dumping.")
    parser.add_argument("-pid", dest="dpdk_pid", type=int, default=-1,
                        help="Trigger DPDK app <PID>.")
    parser.add_argument("-port", dest="dpdk_port", type=int, default=0,
                        help="Trigger DPDK app <PORT> newer dpdk supports -1 for all ports (must provide PID with -pid).")
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
            _config_args["device"] = None
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

    _config_args["resourcedump_mem_mode"] = False
    _config_args["hw_resources_present"] = False


if __name__ == "__main__":
    try:
        parse_args()
        validate_env_caps()
        env_init()
        file_path = _config_args.get("file_path")
        verbose = _config_args.get("verbose")

        csv_file = open(file_path, 'r+')
        load_to_db = False if _config_args.get("dump_hw_resources") else _config_args.get("load_hw_resources")
        obj = dr_parse_csv_file(csv_file, load_to_db)
        csv_file.close()

        if _config_args.get("dump_hw_resources"):
            csv_file = open(_config_args.get("file_path"), 'a+')
            dr_hw_data_engine(obj, csv_file)
            csv_file.close()
        else:
            if _config_args.get("hw_resources_present") == False:
                _config_args["parse_hw_resources"] = False
                _config_args["load_hw_resources"] = False

        print(obj.tree_print(verbose, ""))

        if verbose > 0:
            print_unsupported_obj_list()

    except OSError as e:
        print(e)
    except:
        print("")

    finally:
        env_destroy()
