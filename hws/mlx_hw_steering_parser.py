#!/usr/bin/env python3

#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from io import TextIOWrapper
import json
from pathlib import Path
import sys
import os
import argparse
import csv
import time

MINIMUM_PYTHON_VERSION = (3, 9)

def check_python_version_supported():
    if sys.version_info < MINIMUM_PYTHON_VERSION:
        file_name = Path(__file__).name
        printable_version = '.'.join(map(str, MINIMUM_PYTHON_VERSION))
        print(f"Error: {file_name} requires Python {printable_version} or newer")
        sys.exit(1)

# Need to execute this before parsing the rest of the file
check_python_version_supported()

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
from src.dr_db import _config_args, _db
from src.dr_remote import dr_connect_to_remote

MAX_SUPPORTED_VERSION = Version("1.0.any_generator")

# mapping csv records types to it's relevant parser function
SWITCH_CSV_RES_TYPE = {
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
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_MATCH_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_RANGE_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_HASH_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_COMPARE_MATCH_DEFINER: dr_parse_definer,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_RESIZABLE_ARRAY: dr_parse_matcher_resizable_array,
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_RTC_ARRAY: dr_parse_matcher_resizable_array,
    MLX5DR_DEBUG_RES_TYPE_FW_STE: dr_parse_fw_ste,
    MLX5DR_DEBUG_RES_TYPE_FW_STE_STATS: dr_parse_fw_ste_stats,
    MLX5DR_DEBUG_RES_TYPE_STE: dr_parse_ste,
    MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START: lambda x: x,    # no-op
    MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END: lambda x: x,      # no-op
    MLX5DR_DEBUG_RES_TYPE_ADDRESS: dr_parse_address,
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_STC: dr_parse_stc,
    MLX5DR_DEBUG_RES_TYPE_PATTERN: dr_parse_pattern,
    MLX5DR_DEBUG_RES_TYPE_ARGUMENT: dr_parse_argument,
    MLX5DR_DEBUG_RES_TYPE_COUNTER: dr_parse_res_counter,
    MLX5DR_DEBUG_RES_TYPE_ACTION_STE_TABLE: dr_parse_action_ste_table,
    MLX5DR_DEBUG_RES_TYPE_FT_ANCHORS: dr_parse_ft_anchor,
}

def print_unsupported_obj_list(unsupported_obj_list: list):
    if unsupported_obj_list:
        print(f"Unsupported objects detected: {', '.join(unsupported_obj_list)}")


def dr_csv_get_obj(line):
    res_type = line[0]
    if res_type not in SWITCH_CSV_RES_TYPE.keys():
        return None

    parser = SWITCH_CSV_RES_TYPE[res_type]
    return parser(line)


def pretty_obj_repr(obj, indent: int = 0) -> str:
    """
    Return a string representation of an object with indentation, but without
    the structural markers, '{', '[', and so on, of JSON. Almost like YAML but
    with only the indentation.

    To keep the existing compact representation, only dict values are indented.
    Trailing whitespace is stripped to avoid doubling newlines. Leading
    whitespace is preserved to preserve the behaviour of a bug in
    dr_parse_matcher_match_template. Interior newlines get indented to preserve
    formatting. A final trailing newline is always added.

    >>> print(pretty_obj_repr({"a": 1, "b": "multiline\\nvalue"}))
    a
        1
    b
        multiline
        value
    <BLANKLINE>

    >>> print(pretty_obj_repr([1, "2", [3, "4\\n\\t ", "5 ", " 6"]]))
    1
    2
    3
    4
    5
     6
    <BLANKLINE>

    >>> print(pretty_obj_repr(
    ...     ["top-level-value", {"key": ["list", "of", "values"]}, {"key": "another-value"}]
    ... ))
    top-level-value
    key
        list
        of
        values
    key
        another-value
    <BLANKLINE>
    """
    indentation = TAB * indent
    def literal(val):
        return indentation + str(val).rstrip().replace("\n", "\n" + indentation) + "\n"

    if isinstance(obj, dict):
        s = "".join([literal(k) + pretty_obj_repr(v, indent + 1) for k, v in obj.items()])
        return s
    elif isinstance(obj, list):
        s = "".join([pretty_obj_repr(v, indent) for v in obj])
        return s
    else:
        return literal(obj)


def dr_parse_csv_file(csv_file: TextIOWrapper, load_to_db: bool) -> tuple[list, list]:
    ctxs = []
    ctx = None
    last_table = None
    last_matcher = None
    last_send_engine = None
    last_matcher_template = None
    last_fw_ste = None
    min_ste_addr = ''
    max_ste_addr = ''
    unsupported_obj_list = []
    print("Loading input file ...")
    csv_reader = csv.reader(csv_file)
    for i, line in enumerate(csv_reader):
        obj = dr_csv_get_obj(line)
        if obj is None:
            print(f"Skipping unknown object on line {i} of {csv_file.name}")
            continue
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
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_ARGUMENT:
            if load_to_db:
                obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_COUNTER:
            if load_to_db:
                obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_PATTERN:
            if load_to_db:
                obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT:
            ctx = obj
            version = ctx.dump_version
            if version > MAX_SUPPORTED_VERSION:
                raise Exception(f"Version {version} is newer than what the tool "
                                f"supports ({MAX_SUPPORTED_VERSION}). Please fetch "
                                "the latest version of the dump tool from GitHub.")
            ctxs.append(ctx)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR:
            if ctx is None:
                print("Cannot add attribute without context")
                continue
            ctx.add_attr(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS:
            if ctx is None:
                print("Cannot add caps without context")
                continue
            ctx.add_caps(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE:
            last_send_engine = obj
            if ctx is None:
                print("Cannot add send engine without context")
                continue
            ctx.add_send_engine(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING:
            if last_send_engine is None:
                print("Cannot add send ring without send engine")
                continue
            last_send_engine.add_send_ring(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_TABLE:
            last_table = obj
            if ctx is None:
                print("Cannot add table without context")
                continue
            ctx.add_table(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER:
            last_matcher = obj
            if last_table is None:
                print("Cannot add matcher without table")
                continue
            last_table.add_matcher(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR:
            if last_matcher is None:
                print("Cannot add matcher attribute without matcher")
                continue
            last_matcher.add_attr(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE:
            last_matcher_template = obj
            if last_matcher is None:
                print("Cannot add matcher template without matcher")
                continue
            last_matcher.add_match_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE:
            if last_matcher is None:
                print("Cannot add matcher action template without matcher")
                continue
            last_matcher.add_action_template(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_MATCH_DEFINER:
            if last_matcher_template is None:
                print("Cannot add matcher template match definer without matcher template")
                continue
            last_matcher_template.add_match_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_RANGE_DEFINER:
            if last_matcher_template is None:
                print("Cannot add matcher template range definer without matcher template")
                continue
            last_matcher_template.add_range_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_HASH_DEFINER:
            if last_matcher_template is None:
                print("Cannot add matcher template hash definer without matcher template")
                continue
            last_matcher_template.add_hash_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_COMPARE_MATCH_DEFINER:
            if last_matcher_template is None:
                print("Cannot add matcher template compare match definer without matcher template")
                continue
            last_matcher_template.add_compare_definer(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_RESIZABLE_ARRAY:
            if last_matcher is None:
                print("Cannot add matcher resizable array without matcher")
                continue
            last_matcher.add_resizable_array(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_RTC_ARRAY:
            last_matcher.add_resizable_array(obj)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_CONTEXT_STC:
            obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START:
            if not load_to_db:
                return ctxs, unsupported_obj_list
            _config_args["hw_resources_present"] = True
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_FT_ANCHORS:
            obj.load_to_db()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_FW_STE:
            if last_fw_ste is not None:
                last_fw_ste.add_stes_range(min_ste_addr, max_ste_addr)
            obj.init_fw_ste_db()
            max_ste_addr = '0x00000000'
            min_ste_addr = '0xffffffff'
            last_fw_ste = obj
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_FW_STE_STATS:
            min_ste_addr = obj.get_min_addr()
            max_ste_addr = obj.get_max_addr()
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END:
            if last_fw_ste is not None:
                last_fw_ste.add_stes_range(min_ste_addr, max_ste_addr)
        elif line[0] == MLX5DR_DEBUG_RES_TYPE_ACTION_STE_TABLE:
            print("Action STE table is not supported yet")
        else:
            if line[0] not in unsupported_obj_list:
                unsupported_obj_list.append(line[0])

    return ctxs, unsupported_obj_list


#General env initialization
def env_init():
    if _config_args.get("resourcedump_mem_mode"):
        tmp_file_name = 'tmp_' + str(time.time()) + '.bin'
        tmp_file_path = Path(_config_args.get("file_path")).with_name(tmp_file_name)
        tmp_file_path.touch()

        _config_args["tmp_file_path"] = tmp_file_path


def env_destroy():
    csv_file = _config_args.get("csv_file")
    if csv_file is not None:
        csv_file.close()


#Check and validate environment capabilities
def validate_env_caps():
    p_v = sys.version[0:1]
    dump_hw_res = _config_args.get("dump_hw_resources")
    if dump_hw_res:
        if p_v != '3':
            print('Cannot Dump HW resources <-hw>, need Python3')
            exit()

        status, output = sp.getstatusoutput('resourcedump -v')
        if status != 0:
            print(output)
            print('MFT Error')
            exit()
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
    parser.add_argument("-f", dest="file_path", default="", help="Input steering dump file path.", required=True)
    parser.add_argument("-v", action="count", dest="verbose", default=0, help="Increase output verbosity - v, vv, vvv & vvvv for extra verbosity.")
    parser.add_argument("--skip_dump", action="store_false", default=True, dest="dump_hw_resources",
                        help="Skip HW resources dumping.")
    parser.add_argument("--skip_parse", action="store_false", default=True, dest="hw_parse",
                        help="Skip HW dumped resources parsing.")
    parser.add_argument("-d", dest="device", type=str, default="",
                        help="Provide MST device for HW resources dumping, or remote MST device if --remote_ip was specified")
    parser.add_argument("--pid", dest="app_pid", type=int, default=-1,
                        help="Trigger DPDK/DOCA app <PID>.")
    parser.add_argument("--port", dest="app_port", type=int, default=0,
                        help="Trigger DPDK/DOCA app <PORT> newer dpdk, and doca supports -1 for all ports (must provide PID with -pid).")
    parser.add_argument("--extra_hw_res", type=str, default="", dest="extra_hw_res", metavar="[pat, arg, counter, all]",
                        help = "Request extra HW resources to be dumped/parsed. \'all\' option will dump all the HW resources supported by current FW. Usage example: --extra_hw_res pat,arg")
    parser.add_argument("-s", action="store_true", default=False, dest="statistics",
                        help="Show dump statistics.")
    parser.add_argument("--remote_ip", type=str, default="", dest="remote_ip",
                        help = "Indicates to extract HW resources from the remote setup <IP>")
    parser.add_argument("--user_name", type=str, default="", dest="user_name",
                        help = "Indicates the user name on the remote setup")
    parser.add_argument("--remote_path", type=str, default="", dest="remote_path",
                        help = "Indicates the dump tool location on the remote setup, this is optional")
    parser.add_argument("--json", action="store_true", default=False, dest="json",
                        help = "Emit the steering dump as JSON.")
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    args = parser.parse_args()

    if (args.file_path == ""):
        print("No input steering dump file provided (-f FILEPATH)")
        sys.exit(0)
    else:
        _config_args["file_path"] = args.file_path

    _config_args["json"] = args.json

    _config_args["extra_hw_res_all"] = False
    _config_args["extra_hw_res_arg"] = False
    _config_args["extra_hw_res_pat"] = False
    _config_args["extra_hw_res_counter"] = False

    if (args.dump_hw_resources):
        _config_args["dump_hw_resources"] = True
        if (args.device == ""):
            _config_args["device"] = None
        else:
            _config_args["device"] = args.device
    else:
        _config_args["dump_hw_resources"] = False

    _config_args["args.extra_hw_res"] = args.extra_hw_res
    for hw_res in args.extra_hw_res.split(","):
        if hw_res == "all":
            _config_args["extra_hw_res_all"] = True
            _config_args["extra_hw_res_pat"] = True
            _config_args["extra_hw_res_arg"] = True
            _config_args["extra_hw_res_counter"] = True
            break
        elif hw_res == "pat":
            _config_args["extra_hw_res_pat"] = True
        elif hw_res == "arg":
            _config_args["extra_hw_res_arg"] = True
        elif hw_res == "counter":
            _config_args["extra_hw_res_counter"] = True

    if _config_args.get("extra_hw_res_arg") and not(_config_args.get("extra_hw_res_pat")):
        _config_args["extra_hw_res_arg"] = False

    if (args.hw_parse):
        _config_args["parse_hw_resources"] = True
        _config_args["load_hw_resources"] = True
    else:
        _config_args["parse_hw_resources"] = False
        _config_args["load_hw_resources"] = False

    if (args.app_pid > 0):
        if dr_trigger.trigger_dump(args.app_pid, args.app_port, args.file_path, 0) is None:
            sys.exit(-1)
        _config_args["app_pid"] = args.app_pid

    if (os.stat(args.file_path).st_size == 0):
        print("Empty input file, no data to parse")
        sys.exit(0)

    if args.verbose > 4:
        _config_args["verbose"] = 4
    else:
        _config_args["verbose"] = args.verbose

    _config_args["resourcedump_mem_mode"] = False
    _config_args["hw_resources_present"] = False

    _config_args["statistics"] = args.statistics

    if args.remote_ip != "" and args.dump_hw_resources:
        _config_args["remote"] = True
        _config_args["remote_ip"] = args.remote_ip
        _config_args["user_name"] = args.user_name
        _config_args["dump_tool_remote_path"] = args.remote_path
        _config_args["password"] = None
        _config_args["remote_dep_lib"] = False
        dr_connect_to_remote()
        sys.exit(0)

if __name__ == "__main__":
    try:
        parse_args()
        validate_env_caps()
        env_init()
        file_path = _config_args.get("file_path")
        verbose = _config_args.get("verbose")

        with open(file_path, 'r+') as csv_file:
            load_to_db = False if _config_args.get("dump_hw_resources") else _config_args.get("load_hw_resources")
            ctxs, unsupported_obj_list = dr_parse_csv_file(csv_file, load_to_db)

        if _config_args.get("dump_hw_resources"):
            csv_file = open(_config_args.get("file_path"), 'a+')
            _config_args["csv_file"] = csv_file
        else:
            if not _config_args.get("hw_resources_present"):
                _config_args["parse_hw_resources"] = False
                _config_args["load_hw_resources"] = False

        json_format = _config_args.get("json")
        output_file_suffix = ".json" if json_format else ".parsed"
        output_file_name = file_path + output_file_suffix
        output_file = open(output_file_name, 'w+')

        for ctx in ctxs:
            ctx.load_to_db()
            _config_args["total_resources"] = len(_db._stc_indexes_arr) + len(_db._fw_ste_indexes_arr)
            _config_args["total_fw_ste"] = len(_db._fw_ste_indexes_arr)

            if _config_args.get("dump_hw_resources"):
                dr_hw_data_engine(ctx, csv_file)

            if _config_args.get("parse_hw_resources"):
                _config_args["progress_bar_i"] = 0
                interactive_progress_bar(0, _config_args.get("total_fw_ste"), PARSING_THE_RULES_STR)

            if _config_args.get("csv_file") is not None and _config_args.get("hw_resources_dump_started"):
                csv_file.write(MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END + '\n')

            ctx.pre_parse()
            obj = ctx.dump_obj(verbose, transform_for_print=not json_format)
            if json_format:
                output_file.write(json.dumps(obj, indent=4))
            else:
                output_file.write(pretty_obj_repr(obj))

        print("")#empty line
        print(OUTPUT_FILE_STR + file_path)
        print(PARSED_OUTPUT_FILE_STR + output_file_name)

        if verbose > 0:
            print_unsupported_obj_list(unsupported_obj_list)

    except OSError as e:
        print(e)

    finally:
        env_destroy()
