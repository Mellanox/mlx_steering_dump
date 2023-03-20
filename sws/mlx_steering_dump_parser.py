#!/usr/bin/env python3

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

# Parse tool for SW steering debug dump file
import argparse
import csv

from src import dr_trigger
from src.dr_action import *
from src.dr_domain import *
from src.dr_matcher import *
from src.dr_rule import *
from src.dr_table import *
from src.dr_utilities import *
from src.dr_constants import *

# mapping csv records types to it's relevant parser function
switch_csv_rec_type = {
    DR_DUMP_REC_TYPE_DOMAIN: dr_dump_domain,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR: dr_dump_domain_info_dev_attr,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS: dr_dump_domain_info_caps,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT: dr_dump_domain_info_vport,
    DR_DUMP_REC_TYPE_DOMAIN_SEND_RING: dr_dump_domain_send_ring,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER: dr_dump_domain_info_flex_parser,

    DR_DUMP_REC_TYPE_TABLE: dr_dump_table,
    DR_DUMP_REC_TYPE_TABLE_RX: dr_dump_table_rx_tx,
    DR_DUMP_REC_TYPE_TABLE_TX: dr_dump_table_rx_tx,

    DR_DUMP_REC_TYPE_MATCHER: dr_dump_matcher,
    DR_DUMP_REC_TYPE_MATCHER_MASK: dr_dump_matcher_mask,
    DR_DUMP_REC_TYPE_MATCHER_MASK_WITH_RESERVED: dr_dump_matcher_mask,
    DR_DUMP_REC_TYPE_MATCHER_RX: dr_dump_matcher_rx_tx,
    DR_DUMP_REC_TYPE_MATCHER_TX: dr_dump_matcher_rx_tx,
    DR_DUMP_REC_TYPE_MATCHER_BUILDER: dr_dump_matcher_builder,

    DR_DUMP_REC_TYPE_RULE: dr_dump_rule,
    DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V0: dr_dump_rule_entry_rx_tx,
    DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V0: dr_dump_rule_entry_rx_tx,
    DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V1: dr_dump_rule_entry_rx_tx,
    DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V1: dr_dump_rule_entry_rx_tx,

    DR_DUMP_REC_TYPE_ACTION_ENCAP_L2: dr_dump_action_encap_l2,
    DR_DUMP_REC_TYPE_ACTION_ENCAP_L3: dr_dump_action_encap_l3,
    DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR: dr_dump_action_modify_header,
    DR_DUMP_REC_TYPE_ACTION_DROP: dr_dump_action_drop,
    DR_DUMP_REC_TYPE_ACTION_QP: dr_dump_action_qp,
    DR_DUMP_REC_TYPE_ACTION_FT: dr_dump_action_ft,
    DR_DUMP_REC_TYPE_ACTION_CTR: dr_dump_action_ctr,
    DR_DUMP_REC_TYPE_ACTION_TAG: dr_dump_action_tag,
    DR_DUMP_REC_TYPE_ACTION_VPORT: dr_dump_action_vport,
    DR_DUMP_REC_TYPE_ACTION_DECAP_L2: dr_dump_action_decap_l2,
    DR_DUMP_REC_TYPE_ACTION_DECAP_L3: dr_dump_action_decap_l3,
    DR_DUMP_REC_TYPE_ACTION_DEVX_TIR: dr_dump_action_devx_tir,
    DR_DUMP_REC_TYPE_ACTION_POP_VLAN: dr_dump_action_pop_vlan,
    DR_DUMP_REC_TYPE_ACTION_PUSH_VLAN: dr_dump_action_push_vlan,
    DR_DUMP_REC_TYPE_ACTION_METER: dr_dump_action_meter,
    DR_DUMP_REC_TYPE_ACTION_SAMPLER: dr_dump_action_sampler,
    DR_DUMP_REC_TYPE_ACTION_DEST_ARRAY: dr_dump_action_dest_array,
    DR_DUMP_REC_TYPE_ACTION_ASO_FIRST_HIT: dr_dump_action_aso_flow_hit,
    DR_DUMP_REC_TYPE_ACTION_ASO_FLOW_METER: dr_dump_action_aso_flow_meter,
    DR_DUMP_REC_TYPE_ACTION_MISS: dr_dump_action_default_miss,
    DR_DUMP_REC_TYPE_ACTION_ASO_CT: dr_dump_action_aso_ct,
    DR_DUMP_REC_TYPE_PMD_ACTION_PKT_REFORMAT: dr_dump_encap_decap,
    DR_DUMP_REC_TYPE_PMD_ACTION_COUNTER: dr_dump_counter,
    DR_DUMP_REC_TYPE_PMD_ACTION_MODIFY_HDR: dr_dump_modify_hdr,
    DR_DUMP_REC_TYPE_ACTION_ROOT_FT: dr_dump_action_root_ft,
    DR_DUMP_REC_TYPE_ACTION_MATCH_RANGE: dr_dump_action_match_range,
}

unsupported_obj_list = []
def dr_report_unsupported_objects():
    for dr_rec_type in unsupported_obj_list:
        if dr_rec_type_is_domain(dr_rec_type):
            print("Err: Unsupported domain related object: ", dr_rec_type)
        elif dr_rec_type_is_table(dr_rec_type):
            print("Err: Unsupported table related object: ", dr_rec_type)
        elif dr_rec_type_is_matcher(dr_rec_type):
            print("Err: Unsupported matcher related object: ", dr_rec_type)
        elif dr_rec_type_is_rule(dr_rec_type):
            print("Err: Unsupported rule related object: ", dr_rec_type)
        elif dr_rec_type_is_action(dr_rec_type):
            if dump_ctx.rule:
                action = dr_dump_action_unsupported(line)
                dump_ctx.rule.add_action(action)
            else:
                print("Err: Unsupported domain related object: ", dr_rec_type)
        else:
            print("Unsupported object", dr_rec_type)


# parse csv record according to type and return parsed object (like dr_domain, dr_table, dr_rule ...)
def dr_csv_get_obj(line):
    rec_type = line[0]
    if rec_type not in switch_csv_rec_type.keys():
        return None

    parser = switch_csv_rec_type[line[0]]
    return parser(line)


def print_ctx(dump_ctx, view, verbose, raw, colored):
    dr_obj = None
    if dump_ctx.domain:
        dr_obj = dump_ctx.domain
    elif dump_ctx.table:
        dr_obj = dump_ctx.table.print_view
    elif dump_ctx.matcher:
        dr_obj = dump_ctx.matcher
    elif dump_ctx.rule:
        dr_obj = dump_ctx.rule

    if colored:
        set_colored_prints()

    if view == DR_DUMP_VIEW_TREE:
        dr_obj.print_tree_view(dump_ctx, verbose, raw)
    else:
        dr_obj.print_rule_view(dump_ctx, verbose, raw)


# Used to mark end of file
LAST_OBJ = dr_obj()


def parse_domain(csv_reader, domain_obj=None, verbose=0):
    """
    Function is parsing one domain from provided csv reader
    :param csv_reader: csv reader to parse with
    :param domain_obj: domain object that was parsed in previous function call
    :return: dump_ctx: parsed domain
              dr_obj: parsed domain object for the next function call (or
              LAST_OBJ when end of file is reached)
    """
    dump_ctx = dr_dump_ctx()

    if domain_obj:
        dump_ctx.domain = domain_obj

    for line in csv_reader:
        if len(line) <= 0:
            continue

        if line[0][0] == '4' and verbose < 4:
            continue

        dr_obj = dr_csv_get_obj(line)
        dr_rec_type = line[0]

        # report unsupported object
        if dr_obj is None and dr_rec_type not in unsupported_obj_list:
            unsupported_obj_list.append(dr_rec_type)
            continue

        # update Rule entry objects
        if dr_rec_type in [DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V0,
                           DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V0,
                           DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V1,
                           DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V1]:

            definer_id = '-1'
            for builder in dump_ctx.matcher.builders[::-1]:
                if ((int(builder.data["is_rx"]) and dr_rec_type in [DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V0, \
                                                                    DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V1]) or \
                    ((not int(builder.data["is_rx"]) and dr_rec_type in [DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V0, \
                                                                         DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V1]))):
                    definer_id = builder.data["definer_id"]

            dr_obj.data["definer_id"] = definer_id
            dump_ctx.rule.add_rule_entry(dr_obj)

        # update Action objects
        elif dr_rec_type_is_action(dr_rec_type):
            dump_ctx.rule.add_action(dr_obj)
            if dr_rec_type in [DR_DUMP_REC_TYPE_ACTION_ENCAP_L2,
                               DR_DUMP_REC_TYPE_ACTION_ENCAP_L3,
                               DR_DUMP_REC_TYPE_ACTION_CTR,
                               DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR]:
               dr_obj.add_dump_ctx(dump_ctx)

        # update Rule objects
        elif dr_rec_type == DR_DUMP_REC_TYPE_RULE:
            dump_ctx.rule = dr_obj
            dump_ctx.matcher.add_rule(dr_obj)

        # update Matcher objects
        elif dr_rec_type == DR_DUMP_REC_TYPE_MATCHER_BUILDER:
            dump_ctx.matcher.add_builder(dr_obj)

        elif dr_rec_type == DR_DUMP_REC_TYPE_MATCHER_RX or \
                dr_rec_type == DR_DUMP_REC_TYPE_MATCHER_TX:
            dump_ctx.matcher.add_matcher_rx_tx(dr_obj)

        elif dr_rec_type in [DR_DUMP_REC_TYPE_MATCHER_MASK,
                             DR_DUMP_REC_TYPE_MATCHER_MASK_WITH_RESERVED]:
            dump_ctx.matcher.add_mask(dr_obj)

        elif dr_rec_type == DR_DUMP_REC_TYPE_MATCHER:
            dump_ctx.matcher = dr_obj
            dump_ctx.table.add_matcher(dr_obj)

        # update Table objects
        elif dr_rec_type == DR_DUMP_REC_TYPE_TABLE_RX or \
                dr_rec_type == DR_DUMP_REC_TYPE_TABLE_TX:
            dump_ctx.table.add_table_rx_tx(dr_obj)

        elif dr_rec_type == DR_DUMP_REC_TYPE_TABLE:
            dump_ctx.table = dr_obj
            dump_ctx.domain.add_table(dr_obj)

        # update Domain objects
        elif dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN:
            # If parsing reached the next domain we return the parsed object to
            # use it for the next function call since we can't re-parse this
            # line again
            if dump_ctx.domain is not None:
                return dump_ctx, dr_obj
            dump_ctx.domain = dr_obj

        elif dump_ctx.domain and dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER:
            dump_ctx.domain.add_flex_parser(dr_obj)

        elif dump_ctx.domain and dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR:
            dump_ctx.domain.add_dev_attr(dr_obj)

        elif dump_ctx.domain and dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT:
            dump_ctx.domain.add_vport(dr_obj)

        elif dump_ctx.domain and dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS:
            dump_ctx.domain.add_caps(dr_obj)

        elif dump_ctx.domain and dr_rec_type == DR_DUMP_REC_TYPE_DOMAIN_SEND_RING:
            dump_ctx.domain.add_send_ring(dr_obj)

        elif dr_rec_type == DR_DUMP_REC_TYPE_PMD_ACTION_PKT_REFORMAT:
            if dr_obj.id and dr_obj.data:
                dump_ctx.encap_decap[dr_obj.id] = dr_obj.data

        elif dr_rec_type == DR_DUMP_REC_TYPE_PMD_ACTION_COUNTER:
            if dr_obj.id and dr_obj.data:
                dump_ctx.counter[dr_obj.id] = dr_obj.data

        elif dr_rec_type == DR_DUMP_REC_TYPE_PMD_ACTION_MODIFY_HDR:
            if dr_obj.id and dr_obj.data:
                dump_ctx.modify_hdr[dr_obj.id] = dr_obj.data

    return dump_ctx, LAST_OBJ


def parse_args():
    parser = argparse.ArgumentParser(description='''mlx_steering_dump.py - Steering dump tool''')
    parser.add_argument('-f', dest="FILEPATH", default="", help='input steering dump file path')
    parser.add_argument('-p', dest="dpdk_pid", type=int, default=-1,
                        help='Trigger DPDK app to generate CSV dump file (-p <APP PID>)')
    parser.add_argument('-t', action='store_true', default=False, dest='tree_view',
                        help='tree view (default is rule view)')
    parser.add_argument("-v", action="count", dest='verbose', default=0, help="increase output verbosity")
    parser.add_argument('-r', action='store_true', default=False, dest='raw', help='raw output')
    parser.add_argument('-c', action='store_true', default=False, dest='colored', help='colored output')
    parser.add_argument('-port', dest="dpdk_port", type=int, default=0,
                        help='Trigger DPDK app <PORT> (must provide PID with -p)')
    parser.add_argument('-flowptr', dest="flow_ptr", type=int, default=0, help='dump single rule by rte_flow_pointer')
    parser.add_argument('-version', action='store_true', default=False, dest='version', help='show version')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if (args.version):
        print_dr(dr_print_color.RESET, "Version %s\n" % g_version)
        sys.exit(0)

    if (args.FILEPATH == ""):
        set_colored_prints()
        print_dr(dr_print_color.ERROR, "No input steering dump file provided (-f FILEPATH)\n")
        sys.exit(0)

    if (args.dpdk_pid > 0):
        if dr_trigger.trigger_dump(args.dpdk_pid, args.dpdk_port, args.FILEPATH, args.flow_ptr) is None:
            sys.exit(-1)
    domain_obj = None
    with open(args.FILEPATH) as csv_file:
        csv_reader = csv.reader(csv_file)
        while domain_obj != LAST_OBJ:
            dump_ctx, domain_obj = parse_domain(csv_reader, domain_obj, args.verbose)
            print_ctx(dump_ctx, DR_DUMP_VIEW_TREE if args.tree_view
            else DR_DUMP_VIEW_RULE, args.verbose,
                      args.raw, args.colored)
    if args.verbose:
        dr_report_unsupported_objects()

    if unsupported_obj_list:
        print_dr(dr_print_color.ERROR, "Warning: missing info due to unsupporteds objects\n")
    sys.exit(0)
