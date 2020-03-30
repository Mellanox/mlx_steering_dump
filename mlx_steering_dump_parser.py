#!/usr/bin/env python

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


# mapping csv records types to it's relevant parser function
def dr_csv_rec_type_parser(rec_type):
    switch = {
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN.value[0]: dr_dump_domain,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR.value[0]: dr_dump_domain_info_dev_attr,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS.value[0]: dr_dump_domain_info_caps,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT.value[0]: dr_dump_domain_info_vport,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_SEND_RING.value[0]: dr_dump_domain_send_ring,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER.value[0]: dr_dump_domain_info_flex_parser,

        dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE.value[0]: dr_dump_table,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE_RX.value[0]: dr_dump_table_rx_tx,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE_TX.value[0]: dr_dump_table_rx_tx,

        dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER.value[0]: dr_dump_matcher,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_MASK.value[0]: dr_dump_matcher_mask,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_RX.value[0]: dr_dump_matcher_rx_tx,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_TX.value[0]: dr_dump_matcher_rx_tx,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_BUILDER.value[0]: dr_dump_matcher_builder,

        dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE.value[0]: dr_dump_rule,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE_RX_ENTRY.value[0]: dr_dump_rule_entry_rx_tx,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE_TX_ENTRY.value[0]: dr_dump_rule_entry_rx_tx,

        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_ENCAP_L2.value[0]: dr_dump_action_encup_l2,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_ENCAP_L3.value[0]: dr_dump_action_encup_l2,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR.value[0]: dr_dump_action_modify_header,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_DROP.value[0]: dr_dump_action_drop,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_QP.value[0]: dr_dump_action_qp,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_FT.value[0]: dr_dump_action_ft,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_CTR.value[0]: dr_dump_action_ctr,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_TAG.value[0]: dr_dump_action_tag,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_VPORT.value[0]: dr_dump_action_vport,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_DECAP_L2.value[0]: dr_dump_action_decup_l2,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_DECAP_L3.value[0]: dr_dump_action_decup_l3,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_DEVX_TIR.value[0]: dr_dump_action_devx_tir,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_POP_VLAN.value[0]: dr_dump_action_pop_vlan,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_PUSH_VLAN.value[0]: dr_dump_action_push_vlan,
        dr_dump_rec_type.DR_DUMP_REC_TYPE_ACTION_METER.value[0]: dr_dump_action_meter,
    }

    return switch[rec_type]


# parse csv record according to type and return parsed object (like dr_domain, dr_table, dr_rule ...)
def dr_csv_get_obj(line):
    rec_type = int(line[0])
    parser = dr_csv_rec_type_parser(rec_type)
    return parser(line)

def print_ctx(dump_ctx, view, verbose, raw):
    dr_obj = None
    if dump_ctx.domain:
        dr_obj = dump_ctx.domain
    elif dump_ctx.table:
        dr_obj = dump_ctx.table.print_view
    elif dump_ctx.matcher:
        dr_obj = dump_ctx.matcher
    elif dump_ctx.rule:
        dr_obj = dump_ctx.rule

    if view == dr_dump_view.DR_DUMP_VIEW_TREE:
        dr_obj.print_tree_view(dump_ctx, verbose, raw)
    else:
        dr_obj.print_rule_view(dump_ctx, verbose, raw)


# print parsed data either in tree or rule view
def print_domain(file_path, view, verbose, raw):
    with open(file_path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        dump_ctx = dr_dump_ctx()

        for line in csv_reader:
            dr_obj = dr_csv_get_obj(line)
            dr_rec_type = int(line[0])

            # update Domain objects
            if dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN.value[0]:
                if dump_ctx.domain is not None:
                    print_ctx(dump_ctx, view, verbose, raw)
                dump_ctx.domain = dr_obj

            elif dump_ctx.domain and dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER.value[0]:
                dump_ctx.domain.add_flex_parser(dr_obj)

            elif dump_ctx.domain and dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR.value[0]:
                dump_ctx.domain.add_dev_attr(dr_obj)

            elif dump_ctx.domain and dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT.value[0]:
                dump_ctx.domain.add_vport(dr_obj)

            elif dump_ctx.domain and dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS.value[0]:
                dump_ctx.domain.add_caps(dr_obj)

            elif dump_ctx.domain and dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_DOMAIN_SEND_RING.value[0]:
                dump_ctx.domain.add_send_ring(dr_obj)

            # update Table objects
            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE.value[0]:
                dump_ctx.table = dr_obj
                dump_ctx.domain.add_table(dr_obj)

            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE_RX.value[0] or \
                    dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE_TX.value[0]:
                dump_ctx.table.add_table_rx_tx(dr_obj)

            # update Matcher objects
            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER.value[0]:
                dump_ctx.matcher = dr_obj
                dump_ctx.table.add_matcher(dr_obj)

            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_MASK.value[0]:
                dump_ctx.matcher.add_mask(dr_obj)

            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_RX.value[0] or \
                    dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_RX.value[0]:
                dump_ctx.matcher.add_matcher_rx_tx(dr_obj)

            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_MATCHER_BUILDER.value[0]:
                dump_ctx.matcher.add_builder(dr_obj)

            # update Rule objects
            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE.value[0]:
                dump_ctx.rule = dr_obj
                dump_ctx.matcher.add_rule(dr_obj)

            elif dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE_RX_ENTRY.value[0] \
                    or dr_rec_type == dr_dump_rec_type.DR_DUMP_REC_TYPE_RULE_TX_ENTRY.value[0]:
                dump_ctx.rule.add_rule_entry(dr_obj)

            # update Action objects
            elif dr_dump_rec_type.find_name(dr_rec_type).startswith('DR_DUMP_REC_TYPE_ACTION_'):
                dump_ctx.rule.add_action(dr_obj)

        print_ctx(dump_ctx, view, verbose, raw)


def parse_args():
    parser = argparse.ArgumentParser(description='''mlx_steering_dump.py - Steering dump tool''')
    parser.add_argument('-f', dest="FILEPATH", default="", help='input steering dump file path')
    parser.add_argument('-p', dest="dpdk_pid", type=int, default=-1, help='Trigger DPDK app to generate CSV dump file (-p <APP PID>)')
    parser.add_argument('-t', action='store_true', default=False, dest='tree_view', help='tree view (default is rule view)')
    parser.add_argument("-v", action="count", dest='verbose', default=0, help="increase output verbosity")
    parser.add_argument('-r', action='store_true', default=False, dest='raw', help='raw output')
    parser.add_argument('-version', action='store_true', default=False, dest='version', help='show version')
    return parser.parse_args()


def main():
    DPDK_PORT = 0
    args = parse_args()
    if (args.version):
        print_dr("Version %s\n" % g_version)
        return 0

    if (args.FILEPATH == ""):
        print_dr("No input steering dump file provided (-f FILEPATH)\n")
        return 0

    if (args.dpdk_pid > 0):
        if dr_trigger.trigger_dump(args.dpdk_pid, DPDK_PORT, args.FILEPATH) is None:
            return -1

    if (args.tree_view):
        print_domain(args.FILEPATH, dr_dump_view.DR_DUMP_VIEW_TREE, args.verbose, args.raw)
    else:
        print_domain(args.FILEPATH, dr_dump_view.DR_DUMP_VIEW_RULE, args.verbose, args.raw)

    return 0


main()
