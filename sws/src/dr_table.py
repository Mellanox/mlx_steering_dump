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

from src.dr_utilities import _srd, print_dr, dr_obj, inc_indent, dec_indent, \
    dr_print_color
from src.dr_constants import *


def dr_rec_type_is_table(rec_type):
    if rec_type.startswith(DR_DUMP_REC_TYPE_TABLE_OBJS):
        return True
    return False


class dr_dump_table(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "domain_id", "type", "level"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.fix_data()
        self.matcher_list = []
        self.table_rx = None
        self.table_tx = None

    def dump_str(self, verbose):
        if verbose == 0:
            return "table %s: level: %s, type: %s\n" % (
                _srd(self.data, "id"),
                _srd(self.data, "level"),
                _srd(self.data, "type"))
        else:
            rx_s_anchor = ""
            tx_s_anchor = ""

            if self.table_rx:
                rx_s_anchor = "rx s_anchor %s," % (self.table_rx.dump_str())
            if self.table_tx:
                tx_s_anchor = "tx s_anchor %s" % (self.table_tx.dump_str())

            return "table %s: level: %s, type: %s, %s %s\n" % (
                _srd(self.data, "id"),
                _srd(self.data, "level"),
                _srd(self.data, "type"),
                rx_s_anchor,
                tx_s_anchor)

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.TABLE, self.dump_str(verbose))
        inc_indent()

        for m in self.matcher_list:
            dump_ctx.matcher = m
            dump_ctx.rule = None
            m.print_tree_view(dump_ctx, verbose, raw)

        dec_indent()

    def print_rule_view(self, dump_ctx, verbose, raw):
        for m in self.matcher_list:
            dump_ctx.matcher = m
            dump_ctx.rule = None
            m.print_rule_view(dump_ctx, verbose, raw)

    def fix_data(self):
        type = int(self.data["type"])
        switch = {0x0: "NIC_RX",
                  0x1: "NIC_TX",
                  0x2: "ESW_EGRESS_ACL",
                  0x3: "ESW_INGRESS_ACL",
                  0X4: "FDB",
                  0X5: "SNIFFER_RX",
                  0X6: "SNIFFER_TX"
                  }
        if int(self.data["level"]) == 0:
            self.data["type"] = "ROOT"
        else:
            self.data["type"] = switch[type]

    def add_matcher(self, matcher):
        self.matcher_list.append(matcher)

    def add_table_rx_tx(self, table_rx_tx):
        anchor_type = table_rx_tx.data['dr_dump_rec_type']
        if anchor_type == DR_DUMP_REC_TYPE_TABLE_RX:
            self.table_rx = table_rx_tx
        else:
            self.table_tx = table_rx_tx


class dr_dump_table_rx_tx(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "table_id", "s_anchor"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "%s" % (_srd(self.data, "s_anchor"))
