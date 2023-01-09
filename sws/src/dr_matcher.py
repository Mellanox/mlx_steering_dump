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

from src.dr_utilities import _srd, dict_join_str, print_dr, dr_obj, \
    inc_indent, dec_indent, dr_print_color
from src.parsers import dr_matcher_mask_parser
from src.parsers import mlx5_ifc_parser
from src.dr_constants import *
from src import dr_prettify


def dr_rec_type_is_matcher(rec_type):
    if rec_type.startswith(DR_DUMP_REC_TYPE_MATCHER_OBJS):
        return True
    return False


class dr_dump_matcher(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "table_id", "priority"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.rule_list = []
        self.builders = []
        self.matcher_rx = None
        self.matcher_tx = None

    def dump_str(self):
        rx_tx_e_anchor = ""

        if self.matcher_rx:
            rx_tx_e_anchor += "rx e_anchor %s" % (_srd(self.matcher_rx.data, "e_anchor"))

        if self.matcher_tx:
            if self.matcher_rx:
                rx_tx_e_anchor += ", "
            rx_tx_e_anchor += "tx e_anchor %s" % (_srd(self.matcher_tx.data, "e_anchor"))

        return "matcher %s: priority %s, %s\n" % (
            _srd(self.data, "id"),
            _srd(self.data, "priority"),
            rx_tx_e_anchor)

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.MATCHER, self.dump_str())
        inc_indent()
        print_dr(dr_print_color.MATCHER_MASK, self.mask.dump_str())
        dec_indent()

        inc_indent()
        for r in self.rule_list:
            dump_ctx.rule = None
            r.print_tree_view(dump_ctx, verbose, raw)
        dec_indent()

    def print_rule_view(self, dump_ctx, verbose, raw):
        for r in self.rule_list:
            dump_ctx.rule = r
            r.print_rule_view(dump_ctx, verbose, raw)

    def add_rule(self, rule):
        self.rule_list.append(rule)

    def add_mask(self, mask):
        self.mask = mask

    def add_builder(self, builder):
        self.builders.append(builder)

    def add_matcher_rx_tx(self, matcher_rx_tx):
        if matcher_rx_tx.data['dr_dump_rec_type'] == DR_DUMP_REC_TYPE_MATCHER_RX:
            self.matcher_rx = matcher_rx_tx
        else:
            self.matcher_tx = matcher_rx_tx


class dr_dump_matcher_mask(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "matcher_id", "outer", "inner", "misc", "misc2", "misc3", "misc4", "misc5", "misc6"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        parsed_mask_final = {}
        sub_masks = {}

        if self.data["dr_dump_rec_type"] == DR_DUMP_REC_TYPE_MATCHER_MASK:
            sub_masks = {"outer": dr_matcher_mask_parser.dr_mask_spec_parser,
                         "inner": dr_matcher_mask_parser.dr_mask_spec_parser,
                         "misc": dr_matcher_mask_parser.dr_mask_misc_parser,
                         "misc2": dr_matcher_mask_parser.dr_mask_misc2_parser,
                         "misc3": dr_matcher_mask_parser.dr_mask_misc3_parser,
                         "misc4": dr_matcher_mask_parser.dr_mask_misc4_parser,
                         "misc5": dr_matcher_mask_parser.dr_mask_misc5_parser,
                         "misc6": dr_matcher_mask_parser.dr_mask_misc6_parser
                         }
        else:
            sub_masks = {"outer": mlx5_ifc_parser.mlx5_ifc_dr_match_spec_bits_parser,
                         "inner": mlx5_ifc_parser.mlx5_ifc_dr_match_spec_bits_parser,
                         "misc": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc_bits_parser,
                         "misc2": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc2_bits_parser,
                         "misc3": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc3_bits_parser,
                         "misc4": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc4_bits_parser,
                         "misc5": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc5_bits_parser,
                         "misc6": mlx5_ifc_parser.mlx5_ifc_dr_match_set_misc6_bits_parser
                         }

        for sub_mask_name, sub_mask_parser in sub_masks.items():
            if self.data[sub_mask_name] == "":
                continue

            parsed_mask = sub_mask_parser(self.data[sub_mask_name], False)
            for k, v in list(parsed_mask.items()):
                if sub_mask_name == "inner":
                    parsed_mask[sub_mask_name + "_" + k] = v
                    del parsed_mask[k]

            # Merge to final dictionary
            parsed_mask_final.update(parsed_mask)

        return "mask: %s\n" % dict_join_str(parsed_mask_final)


class dr_dump_matcher_rx_tx(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "matcher_id", "num_of_builders", "s_htbl", "e_anchor"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        return "rx_builder_num: %s, rx_s_htbl_idx: %s, rx_e_anchor_idx: %s\n" % (
            _srd(self.data, "num_of_builders"),
            _srd(self.data, "s_htbl"),
            _srd(self.data, "e_anchor"))


class dr_dump_matcher_builder(dr_obj):
    def __init__(self, data):
        ofed_keys = ["dr_dump_rec_type", "matcher_id", "is_rx", "lu_type", "definer_id"]
        keys = ["dr_dump_rec_type", "matcher_id", "index", "is_rx", "lu_type", "definer_id"]

        if len(data) != len(keys):
            keys = ofed_keys

        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        rx_tx_type = "rx"
        return "matcher_id %s, index %s, rx_tx_type %s, lu_type %s\n" % (
            _srd(self.data, "matcher_id"),
            _srd(self.data, "index"),
            rx_tx_type,
            dr_prettify.lu_type_conv(_srd(self.data, "lu_type")))
