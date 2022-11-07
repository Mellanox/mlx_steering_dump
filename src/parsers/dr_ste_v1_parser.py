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

from src.parsers.dr_ste_v1_tag_parser import mlx5_ste_v1_tag_parser
from src.dr_constants import *
from src.parsers.dr_ste_v1_actions_parser import mlx5_ifc_ste_v1_action_bits_parser
from src.dr_utilities import to_hex


def mlx5_ifc_ste_v1_unsupported_ste():
    ret = {}
    ret["tag"] = {"UNSUPPORTED_FIELDS": 0x0}
    return ret


def mlx5_ifc_ste_v1_match_bwc_bits_parser(bin_str, definer_id, raw):
    ret = {}
    ret["entry_format"] = to_hex(int(bin_str[0: 8], 2))
    ret["counter_id"] = to_hex(int(bin_str[8: 32], 2))

    ret["miss_address_63_48"] = to_hex(int(bin_str[32: 48], 2))
    ret["match_definer_ctx_idx"] = to_hex(int(bin_str[48: 56], 2))
    ret["miss_address_39_32"] = to_hex(int(bin_str[56: 64], 2))

    ret["miss_address_31_6"] = to_hex(int(bin_str[64: 90], 2))
    ret["reserved_at_5a"] = to_hex(int(bin_str[90: 91], 2))
    ret["match_polarity"] = to_hex(int(bin_str[91: 92], 2))
    ret["reparse"] = to_hex(int(bin_str[92: 93], 2))
    ret["reserved_at_5d"] = to_hex(int(bin_str[93: 96], 2))

    ret["next_table_base_63_48"] = to_hex(int(bin_str[96: 112], 2))
    ret["hash_definer_ctx_idx"] = to_hex(int(bin_str[112: 120], 2))
    ret["next_table_base_39_32_size"] = to_hex(int(bin_str[120: 128], 2))

    ret["next_table_base_31_5_size"] = to_hex(int(bin_str[128: 155], 2))
    ret["hash_type"] = to_hex(int(bin_str[155: 157], 2))
    ret["hash_after_actions"] = to_hex(int(bin_str[157: 158], 2))
    ret["reserved_at_9e"] = to_hex(int(bin_str[158: 160], 2))

    ret["byte_mask"] = to_hex(int(bin_str[160: 176], 2))
    ret["next_entry_format"] = to_hex(int(bin_str[176: 177], 2))
    ret["mask_mode"] = to_hex(int(bin_str[177: 178], 2))
    ret["gvmi"] = to_hex(int(bin_str[178: 192], 2))

    ret["action0"] = to_hex(int(bin_str[192: 224], 2))
    ret["action1"] = to_hex(int(bin_str[224: 256], 2))
    ret["actions"] = mlx5_ifc_ste_v1_action_bits_parser([ret["action0"], ret["action1"]])
    tag = bin_str[256: 384]
    lookup_type = int(bin_str[0: 8] + bin_str[48: 56], 2)
    ret["tag"] = mlx5_ste_v1_tag_parser(lookup_type, definer_id, tag, raw)

    return ret


def mlx5_ifc_ste_v1_match_bits_parser(bin_str, definer_id, raw):
    ret = {}
    ret["entry_format"] = to_hex(int(bin_str[0: 8], 2))
    ret["counter_id"] = to_hex(int(bin_str[8: 32], 2))

    ret["miss_address_63_48"] = to_hex(int(bin_str[32: 48], 2))
    ret["match_definer_ctx_idx"] = to_hex(int(bin_str[48: 56], 2))
    ret["miss_address_39_32"] = to_hex(int(bin_str[56: 64], 2))

    ret["miss_address_31_6"] = to_hex(int(bin_str[64: 90], 2))
    ret["reserved_at_5a"] = to_hex(int(bin_str[90: 91], 2))
    ret["match_polarity"] = to_hex(int(bin_str[91: 92], 2))
    ret["reparse"] = to_hex(int(bin_str[92: 93], 2))
    ret["reserved_at_5d"] = to_hex(int(bin_str[93: 96], 2))

    ret["next_table_base_63_48"] = to_hex(int(bin_str[96: 112], 2))
    ret["hash_definer_ctx_idx"] = to_hex(int(bin_str[112: 120], 2))
    ret["next_table_base_39_32_size"] = to_hex(int(bin_str[120: 128], 2))

    ret["next_table_base_31_5_size"] = to_hex(int(bin_str[128: 155], 2))
    ret["hash_type"] = to_hex(int(bin_str[155: 157], 2))
    ret["hash_after_actions"] = to_hex(int(bin_str[157: 158], 2))
    ret["reserved_at_9e"] = to_hex(int(bin_str[158: 160], 2))

    ret["action0"] = to_hex(int(bin_str[160: 192], 2))
    ret["action1"] = to_hex(int(bin_str[192: 224], 2))
    ret["action2"] = to_hex(int(bin_str[224: 256], 2))

    ret["actions"] = mlx5_ifc_ste_v1_action_bits_parser([ret["action0"], ret["action1"], ret["action2"]])

    if len(bin_str) == 512:
        tag = bin_str[256: 512]
        lookup_type = int(bin_str[0: 8] + bin_str[48: 56], 2)
        ret["tag"] = mlx5_ste_v1_tag_parser(lookup_type, definer_id, tag, raw)
    else:
        ret["tag"] = {"Tag": "STE only contains actions"}

    return ret


def mlx5_ifc_ste_v1_match_ranges_bits_parser(bin_str, definer_id, raw):
    ret = {}
    ret["entry_format"] = hex(int(bin_str[0: 8], 2))
    ret["counter_id"] = hex(int(bin_str[8: 32], 2))

    ret["miss_address_63_48"] = hex(int(bin_str[32: 48], 2))
    ret["match_definer_ctx_idx"] = hex(int(bin_str[48: 56], 2))
    ret["miss_address_39_32"] = hex(int(bin_str[56: 64], 2))

    ret["miss_address_31_6"] = hex(int(bin_str[64: 90], 2))
    ret["reserved_at_5a"] = hex(int(bin_str[90: 91], 2))
    ret["match_polarity"] = hex(int(bin_str[91: 92], 2))
    ret["reparse"] = hex(int(bin_str[92: 93], 2))
    ret["reserved_at_5d"] = hex(int(bin_str[93: 96], 2))

    ret["next_table_base_63_48"] = hex(int(bin_str[96: 112], 2))
    ret["hash_definer_ctx_idx"] = hex(int(bin_str[112: 120], 2))
    ret["next_table_base_39_32_size"] = hex(int(bin_str[120: 128], 2))

    ret["next_table_base_31_5_size"] = hex(int(bin_str[128: 155], 2))
    ret["hash_type"] = hex(int(bin_str[155: 157], 2))
    ret["hash_after_actions"] = hex(int(bin_str[157: 158], 2))
    ret["reserved_at_9e"] = hex(int(bin_str[158: 160], 2))

    ret["action0"] = hex(int(bin_str[160: 192], 2))

    ret["action1"] = hex(int(bin_str[192: 224], 2))

    ret["action2"] = hex(int(bin_str[224: 256], 2))

    ret["max_value_2_high"] = hex(int(bin_str[256: 272], 2))
    ret["max_value_2_low"] = hex(int(bin_str[272: 288], 2))
    ret["min_value_2_high"] = hex(int(bin_str[288: 304], 2))
    ret["min_value_2_low"] = hex(int(bin_str[304: 320], 2))

    pkt_len_range = "eth_pkt_len " + ret["min_value_2_high"] + "-" + ret["max_value_2_high"]
    ret["tag"] = {"range": pkt_len_range}

    return ret


def mlx5_hw_ste_v1_parser(bin_str, definer_id, raw, verbose):
    entry_type = int(bin_str[0: 8], 2)

    switch = {
        DR_STE_TYPE_BWC_BYTE: mlx5_ifc_ste_v1_match_bwc_bits_parser,
        DR_STE_TYPE_BWC_DW: mlx5_ifc_ste_v1_match_bwc_bits_parser,
        DR_STE_TYPE_MATCH: mlx5_ifc_ste_v1_match_bits_parser,
        DR_STE_TYPE_MATCH_RANGES: mlx5_ifc_ste_v1_match_ranges_bits_parser,
        # This fake ste type is temporary, in order to not break older dump generators
        DR_STE_TYPE_MATCH_OLD: mlx5_ifc_ste_v1_match_bits_parser,
    }

    if entry_type in switch.keys():
        return switch[entry_type](bin_str, definer_id, raw)
    else:
        return mlx5_ifc_ste_v1_unsupported_ste()
