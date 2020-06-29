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
from src.dr_utilities import dr_ste_entry_format


def mlx5_ifc_ste_v1_match_bwc_bits_parser(bin_str, raw) :
    ret = {}
    ret["entry_format"] = hex(int(bin_str[0 : 8], 2))
    ret["counter_id"] = hex(int(bin_str[8 : 32], 2))

    ret["miss_address_63_48"] = hex(int(bin_str[32 : 48], 2))
    ret["match_definer_ctx_idx"] = hex(int(bin_str[48 : 56], 2))
    ret["miss_address_39_32"] = hex(int(bin_str[56 : 64], 2))

    ret["miss_address_31_6"] = hex(int(bin_str[64 : 90], 2))
    ret["reserved_at_5a"] = hex(int(bin_str[90 : 91], 2))
    ret["match_polarity"] = hex(int(bin_str[91 : 92], 2))
    ret["reparse"] = hex(int(bin_str[92 : 93], 2))
    ret["reserved_at_5d"] = hex(int(bin_str[93 : 96], 2))

    ret["next_table_base_63_48"] = hex(int(bin_str[96 : 112], 2))
    ret["hash_definer_ctx_idx"] = hex(int(bin_str[112 : 120], 2))
    ret["next_table_base_39_32_size"] = hex(int(bin_str[120 : 128], 2))

    ret["next_table_base_31_5_size"] = hex(int(bin_str[128 : 155], 2))
    ret["hash_type"] = hex(int(bin_str[155 : 157], 2))
    ret["hash_after_actions"] = hex(int(bin_str[157 : 158], 2))
    ret["reserved_at_9e"] = hex(int(bin_str[158 : 160], 2))

    ret["byte_mask"] = hex(int(bin_str[160 : 176], 2))
    ret["next_entry_format"] = hex(int(bin_str[176 : 177], 2))
    ret["mask_mode"] = hex(int(bin_str[177 : 178], 2))
    ret["gvmi"] = hex(int(bin_str[178 : 192], 2))

    ret["action0"] = hex(int(bin_str[192 : 224], 2))
    ret["action1"] = hex(int(bin_str[224: 256], 2))

    tag = bin_str[256 : 384]
    lookup_type = int(bin_str[0 : 8] + bin_str[48 : 56], 2)
    ret["tag"] = mlx5_ste_v1_tag_parser(lookup_type, tag, raw)

    return ret


def mlx5_ifc_ste_v1_match_bits_parser(bin_str, raw) :
    ret = {}
    ret["entry_format"] = hex(int(bin_str[0 : 8], 2))
    ret["counter_id"] = hex(int(bin_str[8 : 32], 2))

    ret["miss_address_63_48"] = hex(int(bin_str[32 : 48], 2))
    ret["match_definer_ctx_idx"] = hex(int(bin_str[48 : 56], 2))
    ret["miss_address_39_32"] = hex(int(bin_str[56 : 64], 2))

    ret["miss_address_31_6"] = hex(int(bin_str[64 : 90], 2))
    ret["reserved_at_5a"] = hex(int(bin_str[90 : 91], 2))
    ret["match_polarity"] = hex(int(bin_str[91 : 92], 2))
    ret["reparse"] = hex(int(bin_str[92 : 93], 2))
    ret["reserved_at_5d"] = hex(int(bin_str[93 : 96], 2))

    ret["next_table_base_63_48"] = hex(int(bin_str[96 : 112], 2))
    ret["hash_definer_ctx_idx"] = hex(int(bin_str[112 : 120], 2))
    ret["next_table_base_39_32_size"] = hex(int(bin_str[120 : 128], 2))

    ret["next_table_base_31_5_size"] = hex(int(bin_str[128 : 155], 2))
    ret["hash_type"] = hex(int(bin_str[155 : 157], 2))
    ret["hash_after_actions"] = hex(int(bin_str[157 : 158], 2))
    ret["reserved_at_9e"] = hex(int(bin_str[158 : 160], 2))

    ret["action0"] = hex(int(bin_str[160 : 192], 2))

    ret["action1"] = hex(int(bin_str[192: 224], 2))

    ret["action2"] = hex(int(bin_str[224: 256], 2))

    ret["tag"] = {"info" : "STE only contains actions"}

    return ret


def mlx5_hw_ste_v1_parser(bin_str, raw, verbose):
    entry_type = int(bin_str[0: 8], 2)
    switch = {
        dr_ste_entry_format.DR_STE_TYPE_BWC_BYTE : mlx5_ifc_ste_v1_match_bwc_bits_parser,
        dr_ste_entry_format.DR_STE_TYPE_BWC_DW : mlx5_ifc_ste_v1_match_bwc_bits_parser,
        dr_ste_entry_format.DR_STE_TYPE_MATCH : mlx5_ifc_ste_v1_match_bits_parser,
    }

    parsed_ste = switch[entry_type](bin_str, raw)

    if entry_type is dr_ste_entry_format.DR_STE_TYPE_MATCH and not verbose:
        parsed_ste["tag"] = {}
        
    return parsed_ste

