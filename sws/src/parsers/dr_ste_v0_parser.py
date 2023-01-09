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

from src.parsers.dr_ste_v0_tag_parser import mlx5_ste_v0_tag_parser
from src.dr_utilities import _val


# HW_STE parsing funcs
def mlx5_ifc_ste_v0_unsupported_ste():
    ret = {}
    ret["tag"] = {"UNSUPPORTED_FIELDS": 0x0}
    return ret


def mlx5_ifc_ste_v0_rx_steering_mult_bits_parser(bin_str, raw):
    ret = {}
    ret["entry_type"] = _val(bin_str[0: 4])
    ret["reserved_at_4"] = _val(bin_str[4: 8])
    ret["entry_sub_type"] = _val(bin_str[8: 16])
    ret["byte_mask"] = _val(bin_str[16: 32])
    ret["next_table_base_63_48"] = _val(bin_str[32: 48])
    ret["next_lu_type"] = _val(bin_str[48: 56])
    ret["next_table_base_39_32_size"] = _val(bin_str[56: 64])
    ret["next_table_base_31_5_size"] = _val(bin_str[64: 91])
    ret["linear_hash_enable"] = _val(bin_str[91: 92])
    ret["reserved_at_5c"] = _val(bin_str[92: 94])
    ret["next_table_rank"] = _val(bin_str[94: 96])
    ret["member_count"] = _val(bin_str[96: 112])
    ret["gvmi"] = _val(bin_str[112: 128])
    ret["qp_list_pointer"] = _val(bin_str[128: 160])
    ret["reserved_at_a0"] = _val(bin_str[160: 161])
    ret["tunneling_action"] = _val(bin_str[161: 164])
    ret["action_description"] = _val(bin_str[164: 168])
    ret["reserved_at_a8"] = _val(bin_str[168: 176])
    ret["counter_trigger_15_0"] = _val(bin_str[176: 192])
    ret["miss_address_63_48"] = _val(bin_str[192: 208])
    ret["counter_trigger_23_16"] = _val(bin_str[208: 216])
    ret["miss_address_39_32"] = _val(bin_str[216: 224])
    ret["miss_address_31_6"] = _val(bin_str[224: 250])
    ret["learning_point"] = _val(bin_str[250: 251])
    ret["fail_on_error"] = _val(bin_str[251: 252])
    ret["match_polarity"] = _val(bin_str[252: 253])
    ret["mask_mode"] = _val(bin_str[253: 254])
    ret["miss_rank"] = _val(bin_str[254: 256])
    ret["tag"] = mlx5_ste_v0_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


def mlx5_ifc_ste_v0_sx_transmit_bits_parser(bin_str, raw):
    ret = {}
    ret["entry_type"] = _val(bin_str[0: 4])
    ret["reserved_at_4"] = _val(bin_str[4: 8])
    ret["entry_sub_type"] = _val(bin_str[8: 16])
    ret["byte_mask"] = _val(bin_str[16: 32])
    ret["next_table_base_63_48"] = _val(bin_str[32: 48])
    ret["next_lu_type"] = _val(bin_str[48: 56])
    ret["next_table_base_39_32_size"] = _val(bin_str[56: 64])
    ret["next_table_base_31_5_size"] = _val(bin_str[64: 91])
    ret["linear_hash_enable"] = _val(bin_str[91: 92])
    ret["reserved_at_5c"] = _val(bin_str[92: 94])
    ret["next_table_rank"] = _val(bin_str[94: 96])
    ret["sx_wire"] = _val(bin_str[96: 97])
    ret["sx_func_lb"] = _val(bin_str[97: 98])
    ret["sx_sniffer"] = _val(bin_str[98: 99])
    ret["sx_wire_enable"] = _val(bin_str[99: 100])
    ret["sx_func_lb_enable"] = _val(bin_str[100: 101])
    ret["sx_sniffer_enable"] = _val(bin_str[101: 102])
    ret["action_type"] = _val(bin_str[102: 105])
    ret["reserved_at_69"] = _val(bin_str[105: 106])
    ret["action_description"] = _val(bin_str[106: 112])
    ret["gvmi"] = _val(bin_str[112: 128])
    ret["encap_pointer_vlan_data"] = _val(bin_str[128: 160])
    ret["loopback_syndome_en"] = _val(bin_str[160: 168])
    ret["loopback_syndome"] = _val(bin_str[168: 176])
    ret["counter_trigger"] = _val(bin_str[176: 192])
    ret["miss_address_63_48"] = _val(bin_str[192: 208])
    ret["counter_trigger_23_16"] = _val(bin_str[208: 216])
    ret["miss_address_39_32"] = _val(bin_str[216: 224])
    ret["miss_address_31_6"] = _val(bin_str[224: 250])
    ret["learning_point"] = _val(bin_str[250: 251])
    ret["go_back"] = _val(bin_str[251: 252])
    ret["match_polarity"] = _val(bin_str[252: 253])
    ret["mask_mode"] = _val(bin_str[253: 254])
    ret["miss_rank"] = _val(bin_str[254: 256])
    ret["tag"] = mlx5_ste_v0_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


def mlx5_ifc_ste_v0_modify_packet_bits_parser(bin_str, raw):
    ret = {}
    ret["entry_type"] = _val(bin_str[0: 4])
    ret["reserved_at_4"] = _val(bin_str[4: 8])
    ret["entry_sub_type"] = _val(bin_str[8: 16])
    ret["byte_mask"] = _val(bin_str[16: 32])
    ret["next_table_base_63_48"] = _val(bin_str[32: 48])
    ret["next_lu_type"] = _val(bin_str[48: 56])
    ret["next_table_base_39_32_size"] = _val(bin_str[56: 64])
    ret["next_table_base_31_5_size"] = _val(bin_str[64: 91])
    ret["linear_hash_enable"] = _val(bin_str[91: 92])
    ret["reserved_at_5c"] = _val(bin_str[92: 94])
    ret["next_table_rank"] = _val(bin_str[94: 96])
    ret["number_of_re_write_actions"] = _val(bin_str[96: 112])
    ret["gvmi"] = _val(bin_str[112: 128])
    ret["header_re_write_actions_pointer"] = _val(bin_str[128: 160])
    ret["reserved_at_a0"] = _val(bin_str[160: 161])
    ret["tunneling_action"] = _val(bin_str[161: 164])
    ret["action_description"] = _val(bin_str[164: 168])
    ret["reserved_at_a8"] = _val(bin_str[168: 176])
    ret["counter_trigger_15_0"] = _val(bin_str[176: 192])
    ret["miss_address_63_48"] = _val(bin_str[192: 208])
    ret["counter_trigger_23_16"] = _val(bin_str[208: 216])
    ret["miss_address_39_32"] = _val(bin_str[216: 224])
    ret["miss_address_31_6"] = _val(bin_str[224: 250])
    ret["learning_point"] = _val(bin_str[250: 251])
    ret["fail_on_error"] = _val(bin_str[251: 252])
    ret["match_polarity"] = _val(bin_str[252: 253])
    ret["mask_mode"] = _val(bin_str[253: 254])
    ret["miss_rank"] = _val(bin_str[254: 256])
    ret["tag"] = mlx5_ste_v0_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


switch_ste_type = {
    1: mlx5_ifc_ste_v0_sx_transmit_bits_parser,
    2: mlx5_ifc_ste_v0_rx_steering_mult_bits_parser,
    6: mlx5_ifc_ste_v0_modify_packet_bits_parser
}


def mlx5_hw_ste_v0_parser(bin_str, raw):
    entry_type = int(bin_str[0: 4], 2)
    if entry_type in switch_ste_type.keys():
        return switch_ste_type[entry_type](bin_str, raw)
    else:
        return mlx5_ifc_ste_v0_unsupported_ste()
