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

from src.dr_utilities import dr_ste_v1_lu_type
from src.dr_utilities import _val
from src.dr_utilities import add_inner_to_key
import src.dr_prettify as dr_prettify
from src.parsers.dr_ste_v0_tag_parser import mlx5_ifc_ste_v0_general_purpose_bits_tag_parser,\
	mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, mlx5_ifc_ste_v0_mpls_bits_tag_parser,\
	mlx5_ifc_ste_v0_register_0_bits_tag_parser, mlx5_ifc_ste_v0_register_1_bits_tag_parser,\
	mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p


def mlx5_ifc_ste_eth_l2_src_v1_bits_tag_parser_p(bin_str):
	ret = {}
	ret["reserved_at_0"] = _val(bin_str[0: 1])
	ret["sx_sniffer"] = _val(bin_str[1: 2])
	ret["functional_loopback"] = _val(bin_str[2: 3])
	ret["ip_fragmented"] = _val(bin_str[3: 4])
	ret["qp_type"] = _val(bin_str[4: 6])
	ret["encapsulation_type"] = _val(bin_str[6: 8])
	ret["port"] = _val(bin_str[8: 10])
	ret["l3_type"] = _val(bin_str[10: 12])
	ret["l4_type"] = _val(bin_str[12: 14])
	ret["first_vlan_qualifier"] = _val(bin_str[14: 16])
	ret["first_priority"] = _val(bin_str[16: 19])
	ret["first_cfi"] = _val(bin_str[19: 20])
	ret["first_vlan_id"] = _val(bin_str[20: 32])
	ret["smac"] = _val(bin_str[32: 80])
	ret["l3_ethertype"] = _val(bin_str[80: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 102])
	ret["tcp_syn"] = _val(bin_str[102: 103])
	ret["reserved_at_67"] = _val(bin_str[103: 106])
	ret["force_loopback"] = _val(bin_str[106: 107])
	ret["l2_ok"] = _val(bin_str[107: 108])
	ret["l3_ok"] = _val(bin_str[108: 109])
	ret["l4_ok"] = _val(bin_str[109: 110])
	ret["second_vlan_qualifier"] = _val(bin_str[110: 112])
	ret["second_priority"] = _val(bin_str[112: 115])
	ret["second_cfi"] = _val(bin_str[115: 116])
	ret["second_vlan_id"] = _val(bin_str[116: 128])
	return ret


def mlx5_ifc_ste_eth_l2_dst_v1_bits_tag_parser_p(bin_str):
	ret = {}
	ret["reserved_at_0"] = _val(bin_str[0: 1])
	ret["sx_sniffer"] = _val(bin_str[1: 2])
	ret["functional_lb"] = _val(bin_str[2: 3])
	ret["ip_fragmented"] = _val(bin_str[3: 4])
	ret["qp_type"] = _val(bin_str[4: 6])
	ret["encapsulation_type"] = _val(bin_str[6: 8])
	ret["port"] = _val(bin_str[8: 10])
	ret["l3_type"] = _val(bin_str[10: 12])
	ret["l4_type"] = _val(bin_str[12: 14])
	ret["first_vlan_qualifier"] = _val(bin_str[14: 16])
	ret["first_priority"] = _val(bin_str[16: 19])
	ret["first_cfi"] = _val(bin_str[19: 20])
	ret["first_vlan_id"] = _val(bin_str[20: 32])
	ret["dmac"] = _val(bin_str[32: 80])
	ret["l3_ethertype"] = _val(bin_str[80: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 102])
	ret["tcp_syn"] = _val(bin_str[102: 103])
	ret["reserved_at_67"] = _val(bin_str[103: 106])
	ret["force_lb"] = _val(bin_str[106: 107])
	ret["l2_ok"] = _val(bin_str[107: 108])
	ret["l3_ok"] = _val(bin_str[108: 109])
	ret["l4_ok"] = _val(bin_str[109: 110])
	ret["second_vlan_qualifier"] = _val(bin_str[110: 112])
	ret["second_priority"] = _val(bin_str[112: 115])
	ret["second_cfi"] = _val(bin_str[115: 116])
	ret["second_vlan_id"] = _val(bin_str[116: 128])
	return ret


def mlx5_ifc_ste_eth_l2_src_dst_v1_bits_tag_parser_p(bin_str):
	ret = {}
	ret["dmac_47_16"] = _val(bin_str[0: 32] + bin_str[64: 80])
	ret["smac_47_16"] = _val(bin_str[32: 64] + bin_str[112: 128])
	ret["reserved_at_50"] = _val(bin_str[80: 82])
	ret["functional_lb"] = _val(bin_str[82: 83])
	ret["reserved_at_53"] = _val(bin_str[83: 88])
	ret["port"] = _val(bin_str[88: 90])
	ret["l3_type"] = _val(bin_str[90: 92])
	ret["reserved_at_5c"] = _val(bin_str[92: 94])
	ret["first_vlan_qualifier"] = _val(bin_str[94: 96])
	ret["first_priority"] = _val(bin_str[96: 99])
	ret["first_cfi"] = _val(bin_str[99: 100])
	ret["first_vlan_id"] = _val(bin_str[100: 112])
	return ret


def mlx5_ifc_ste_eth_l3_ipv4_5_tuple_v1_bits_tag_parser_p(bin_str):
	ret = {}
	ret["src_ip"] = _val(bin_str[0: 32])
	ret["dst_ip"] = _val(bin_str[32: 64])
	ret["src_tcp/udp_port"] = _val(bin_str[64: 80])
	ret["dst_tcp/udp_port"] = _val(bin_str[80: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 100])
	ret["l4_ok"] = _val(bin_str[100: 101])
	ret["l3_ok"] = _val(bin_str[101: 102])
	ret["fragmented"] = _val(bin_str[102: 103])
	ret["tcp_ns"] = _val(bin_str[103: 104])
	ret["tcp_cwr"] = _val(bin_str[104: 105])
	ret["tcp_ece"] = _val(bin_str[105: 106])
	ret["tcp_urg"] = _val(bin_str[106: 107])
	ret["tcp_ack"] = _val(bin_str[107: 108])
	ret["tcp_psh"] = _val(bin_str[108: 109])
	ret["tcp_rst"] = _val(bin_str[109: 110])
	ret["tcp_syn"] = _val(bin_str[110: 111])
	ret["tcp_fin"] = _val(bin_str[111: 112])
	ret["dscp"] = _val(bin_str[112: 118])
	ret["ecn"] = _val(bin_str[118: 120])
	ret["protocol"] = _val(bin_str[120: 128])
	return ret


def mlx5_ifc_ste_eth_l2_tnl_v1_bits_tag_parser_p(bin_str):
	ret = {}
	ret["l2_tunneling_network_id"] = _val(bin_str[0: 32])
	ret["dmac"] = _val(bin_str[32: 80])
	ret["l3_ethertype"] = _val(bin_str[80: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 99])
	ret["ip_fragmented"] = _val(bin_str[99: 100])
	ret["reserved_at_64"] = _val(bin_str[100: 102])
	ret["encp_type"] = _val(bin_str[102: 104])
	ret["reserved_at_68"] = _val(bin_str[104: 106])
	ret["l3_type"] = _val(bin_str[106: 108])
	ret["l4_type"] = _val(bin_str[108: 110])
	ret["first_vlan_qualifier"] = _val(bin_str[110: 112])
	ret["first_priority"] = _val(bin_str[112: 115])
	ret["first_cfi"] = _val(bin_str[115: 116])
	ret["first_vlan_id"] = _val(bin_str[116: 128])
	return ret


def mlx5_ifc_ste_eth_l3_ipv4_misc_v1_bits_tag_parser(bin_str):
	ret = {}
	ret["identification"] = _val(bin_str[0: 16])
	ret["flags"] = _val(bin_str[16: 19])
	ret["fragment_offset"] = _val(bin_str[19: 32])
	ret["total_length"] = _val(bin_str[32: 48])
	ret["checksum"] = _val(bin_str[48: 64])
	ret["version"] = _val(bin_str[64: 68])
	ret["ihl"] = _val(bin_str[68: 72])
	ret["time_to_live"] = _val(bin_str[72: 80])
	ret["reserved_at_50"] = _val(bin_str[80: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 124])
	ret["voq_internal_prio"] = _val(bin_str[124: 128])
	return ret


def mlx5_ifc_ste_eth_l4_v1_bits_tag_parser(bin_str):
	ret = {}
	ret["ipv6_version"] = _val(bin_str[0: 4])
	ret["reserved_at_4"] = _val(bin_str[4: 8])
	ret["dscp"] = _val(bin_str[8: 14])
	ret["ecn"] = _val(bin_str[14: 16])
	ret["ipv6_hop_limit"] = _val(bin_str[16: 24])
	ret["protocol"] = _val(bin_str[24: 32])
	ret["src_port"] = _val(bin_str[32: 48])
	ret["dst_port"] = _val(bin_str[48: 64])
	ret["first_fragment"] = _val(bin_str[64: 65])
	ret["reserved_at_41"] = _val(bin_str[65: 76])
	ret["flow_label"] = _val(bin_str[76: 96])
	ret["tcp_data_offset"] = _val(bin_str[96: 100])
	ret["l4_ok"] = _val(bin_str[100: 101])
	ret["l3_ok"] = _val(bin_str[101: 102])
	ret["fragmented"] = _val(bin_str[102: 103])
	ret["tcp_ns"] = _val(bin_str[103: 104])
	ret["tcp_cwr"] = _val(bin_str[104: 105])
	ret["tcp_ece"] = _val(bin_str[105: 106])
	ret["tcp_urg"] = _val(bin_str[106: 107])
	ret["tcp_ack"] = _val(bin_str[107: 108])
	ret["tcp_psh"] = _val(bin_str[108: 109])
	ret["tcp_rst"] = _val(bin_str[109: 110])
	ret["tcp_syn"] = _val(bin_str[110: 111])
	ret["tcp_fin"] = _val(bin_str[111: 112])
	ret["ipv6_paylen"] = _val(bin_str[112: 128])
	return ret


def mlx5_ifc_ste_eth_l4_misc_v1_bits_tag_parser(bin_str):
	ret = {}
	ret["window_size"] = _val(bin_str[0: 16])
	ret["urgent_pointer"] = _val(bin_str[16: 32])
	ret["ack_num"] = _val(bin_str[32: 64])
	ret["seq_num"] = _val(bin_str[64: 96])
	ret["length"] = _val(bin_str[96: 112])
	ret["checksum"] = _val(bin_str[112: 128])
	return ret


def mlx5_ifc_ste_gre_v1_bits_tag_parser(bin_str):
	ret = {}
	ret["gre_c_present"] = _val(bin_str[0: 1])
	ret["reserved_at_1"] = _val(bin_str[1: 2])
	ret["gre_k_present"] = _val(bin_str[2: 3])
	ret["gre_s_present"] = _val(bin_str[3: 4])
	ret["strict_src_route"] = _val(bin_str[4: 5])
	ret["recur"] = _val(bin_str[5: 8])
	ret["flags"] = _val(bin_str[8: 13])
	ret["version"] = _val(bin_str[13: 16])
	ret["gre_protocol"] = _val(bin_str[16: 32])
	ret["reserved_at_20"] = _val(bin_str[32: 64])
	ret["gre_key_h"] = _val(bin_str[64: 88])
	ret["gre_key_l"] = _val(bin_str[88: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 128])
	return ret


def mlx5_ifc_ste_src_gvmi_qp_v1_bits_tag_parser(bin_str):
	ret = {}
	ret["loopback_synd"] = _val(bin_str[0: 8])
	ret["reserved_at_8"] = _val(bin_str[8: 15])
	ret["defal_lb"] = _val(bin_str[15: 16])
	ret["source_gvmi"] = _val(bin_str[16: 32])
	ret["force_lb"] = _val(bin_str[32: 33])
	ret["reserved_at_21"] = _val(bin_str[33: 34])
	ret["source_is_requestor"] = _val(bin_str[34: 35])
	ret["reserved_at_23"] = _val(bin_str[35: 40])
	ret["source_qp"] = _val(bin_str[40: 64])
	ret["reserved_at_40"] = _val(bin_str[64: 96])
	ret["reserved_at_60"] = _val(bin_str[96: 128])
	return ret


def mlx5_ste_v1_tag_parser(entry_format, tag, raw):
	switch = {
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_I: [mlx5_ifc_ste_eth_l2_src_dst_v1_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_O: [mlx5_ifc_ste_eth_l2_src_dst_v1_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_I:  [mlx5_ifc_ste_eth_l2_dst_v1_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_O:  [mlx5_ifc_ste_eth_l2_dst_v1_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_SRC_I: [mlx5_ifc_ste_eth_l2_src_v1_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_SRC_O: [mlx5_ifc_ste_eth_l2_src_v1_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL2_TNL: [mlx5_ifc_ste_eth_l2_tnl_v1_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_I: [mlx5_ifc_ste_eth_l3_ipv4_5_tuple_v1_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_O: [mlx5_ifc_ste_eth_l3_ipv4_5_tuple_v1_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_I: [mlx5_ifc_ste_eth_l3_ipv4_misc_v1_bits_tag_parser, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_O: [mlx5_ifc_ste_eth_l3_ipv4_misc_v1_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL4_I: [mlx5_ifc_ste_eth_l4_v1_bits_tag_parser, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL4_MISC_I: [mlx5_ifc_ste_eth_l4_v1_bits_tag_parser, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL4_MISC_O: [mlx5_ifc_ste_eth_l4_misc_v1_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_ETHL4_O: [mlx5_ifc_ste_eth_l4_v1_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_GENERAL_PURPOSE: [mlx5_ifc_ste_v0_general_purpose_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_GRE: [mlx5_ifc_ste_gre_v1_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_IPV6_DES_I: [mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_IPV6_DES_O: [mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_IPV6_SRC_I: [mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_IPV6_SRC_O: [mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_MPLS_I: [mlx5_ifc_ste_v0_mpls_bits_tag_parser, True],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_MPLS_O: [mlx5_ifc_ste_v0_mpls_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_SRC_QP_GVMI: [mlx5_ifc_ste_src_gvmi_qp_v1_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0: [mlx5_ifc_ste_v0_register_0_bits_tag_parser, False],
        dr_ste_v1_lu_type.DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1: [mlx5_ifc_ste_v0_register_1_bits_tag_parser, False],
    }

	if entry_format not in switch.keys():
		# Silent fail lookup type is not supported
		return {}

	func, inner = switch[entry_format]
	parsed_tag = func(tag)

	if not raw:
		parsed_tag = dr_prettify.prettify_tag(parsed_tag)

	if inner:
		add_inner_to_key(parsed_tag)

	return parsed_tag
