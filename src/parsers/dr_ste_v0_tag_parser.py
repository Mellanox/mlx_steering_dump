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

from src import dr_prettify
from src.dr_utilities import conv_ip_version
from src.dr_utilities import _val
from src.dr_utilities import add_inner_to_key


def mlx5_ifc_ste_v0_unsupported_tag():
    ret = {}
    ret["UNSUPPORTED_FIELDS"] = 0
    return ret


def mlx5_ifc_ste_v0_eth_l2_src_bits_tag_parser_p(bin_str):
    ret = {}
    ret["smac"] = _val(bin_str[0: 48])
    ret["ethertype"] = _val(bin_str[48: 64])
    ret["qp_type"] = _val(bin_str[64: 66])
    ret["ethertype_filter"] = _val(bin_str[66: 67])
    ret["sx_sniffer"] = _val(bin_str[68: 69])
    ret["force_lb"] = _val(bin_str[69: 70])
    ret["functional_lb"] = _val(bin_str[70: 71])
    ret["port"] = _val(bin_str[71: 72])
    ret["first_prio"] = _val(bin_str[76: 79])
    ret["first_cfi"] = _val(bin_str[79: 80])
    ret["first_vlan_qualifier"] = _val(bin_str[80: 82])
    ret["first_vid"] = _val(bin_str[84: 96])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["ip_version"] = conv_ip_version(_val(bin_str[100: 102]))
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["second_priority"] = _val(bin_str[108: 111])
    ret["second_cfi"] = _val(bin_str[111: 112])
    ret["second_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["second_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l2_dst_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dmac"] = _val(bin_str[0: 48])
    ret["ethertype"] = _val(bin_str[48: 64])
    ret["qp_type"] = _val(bin_str[64: 66])
    ret["ethertype_filter"] = _val(bin_str[66: 67])
    ret["sx_sniffer"] = _val(bin_str[68: 69])
    ret["force_lb"] = _val(bin_str[69: 70])
    ret["functional_lb"] = _val(bin_str[70: 71])
    ret["port"] = _val(bin_str[71: 72])
    ret["first_prio"] = _val(bin_str[76: 79])
    ret["first_cfi"] = _val(bin_str[79: 80])
    ret["first_vlan_qualifier"] = _val(bin_str[80: 82])
    ret["first_vid"] = _val(bin_str[84: 96])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["ip_version"] = conv_ip_version(_val(bin_str[100: 102]))
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["second_priority"] = _val(bin_str[108: 111])
    ret["second_cfi"] = _val(bin_str[111: 112])
    ret["second_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["second_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l2_src_dst_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dmac"] = _val(bin_str[0: 48])
    ret["smac"] = _val(bin_str[48: 96])
    ret["sx_sniffer"] = _val(bin_str[96: 97])
    ret["force_lb"] = _val(bin_str[97: 98])
    ret["functional_lb"] = _val(bin_str[98: 99])
    ret["port"] = _val(bin_str[99: 100])
    ret["ip_version"] = conv_ip_version(_val(bin_str[100: 102]))
    ret["first_prio"] = _val(bin_str[108: 111])
    ret["first_cfi"] = _val(bin_str[111: 112])
    ret["first_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["first_vid"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l3_ipv4_5_tuple_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dst_ip"] = _val(bin_str[0: 32])
    ret["src_ip"] = _val(bin_str[32: 64])
    ret["src_tcp/udp_port"] = _val(bin_str[64: 80])
    ret["dst_tcp/udp_port"] = _val(bin_str[80: 96])
    ret["fragmented"] = _val(bin_str[96: 97])
    ret["first_fragment"] = _val(bin_str[97: 98])
    ret["ip_ecn"] = _val(bin_str[101: 103])
    ret["tcp_ns"] = _val(bin_str[103: 104])
    ret["tcp_cwr"] = _val(bin_str[104: 105])
    ret["tcp_ece"] = _val(bin_str[105: 106])
    ret["tcp_urg"] = _val(bin_str[106: 107])
    ret["tcp_ack"] = _val(bin_str[107: 108])
    ret["tcp_psh"] = _val(bin_str[108: 109])
    ret["tcp_rst"] = _val(bin_str[109: 110])
    ret["tcp_syn"] = _val(bin_str[110: 111])
    ret["tcp_fin"] = _val(bin_str[111: 112])
    ret["ip_dscp"] = _val(bin_str[112: 118])
    ret["ip_protocol"] = _val(bin_str[120: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dst_ip"] = _val(bin_str[0: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l2_tnl_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dmac"] = _val(bin_str[0: 48])
    ret["ethertype"] = _val(bin_str[48: 64])
    ret["l2_tunneling_network_id"] = _val(bin_str[64: 88])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["ip_version"] = conv_ip_version(_val(bin_str[100: 102]))
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["first_prio"] = _val(bin_str[104: 107])
    ret["first_cfi"] = _val(bin_str[107: 108])
    ret["gre_key_flag"] = _val(bin_str[111: 112])
    ret["first_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["first_vid"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p(bin_str):
    ret = {}
    ret["src_ip"] = _val(bin_str[0: 128])
    return ret


def mlx5_ifc_ste_v0_eth_l3_ipv4_misc_bits_tag_parser_p(bin_str):
    ret = {}
    ret["version"] = _val(bin_str[0: 4])
    ret["ihl"] = _val(bin_str[4: 8])
    ret["total_length"] = _val(bin_str[16: 32])
    ret["identification"] = _val(bin_str[32: 48])
    ret["flags"] = _val(bin_str[48: 51])
    ret["fragment_offset"] = _val(bin_str[51: 64])
    ret["ttl"] = _val(bin_str[64: 72])
    ret["checksum"] = _val(bin_str[80: 96])
    return ret


def mlx5_ifc_ste_v0_eth_l4_misc_bits_tag_parser(bin_str):
    ret = {}
    ret["checksum"] = _val(bin_str[0: 16])
    ret["length"] = _val(bin_str[16: 32])
    ret["seq_num"] = _val(bin_str[32: 64])
    ret["ack_num"] = _val(bin_str[64: 96])
    ret["urgent_pointer"] = _val(bin_str[96: 112])
    ret["window_size"] = _val(bin_str[112: 128])
    return ret


def mlx5_ifc_ste_v0_mpls_bits_tag_parser(bin_str):
    ret = {}
    ret["mpls0_label"] = _val(bin_str[0: 20])
    ret["mpls0_exp"] = _val(bin_str[20: 23])
    ret["mpls0_s_bos"] = _val(bin_str[23: 24])
    ret["mpls0_ttl"] = _val(bin_str[24: 32])
    ret["mpls1_label"] = _val(bin_str[32: 64])
    ret["mpls2_label"] = _val(bin_str[64: 96])
    ret["reserved_at_60"] = _val(bin_str[96: 118])
    ret["mpls4_s_bit"] = _val(bin_str[118: 119])
    ret["mpls4_qualifier"] = _val(bin_str[119: 120])
    ret["mpls3_s_bit"] = _val(bin_str[120: 121])
    ret["mpls3_qualifier"] = _val(bin_str[121: 122])
    ret["mpls2_s_bit"] = _val(bin_str[122: 123])
    ret["mpls2_qualifier"] = _val(bin_str[123: 124])
    ret["mpls1_s_bit"] = _val(bin_str[124: 125])
    ret["mpls1_qualifier"] = _val(bin_str[125: 126])
    ret["mpls0_s_bit"] = _val(bin_str[126: 127])
    ret["mpls0_qualifier"] = _val(bin_str[127: 128])
    return ret


def mlx5_ifc_ste_v0_register_0_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_c_0"] = _val(bin_str[0: 32])
    ret["metadata_reg_c_1"] = _val(bin_str[32: 64])
    ret["metadata_reg_c_2"] = _val(bin_str[64: 96])
    ret["metadata_reg_c_3"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_v0_register_1_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_c_4"] = _val(bin_str[0: 32])
    ret["metadata_reg_c_5"] = _val(bin_str[32: 64])
    ret["metadata_reg_c_6"] = _val(bin_str[64: 96])
    ret["metadata_reg_c_7"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_v0_gre_bits_tag_parser(bin_str):
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
    ret["checksum"] = _val(bin_str[32: 48])
    ret["offset"] = _val(bin_str[48: 64])
    ret["gre_key_h"] = _val(bin_str[64: 88])
    ret["gre_key_l"] = _val(bin_str[88: 96])
    ret["seq_num"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_v0_general_purpose_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_a"] = _val(bin_str[0: 32])
    ret["reserved_at_20"] = _val(bin_str[32: 64])
    ret["reserved_at_40"] = _val(bin_str[64: 96])
    ret["reserved_at_60"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_v0_src_gvmi_qp_bits_tag_parser(bin_str):
    ret = {}
    ret["loopback_syndrome"] = _val(bin_str[0: 8])
    ret["reserved_at_8"] = _val(bin_str[8: 16])
    ret["source_gvmi"] = _val(bin_str[16: 32])
    ret["reserved_at_20"] = _val(bin_str[32: 37])
    ret["force_lb"] = _val(bin_str[37: 38])
    ret["functional_lb"] = _val(bin_str[38: 39])
    ret["source_is_requestor"] = _val(bin_str[39: 40])
    ret["source_qp"] = _val(bin_str[40: 64])
    ret["reserved_at_40"] = _val(bin_str[64: 96])
    ret["reserved_at_60"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_v0_flex_parser_bits_tag_parser(bin_str):
    ret = {}
    ret["flex_parser"] = "can't parse fields"
    return ret

def mlx5_ifc_ste_tunnel_header_v0_bits_parser(bin_str):
    ret = {}
    ret["tunnel_header_dw0"] = _val(bin_str[0: 32])
    ret["tunnel_header_dw1"] = _val(bin_str[32: 64])
    return ret


switch_tag_parser = {
    "0x05": [mlx5_ifc_ste_v0_src_gvmi_qp_bits_tag_parser, False],
    "0x0a": [mlx5_ifc_ste_v0_eth_l2_tnl_bits_tag_parser_p, True],
    "0x06": [mlx5_ifc_ste_v0_eth_l2_dst_bits_tag_parser_p, False],
    "0x07": [mlx5_ifc_ste_v0_eth_l2_dst_bits_tag_parser_p, True],
    "0x1b": [mlx5_ifc_ste_v0_eth_l2_dst_bits_tag_parser_p, False],
    "0x08": [mlx5_ifc_ste_v0_eth_l2_src_bits_tag_parser_p, False],
    "0x09": [mlx5_ifc_ste_v0_eth_l2_src_bits_tag_parser_p, True],
    "0x1c": [mlx5_ifc_ste_v0_eth_l2_src_bits_tag_parser_p, False],
    "0x36": [mlx5_ifc_ste_v0_eth_l2_src_dst_bits_tag_parser_p, False],
    "0x37": [mlx5_ifc_ste_v0_eth_l2_src_dst_bits_tag_parser_p, True],
    "0x38": [mlx5_ifc_ste_v0_eth_l2_src_dst_bits_tag_parser_p, False],
    "0x0d": [mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, False],
    "0x0e": [mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, True],
    "0x1e": [mlx5_ifc_ste_v0_eth_l3_ipv6_dst_bits_tag_parser_p, False],
    "0x0f": [mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p, False],
    "0x10": [mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p, True],
    "0x1f": [mlx5_ifc_ste_v0_eth_l3_ipv6_src_bits_tag_parser_p, False],
    "0x11": [mlx5_ifc_ste_v0_eth_l3_ipv4_5_tuple_bits_tag_parser_p, False],
    "0x12": [mlx5_ifc_ste_v0_eth_l3_ipv4_5_tuple_bits_tag_parser_p, True],
    "0x20": [mlx5_ifc_ste_v0_eth_l3_ipv4_5_tuple_bits_tag_parser_p, False],
    "0x29": [mlx5_ifc_ste_v0_eth_l3_ipv4_misc_bits_tag_parser_p, False],
    "0x2a": [mlx5_ifc_ste_v0_eth_l3_ipv4_misc_bits_tag_parser_p, True],
    "0x2b": [mlx5_ifc_ste_v0_eth_l3_ipv4_misc_bits_tag_parser_p, False],
    "0x2c": [mlx5_ifc_ste_v0_eth_l4_misc_bits_tag_parser, False],
    "0x2d": [mlx5_ifc_ste_v0_eth_l4_misc_bits_tag_parser, True],
    "0x2e": [mlx5_ifc_ste_v0_eth_l4_misc_bits_tag_parser, False],
    "0x15": [mlx5_ifc_ste_v0_mpls_bits_tag_parser, False],
    "0x24": [mlx5_ifc_ste_v0_mpls_bits_tag_parser, True],
    "0x25": [mlx5_ifc_ste_v0_mpls_bits_tag_parser, False],
    "0x16": [mlx5_ifc_ste_v0_gre_bits_tag_parser, False],
    "0x18": [mlx5_ifc_ste_v0_general_purpose_bits_tag_parser, False],
    "0x2f": [mlx5_ifc_ste_v0_register_0_bits_tag_parser, False],
    "0x30": [mlx5_ifc_ste_v0_register_1_bits_tag_parser, False],
    "0x22": [mlx5_ifc_ste_v0_flex_parser_bits_tag_parser, False],
    "0x23": [mlx5_ifc_ste_v0_flex_parser_bits_tag_parser, False],
    "0x34": [mlx5_ifc_ste_tunnel_header_v0_bits_parser, False],
}

def mlx5_ste_v0_tag_parser(lookup_type, tag, raw):
    if lookup_type not in switch_tag_parser.keys():
        # Silent fail lookup type is not supported
        return {}

    if lookup_type not in switch_tag_parser.keys():
        return mlx5_ifc_ste_v0_unsupported_tag()

    func, inner = switch_tag_parser[lookup_type]
    parsed_tag = func(tag)

    if not raw and (lookup_type not in ["0x22", 0x23]):
        parsed_tag = dr_prettify.prettify_tag(parsed_tag)

    if inner:
        add_inner_to_key(parsed_tag)

    return parsed_tag
