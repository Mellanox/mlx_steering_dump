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


def conv_ip_version(version):
    if eval(version) == 1:
        return "0x4"
    elif eval(version) == 2:
        return "0x6"
    return "0x0"


def _val(field_str):
    nibbels = str(int(len(field_str) / 4))
    fmt = "0x{:0" + nibbels + "x}"
    return fmt.format(int(field_str, 2))


def add_inner_to_key(in_dict):
    for k, v in list(in_dict.items()):
        in_dict["inner_" + k] = v
        del in_dict[k]


def mlx5_ifc_ste_eth_l2_src_bits_tag_parser(bin_str):
    ret = {}
    ret["smac_47_16"] = _val(bin_str[0: 32])
    ret["smac_15_0"] = _val(bin_str[32: 48])
    ret["l3_ethertype"] = _val(bin_str[48: 64])
    ret["qp_type"] = _val(bin_str[64: 66])
    ret["ethertype_filter"] = _val(bin_str[66: 67])
    ret["reserved_at_43"] = _val(bin_str[67: 68])
    ret["sx_sniffer"] = _val(bin_str[68: 69])
    ret["force_lb"] = _val(bin_str[69: 70])
    ret["functional_lb"] = _val(bin_str[70: 71])
    ret["port"] = _val(bin_str[71: 72])
    ret["reserved_at_48"] = _val(bin_str[72: 76])
    ret["first_priority"] = _val(bin_str[76: 79])
    ret["first_cfi"] = _val(bin_str[79: 80])
    ret["first_vlan_qualifier"] = _val(bin_str[80: 82])
    ret["reserved_at_52"] = _val(bin_str[82: 84])
    ret["first_vlan_id"] = _val(bin_str[84: 96])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["l3_type"] = _val(bin_str[100: 102])
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["reserved_at_68"] = _val(bin_str[104: 108])
    ret["second_priority"] = _val(bin_str[108: 111])
    ret["second_cfi"] = _val(bin_str[111: 112])
    ret["second_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["reserved_at_72"] = _val(bin_str[114: 116])
    ret["second_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_eth_l2_src_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l2_dst_bits_tag_parser(bin_str):
    ret = {}
    ret["dmac_47_16"] = _val(bin_str[0: 32])
    ret["dmac_15_0"] = _val(bin_str[32: 48])
    ret["l3_ethertype"] = _val(bin_str[48: 64])
    ret["qp_type"] = _val(bin_str[64: 66])
    ret["ethertype_filter"] = _val(bin_str[66: 67])
    ret["reserved_at_43"] = _val(bin_str[67: 68])
    ret["sx_sniffer"] = _val(bin_str[68: 69])
    ret["force_lb"] = _val(bin_str[69: 70])
    ret["functional_lb"] = _val(bin_str[70: 71])
    ret["port"] = _val(bin_str[71: 72])
    ret["reserved_at_48"] = _val(bin_str[72: 76])
    ret["first_priority"] = _val(bin_str[76: 79])
    ret["first_cfi"] = _val(bin_str[79: 80])
    ret["first_vlan_qualifier"] = _val(bin_str[80: 82])
    ret["reserved_at_52"] = _val(bin_str[82: 84])
    ret["first_vlan_id"] = _val(bin_str[84: 96])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["l3_type"] = _val(bin_str[100: 102])
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["reserved_at_68"] = _val(bin_str[104: 108])
    ret["second_priority"] = _val(bin_str[108: 111])
    ret["second_cfi"] = _val(bin_str[111: 112])
    ret["second_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["reserved_at_72"] = _val(bin_str[114: 116])
    ret["second_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_eth_l2_dst_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l2_src_dst_bits_tag_parser(bin_str):
    ret = {}
    ret["dmac_47_16"] = _val(bin_str[0: 32])
    ret["dmac_15_0"] = _val(bin_str[32: 48])
    ret["smac_47_32"] = _val(bin_str[48: 64])
    ret["smac_31_0"] = _val(bin_str[64: 96])
    ret["sx_sniffer"] = _val(bin_str[96: 97])
    ret["force_lb"] = _val(bin_str[97: 98])
    ret["functional_lb"] = _val(bin_str[98: 99])
    ret["port"] = _val(bin_str[99: 100])
    ret["l3_type"] = _val(bin_str[100: 102])
    ret["reserved_at_66"] = _val(bin_str[102: 108])
    ret["first_priority"] = _val(bin_str[108: 111])
    ret["first_cfi"] = _val(bin_str[111: 112])
    ret["first_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["reserved_at_72"] = _val(bin_str[114: 116])
    ret["first_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_eth_l2_src_dst_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l3_ipv4_5_tuple_bits_tag_parser(bin_str):
    ret = {}
    ret["destination_address"] = _val(bin_str[0: 32])
    ret["source_address"] = _val(bin_str[32: 64])
    ret["source_port"] = _val(bin_str[64: 80])
    ret["destination_port"] = _val(bin_str[80: 96])
    ret["fragmented"] = _val(bin_str[96: 97])
    ret["first_fragment"] = _val(bin_str[97: 98])
    ret["reserved_at_62"] = _val(bin_str[98: 100])
    ret["reserved_at_64"] = _val(bin_str[100: 101])
    ret["ecn"] = _val(bin_str[101: 103])
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
    ret["reserved_at_76"] = _val(bin_str[118: 120])
    ret["protocol"] = _val(bin_str[120: 128])
    return ret


def mlx5_ifc_ste_eth_l3_ipv4_5_tuple_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l3_ipv6_dst_bits_tag_parser(bin_str):
    ret = {}
    ret["dst_ip_127_96"] = _val(bin_str[0: 32])
    ret["dst_ip_95_64"] = _val(bin_str[32: 64])
    ret["dst_ip_63_32"] = _val(bin_str[64: 96])
    ret["dst_ip_31_0"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_eth_l3_ipv6_dst_bits_tag_parser_p(bin_str):
    ret = {}
    ret["dst_ip"] = _val(bin_str[0: 128])
    return ret


def mlx5_ifc_ste_eth_l2_tnl_bits_tag_parser(bin_str):
    ret = {}
    ret["dmac_47_16"] = _val(bin_str[0: 32])
    ret["dmac_15_0"] = _val(bin_str[32: 48])
    ret["l3_ethertype"] = _val(bin_str[48: 64])
    ret["l2_tunneling_network_id"] = _val(bin_str[64: 96])
    ret["ip_fragmented"] = _val(bin_str[96: 97])
    ret["tcp_syn"] = _val(bin_str[97: 98])
    ret["encp_type"] = _val(bin_str[98: 100])
    ret["l3_type"] = _val(bin_str[100: 102])
    ret["l4_type"] = _val(bin_str[102: 104])
    ret["first_priority"] = _val(bin_str[104: 107])
    ret["first_cfi"] = _val(bin_str[107: 108])
    ret["reserved_at_6c"] = _val(bin_str[108: 111])
    ret["gre_key_flag"] = _val(bin_str[111: 112])
    ret["first_vlan_qualifier"] = _val(bin_str[112: 114])
    ret["reserved_at_72"] = _val(bin_str[114: 116])
    ret["first_vlan_id"] = _val(bin_str[116: 128])
    return ret


def mlx5_ifc_ste_eth_l2_tnl_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l3_ipv6_src_bits_tag_parser(bin_str):
    ret = {}
    ret["src_ip_127_96"] = _val(bin_str[0: 32])
    ret["src_ip_95_64"] = _val(bin_str[32: 64])
    ret["src_ip_63_32"] = _val(bin_str[64: 96])
    ret["src_ip_31_0"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_eth_l3_ipv6_src_bits_tag_parser_p(bin_str):
    ret = {}
    ret["src_ip"] = _val(bin_str[0: 128])
    return ret


def mlx5_ifc_ste_eth_l3_ipv4_misc_bits_tag_parser(bin_str):
    ret = {}
    ret["version"] = _val(bin_str[0: 4])
    ret["ihl"] = _val(bin_str[4: 8])
    ret["reserved_at_8"] = _val(bin_str[8: 16])
    ret["total_length"] = _val(bin_str[16: 32])
    ret["identification"] = _val(bin_str[32: 48])
    ret["flags"] = _val(bin_str[48: 51])
    ret["fragment_offset"] = _val(bin_str[51: 64])
    ret["time_to_live"] = _val(bin_str[64: 72])
    ret["reserved_at_48"] = _val(bin_str[72: 80])
    ret["checksum"] = _val(bin_str[80: 96])
    ret["reserved_at_60"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_eth_l3_ipv4_misc_bits_tag_parser_p(bin_str):
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


def mlx5_ifc_ste_eth_l4_bits_tag_parser(bin_str):
    ret = {}
    ret["fragmented"] = _val(bin_str[0: 1])
    ret["first_fragment"] = _val(bin_str[1: 2])
    ret["reserved_at_2"] = _val(bin_str[2: 8])
    ret["protocol"] = _val(bin_str[8: 16])
    ret["dst_port"] = _val(bin_str[16: 32])
    ret["ipv6_version"] = _val(bin_str[32: 36])
    ret["reserved_at_24"] = _val(bin_str[36: 37])
    ret["ecn"] = _val(bin_str[37: 39])
    ret["tcp_ns"] = _val(bin_str[39: 40])
    ret["tcp_cwr"] = _val(bin_str[40: 41])
    ret["tcp_ece"] = _val(bin_str[41: 42])
    ret["tcp_urg"] = _val(bin_str[42: 43])
    ret["tcp_ack"] = _val(bin_str[43: 44])
    ret["tcp_psh"] = _val(bin_str[44: 45])
    ret["tcp_rst"] = _val(bin_str[45: 46])
    ret["tcp_syn"] = _val(bin_str[46: 47])
    ret["tcp_fin"] = _val(bin_str[47: 48])
    ret["src_port"] = _val(bin_str[48: 64])
    ret["ipv6_payload_length"] = _val(bin_str[64: 80])
    ret["ipv6_hop_limit"] = _val(bin_str[80: 88])
    ret["dscp"] = _val(bin_str[88: 94])
    ret["reserved_at_5e"] = _val(bin_str[94: 96])
    ret["tcp_data_offset"] = _val(bin_str[96: 100])
    ret["reserved_at_64"] = _val(bin_str[100: 108])
    ret["flow_label"] = _val(bin_str[108: 128])
    return ret


def mlx5_ifc_ste_eth_l4_misc_bits_tag_parser(bin_str):
    ret = {}
    ret["checksum"] = _val(bin_str[0: 16])
    ret["length"] = _val(bin_str[16: 32])
    ret["seq_num"] = _val(bin_str[32: 64])
    ret["ack_num"] = _val(bin_str[64: 96])
    ret["urgent_pointer"] = _val(bin_str[96: 112])
    ret["window_size"] = _val(bin_str[112: 128])
    return ret


def mlx5_ifc_ste_mpls_bits_tag_parser(bin_str):
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


def mlx5_ifc_ste_register_0_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_c_0"] = _val(bin_str[0: 32])
    ret["metadata_reg_c_1"] = _val(bin_str[32: 64])
    ret["metadata_reg_c_2"] = _val(bin_str[64: 96])
    ret["metadata_reg_c_3"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_register_1_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_c_4"] = _val(bin_str[0: 32])
    ret["metadata_reg_c_5"] = _val(bin_str[32: 64])
    ret["metadata_reg_c_6"] = _val(bin_str[64: 96])
    ret["metadata_reg_c_7"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_gre_bits_tag_parser(bin_str):
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


def mlx5_ifc_ste_general_purpose_bits_tag_parser(bin_str):
    ret = {}
    ret["metadata_reg_a"] = _val(bin_str[0: 32])
    ret["reserved_at_20"] = _val(bin_str[32: 64])
    ret["reserved_at_40"] = _val(bin_str[64: 96])
    ret["reserved_at_60"] = _val(bin_str[96: 128])
    return ret


def mlx5_ifc_ste_src_gvmi_qp_bits_tag_parser(bin_str):
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


def mlx5_tag_parser(lookup_type, tag, raw):
    switch = {"0x05": [mlx5_ifc_ste_src_gvmi_qp_bits_tag_parser, False],
              "0x0a": [mlx5_ifc_ste_eth_l2_tnl_bits_tag_parser_p, True],
              "0x06": [mlx5_ifc_ste_eth_l2_dst_bits_tag_parser_p, False],
              "0x07": [mlx5_ifc_ste_eth_l2_dst_bits_tag_parser_p, True],
              "0x1b": [mlx5_ifc_ste_eth_l2_dst_bits_tag_parser_p, False],
              "0x08": [mlx5_ifc_ste_eth_l2_src_bits_tag_parser_p, False],
              "0x09": [mlx5_ifc_ste_eth_l2_src_bits_tag_parser_p, True],
              "0x1c": [mlx5_ifc_ste_eth_l2_src_bits_tag_parser_p, False],
              "0x36": [mlx5_ifc_ste_eth_l2_src_dst_bits_tag_parser_p, False],
              "0x37": [mlx5_ifc_ste_eth_l2_src_dst_bits_tag_parser_p, True],
              "0x38": [mlx5_ifc_ste_eth_l2_src_dst_bits_tag_parser_p, False],
              "0x0d": [mlx5_ifc_ste_eth_l3_ipv6_dst_bits_tag_parser_p, False],
              "0x0e": [mlx5_ifc_ste_eth_l3_ipv6_dst_bits_tag_parser_p, True],
              "0x1e": [mlx5_ifc_ste_eth_l3_ipv6_dst_bits_tag_parser_p, False],
              "0x0f": [mlx5_ifc_ste_eth_l3_ipv6_src_bits_tag_parser_p, False],
              "0x10": [mlx5_ifc_ste_eth_l3_ipv6_src_bits_tag_parser_p, True],
              "0x1f": [mlx5_ifc_ste_eth_l3_ipv6_src_bits_tag_parser_p, False],
              "0x11": [mlx5_ifc_ste_eth_l3_ipv4_5_tuple_bits_tag_parser_p, False],
              "0x12": [mlx5_ifc_ste_eth_l3_ipv4_5_tuple_bits_tag_parser_p, True],
              "0x20": [mlx5_ifc_ste_eth_l3_ipv4_5_tuple_bits_tag_parser_p, False],
              "0x29": [mlx5_ifc_ste_eth_l3_ipv4_misc_bits_tag_parser_p, False],
              "0x2a": [mlx5_ifc_ste_eth_l3_ipv4_misc_bits_tag_parser_p, True],
              "0x2b": [mlx5_ifc_ste_eth_l3_ipv4_misc_bits_tag_parser_p, False],
              "0x2c": [mlx5_ifc_ste_eth_l4_misc_bits_tag_parser, False],
              "0x2d": [mlx5_ifc_ste_eth_l4_misc_bits_tag_parser, True],
              "0x2e": [mlx5_ifc_ste_eth_l4_misc_bits_tag_parser, False],
              "0x15": [mlx5_ifc_ste_mpls_bits_tag_parser, False],
              "0x24": [mlx5_ifc_ste_mpls_bits_tag_parser, True],
              "0x25": [mlx5_ifc_ste_mpls_bits_tag_parser, False],
              "0x16": [mlx5_ifc_ste_gre_bits_tag_parser, False],
              "0x18": [mlx5_ifc_ste_general_purpose_bits_tag_parser, False],
              "0x2f": [mlx5_ifc_ste_register_0_bits_tag_parser, False],
              "0x30": [mlx5_ifc_ste_register_1_bits_tag_parser, False],
              }

    if lookup_type not in switch.keys():
        # Silent fail lookup type is not supported
        return {}

    func, inner = switch[lookup_type]
    parsed_tag = func(tag)

    if not raw:
        parsed_tag = dr_prettify.prettify_tag(parsed_tag)

    if inner:
        add_inner_to_key(parsed_tag)

    return parsed_tag


# HW_STE parsing funcs
def mlx5_ifc_ste_rx_steering_mult_bits_parser(bin_str, raw):
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
    ret["tag"] = mlx5_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


def mlx5_ifc_ste_sx_transmit_bits_parser(bin_str, raw):
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
    ret["tag"] = mlx5_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


def mlx5_ifc_ste_modify_packet_bits_parser(bin_str, raw):
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
    ret["tag"] = mlx5_tag_parser(ret["entry_sub_type"], bin_str[256: 384], raw)
    return ret


def mlx5_hw_ste_parser(hex_str, raw):
    arr = {
        "0": "0000", "1": "0001", "2": "0010", "3": "0011",
        "4": "0100", "5": "0101", "6": "0110", "7": "0111",
        "8": "1000", "9": "1001", "a": "1010", "b": "1011",
        "c": "1100", "d": "1101", "e": "1110", "f": "1111"
    }

    bin_str = ""

    for i in range(0, len(hex_str)):
        bin_str += arr[hex_str[i]]

    entry_type = int(bin_str[0: 4], 2)
    switch = {1: mlx5_ifc_ste_sx_transmit_bits_parser,
              2: mlx5_ifc_ste_rx_steering_mult_bits_parser,
              6: mlx5_ifc_ste_modify_packet_bits_parser
              }

    return switch[entry_type](bin_str, raw)
