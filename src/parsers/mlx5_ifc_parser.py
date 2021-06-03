# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

from socket import ntohl

from src import dr_prettify
from src.dr_utilities import hex_2_bin


def little_endian_32(hex_str):
    l_e_32 = ntohl(int(hex_str, 16))
    return "{:08x}".format(l_e_32)


def get_bits_at(data, i, j, m, n):
    bin_val = hex_2_bin(data[i: j])
    bin_val = hex(int(bin_val[m: n], 2))
    return bin_val


def _val(field_str):
    return "0x" + field_str


def mlx5_ifc_dr_match_spec_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["smac"] = _val(data[0: 8] + data[12: 16])
    ret["ethertype"] = _val(data[8: 12])

    ret["dmac"] = _val(data[16: 24] + data[28: 32])

    ret["first_vid"] = get_bits_at(data, 24, 32, 0, 12)
    ret["first_cfi"] = get_bits_at(data, 24, 32, 12, 13)
    ret["first_prio"] = get_bits_at(data, 24, 32, 13, 16)

    ret["ip_protocol"] = get_bits_at(data, 32, 40, 23, 32)
    ret["ip_dscp"] = get_bits_at(data, 32, 40, 19, 23)
    ret["ip_ecn"] = get_bits_at(data, 32, 40, 18, 19)
    ret["cvlan_tag"] = get_bits_at(data, 32, 40, 17, 18)
    ret["svlan_tag"] = get_bits_at(data, 32, 40, 16, 17)
    ret["frag"] = get_bits_at(data, 32, 40, 14, 16)
    ret["ip_version"] = get_bits_at(data, 32, 40, 8, 14)
    ret["tcp_flags"] = get_bits_at(data, 32, 40, 0, 8)

    ret["tcp_sport"] = get_bits_at(data, 40, 48, 16, 32)
    ret["tcp_dport"] = get_bits_at(data, 40, 48, 0, 16)

    ret["reserved_at_c0"] = get_bits_at(data, 48, 56, 24, 32)
    ret["ipv4_ihl"] = get_bits_at(data, 48, 56, 23, 24)
    ret["l3_ok"] = get_bits_at(data, 48, 56, 22, 23)
    ret["ipv4_checksum_ok"] = get_bits_at(data, 48, 56, 21, 22)
    ret["l4_ok"] = get_bits_at(data, 48, 56, 20, 21)
    ret["l4_checksum_ok"] = get_bits_at(data, 48, 56, 16, 20)
    ret["ip_ttl_hoplimit"] = get_bits_at(data, 48, 56, 0, 16)

    ret["udp_sport"] = get_bits_at(data, 56, 64, 16, 32)
    ret["udp_dport"] = get_bits_at(data, 56, 64, 0, 16)

    if eval(_val(data[88: 96])) == eval(_val(data[64: 96])):
        ret["src_ip"] = _val(data[88: 96])  # IPV4
    else:
        ret["src_ip"] = _val(data[64: 96])  # IPV6

    if eval(_val(data[120: 128])) == eval(_val(data[96: 128])):
        ret["dst_ip"] = _val(data[120: 128])  # IPV4
    else:
        ret["dst_ip"] = _val(data[96: 128])  # IPV6

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret


def mlx5_ifc_dr_match_set_misc_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["source_sqn"] = get_bits_at(data, 0, 8, 0, 24)
    ret["source_vhca_port"] = get_bits_at(data, 0, 8, 24, 28)
    ret["gre_s_present"] = get_bits_at(data, 0, 8, 28, 29)
    ret["gre_k_present"] = get_bits_at(data, 0, 8, 29, 30)
    ret["reserved_auto1"] = get_bits_at(data, 0, 8, 30, 31)
    ret["gre_c_present"] = get_bits_at(data, 0, 8, 31, 32)

    ret["source_port"] = get_bits_at(data, 8, 16, 0, 16)
    ret["source_eswitch_owner_vhca_id"] = get_bits_at(data, 8, 16, 16, 32)

    ret["inner_second_vid"] = get_bits_at(data, 16, 24, 0, 12)
    ret["inner_second_cfi"] = get_bits_at(data, 16, 24, 12, 13)
    ret["inner_second_prio"] = get_bits_at(data, 16, 24, 13, 16)
    ret["outer_second_vid"] = get_bits_at(data, 16, 24, 16, 28)
    ret["outer_second_cfi"] = get_bits_at(data, 16, 24, 28, 29)
    ret["outer_second_prio"] = get_bits_at(data, 16, 24, 29, 32)

    ret["gre_protocol"] = get_bits_at(data, 24, 32, 0, 16)
    ret["reserved_at_65"] = get_bits_at(data, 24, 32, 16, 27)
    ret["outer_emd_tag"] = get_bits_at(data, 24, 32, 27, 28)
    ret["inner_second_svlan_tag"] = get_bits_at(data, 24, 32, 28, 29)
    ret["outer_second_svlan_tag"] = get_bits_at(data, 24, 32, 29, 30)
    ret["inner_second_cvlan_tag"] = get_bits_at(data, 24, 32, 30, 31)
    ret["outer_second_cvlan_tag"] = get_bits_at(data, 24, 32, 31, 32)

    ret["gre_key_l"] = get_bits_at(data, 32, 40, 0, 8)
    ret["gre_key_h"] = get_bits_at(data, 32, 40, 8, 32)

    ret["reserved_at_b8"] = get_bits_at(data, 40, 48, 0, 8)
    ret["vxlan_vni"] = get_bits_at(data, 40, 48, 8, 32)

    ret["geneve_oam"] = get_bits_at(data, 48, 56, 0, 1)
    ret["reserved_at_e4"] = get_bits_at(data, 48, 56, 1, 8)
    ret["geneve_vni"] = get_bits_at(data, 48, 56, 8, 32)

    ret["outer_ipv6_flow_label"] = get_bits_at(data, 56, 64, 0, 20)
    ret["reserved_at_ec"] = get_bits_at(data, 56, 64, 20, 32)

    ret["inner_ipv6_flow_label"] = get_bits_at(data, 64, 72, 0, 20)
    ret["reserved_at_100"] = get_bits_at(data, 64, 72, 20, 32)

    ret["geneve_protocol_type"] = get_bits_at(data, 72, 80, 0, 16)
    ret["geneve_opt_len"] = get_bits_at(data, 72, 80, 16, 22)
    ret["reserved_at_120"] = get_bits_at(data, 72, 80, 22, 32)

    ret["bth_dst_qp"] = get_bits_at(data, 80, 88, 0, 24)
    ret["reserved_at_140"] = get_bits_at(data, 80, 88, 24, 32)

    ret["inner_esp_spi"] = _val(data[88: 96])
    ret["outer_esp_spi"] = _val(data[96: 104])
    ret["reserved_at_1a0"] = _val(data[104: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)
    return ret


def mlx5_ifc_dr_match_set_misc2_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["outer_first_mpls_ttl"] = get_bits_at(data, 0, 8, 0, 8)
    ret["outer_first_mpls_s_bos"] = get_bits_at(data, 0, 8, 8, 9)
    ret["outer_first_mpls_exp"] = get_bits_at(data, 0, 8, 9, 12)
    ret["outer_first_mpls_label"] = get_bits_at(data, 0, 8, 12, 32)

    ret["inner_first_mpls_ttl"] = get_bits_at(data, 8, 16, 0, 8)
    ret["inner_first_mpls_s_bos"] = get_bits_at(data, 8, 16, 8, 9)
    ret["inner_first_mpls_exp"] = get_bits_at(data, 8, 16, 9, 12)
    ret["inner_first_mpls_label"] = get_bits_at(data, 8, 16, 12, 32)

    ret["outer_first_mpls_over_gre_ttl"] = get_bits_at(data, 16, 24, 0, 8)
    ret["outer_first_mpls_over_gre_s_bos"] = get_bits_at(data, 16, 24, 8, 9)
    ret["outer_first_mpls_over_gre_exp"] = get_bits_at(data, 16, 24, 9, 12)
    ret["outer_first_mpls_over_gre_label"] = get_bits_at(data, 16, 24, 12, 32)

    ret["outer_first_mpls_over_udp_ttl"] = get_bits_at(data, 24, 32, 0, 8)
    ret["outer_first_mpls_over_udp_s_bos"] = get_bits_at(data, 24, 32, 8, 9)
    ret["outer_first_mpls_over_udp_exp"] = get_bits_at(data, 24, 32, 9, 12)
    ret["outer_first_mpls_over_udp_label"] = get_bits_at(data, 24, 32, 12, 32)

    ret["metadata_reg_c_7"] = _val(data[32: 40])
    ret["metadata_reg_c_6"] = _val(data[40: 48])
    ret["metadata_reg_c_5"] = _val(data[48: 56])
    ret["metadata_reg_c_4"] = _val(data[56: 64])
    ret["metadata_reg_c_3"] = _val(data[64: 72])
    ret["metadata_reg_c_2"] = _val(data[72: 80])
    ret["metadata_reg_c_1"] = _val(data[80: 88])
    ret["metadata_reg_c_0"] = _val(data[88: 96])
    ret["metadata_reg_a"] = _val(data[96: 104])
    ret["metadata_reg_b"] = _val(data[104: 112])
    ret["reserved_at_260"] = _val(data[112: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret


def mlx5_ifc_dr_match_set_misc3_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["inner_tcp_seq_num"] = _val(data[0: 8])
    ret["outer_tcp_seq_num"] = _val(data[8: 16])
    ret["inner_tcp_ack_num"] = _val(data[16: 24])
    ret["outer_tcp_ack_num"] = _val(data[24: 32])

    ret["outer_vxlan_gpe_vni"] = get_bits_at(data, 32, 40, 0, 24)
    ret["reserved_at_80"] = get_bits_at(data, 32, 40, 24, 32)

    ret["reserved_at_b0"] = get_bits_at(data, 40, 48, 0, 16)
    ret["outer_vxlan_gpe_flags"] = get_bits_at(data, 40, 48, 16, 24)
    ret["outer_vxlan_gpe_next_protocol"] = get_bits_at(data, 40, 48, 24, 32)

    ret["icmp_header_data"] = _val(data[48: 56])
    ret["icmpv6_header_data"] = _val(data[56: 64])

    ret["icmpv6_code"] = get_bits_at(data, 64, 72, 0, 8)
    ret["icmpv6_type"] = get_bits_at(data, 64, 72, 8, 16)
    ret["icmp_code"] = get_bits_at(data, 64, 72, 16, 24)
    ret["icmp_type"] = get_bits_at(data, 64, 72, 24, 32)

    ret["geneve_tlv_option_0_data"] = _val(data[72: 80])
    ret["gtpu_teid"] = _val(data[80: 88])

    ret["reserved_at_150"] = get_bits_at(data, 88, 96, 0, 16)
    ret["gtpu_msg_flags"] = get_bits_at(data, 88, 96, 16, 24)
    ret["gtpu_msg_type"] = get_bits_at(data, 88, 96, 24, 32)

    ret["gtpu_dw_2"] = _val(data[96: 104])
    ret["gtpu_first_ext_dw_0"] = _val(data[104: 112])
    ret["gtpu_dw_0"] = _val(data[112: 120])
    ret["reserved_at_1c0"] = _val(data[120: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret


def mlx5_ifc_dr_match_set_misc4_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["prog_sample_field_value_0"] = _val(data[0: 8])
    ret["prog_sample_field_id_0"] = _val(data[8: 16])
    ret["prog_sample_field_value_1"] = _val(data[16: 24])
    ret["prog_sample_field_id_1"] = _val(data[24: 32])
    ret["prog_sample_field_value_2"] = _val(data[32: 40])
    ret["prog_sample_field_id_2"] = _val(data[40: 48])
    ret["prog_sample_field_value_3"] = _val(data[48: 56])
    ret["prog_sample_field_id_3"] = _val(data[56: 64])
    ret["reserved"] = _val(data[64: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret


def mlx5_ifc_dr_match_set_misc5_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["macsec_tag_0"] = _val(data[0: 8])
    ret["macsec_tag_1"] = _val(data[8: 16])
    ret["macsec_tag_2"] = _val(data[16: 24])
    ret["macsec_tag_3"] = _val(data[24: 32])
    ret["tunnel_header_0"] = _val(data[32: 40])
    ret["tunnel_header_1"] = _val(data[40: 48])
    ret["tunnel_header_2"] = _val(data[48: 56])
    ret["tunnel_header_3"] = _val(data[56: 64])
    ret["reserved"] = _val(data[64: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret
