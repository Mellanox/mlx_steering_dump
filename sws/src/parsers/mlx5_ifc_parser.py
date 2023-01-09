# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

from socket import ntohl

from src import dr_prettify
from src.dr_utilities import hex_2_bin, to_hex
import ctypes
import re
from src.dr_prettify import pretty_ip, pretty_mac


def little_endian_32(hex_str):
    l_e_32 = ntohl(int(hex_str, 16))
    return "{:08x}".format(l_e_32)


def get_bits_at(data, i, j, m, n):
    bin_val = hex_2_bin(data[i: j])
    bin_val = to_hex(int(bin_val[m: n], 2))
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

    ret["ip_protocol"] = get_bits_at(data, 32, 40, 24, 32)
    ret["ip_dscp"] = get_bits_at(data, 32, 40, 18, 24)
    ret["ip_ecn"] = get_bits_at(data, 32, 40, 16, 18)
    ret["cvlan_tag"] = get_bits_at(data, 32, 40, 15, 16)
    ret["svlan_tag"] = get_bits_at(data, 32, 40, 14, 15)
    ret["frag"] = get_bits_at(data, 32, 40, 13, 14)
    ret["ip_version"] = get_bits_at(data, 32, 40, 9, 13)
    ret["tcp_flags"] = get_bits_at(data, 32, 40, 0, 9)

    ret["tcp_sport"] = get_bits_at(data, 40, 48, 16, 32)
    ret["tcp_dport"] = get_bits_at(data, 40, 48, 0, 16)

    ret["reserved_at_c0"] = get_bits_at(data, 48, 56, 16, 32)
    ret["ipv4_ihl"] = get_bits_at(data, 48, 56, 12, 16)
    ret["l3_ok"] = get_bits_at(data, 48, 56, 11, 12)
    ret["l4_ok"] = get_bits_at(data, 48, 56, 10, 11)
    ret["ipv4_checksum_ok"] = get_bits_at(data, 48, 56, 9, 10)
    ret["l4_checksum_ok"] = get_bits_at(data, 48, 56, 8, 9)
    ret["ip_ttl_hoplimit"] = get_bits_at(data, 48, 56, 0, 8)

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


def mlx5_ifc_dr_match_set_misc6_bits_parser(mask, raw):
    ret = {}
    data = ""

    if not mask:
        return ret

    for i in range(0, len(mask), 8):
        tmp = little_endian_32(mask[i: i + 8])
        data += tmp

    ret["nisp_header_0"] = _val(data[0: 8])
    ret["nisp_header_1"] = _val(data[8: 16])
    ret["nisp_header_2"] = _val(data[16: 24])
    ret["nisp_header_3"] = _val(data[24: 32])
    ret["nisp_header_4"] = _val(data[32: 40])
    ret["nisp_header_5"] = _val(data[40: 48])
    ret["nisp_header_6"] = _val(data[48: 56])
    ret["nisp_header_7"] = _val(data[56: 64])
    ret["nisp_header_8"] = _val(data[64: 72])
    ret["nisp_header_9"] = _val(data[72: 80])
    ret["reserved"] = _val(data[80: 128])

    if not raw:
        ret = dr_prettify.prettify_mask(ret)

    return ret


# MLX5_MOD_FLD
MLX5_MODI_OUT_NONE = -1
MLX5_MODI_OUT_SMAC_47_16 = 1
MLX5_MODI_OUT_SMAC_15_0 = 2
MLX5_MODI_OUT_ETHERTYPE = 3
MLX5_MODI_OUT_DMAC_47_16 = 4
MLX5_MODI_OUT_DMAC_15_0 = 5
MLX5_MODI_OUT_IP_DSCP = 6
MLX5_MODI_OUT_TCP_FLAGS = 7
MLX5_MODI_OUT_TCP_SPORT = 8
MLX5_MODI_OUT_TCP_DPORT = 9
MLX5_MODI_OUT_IPV4_TTL = 10
MLX5_MODI_OUT_UDP_SPORT = 11
MLX5_MODI_OUT_UDP_DPORT = 12
MLX5_MODI_OUT_SIPV6_127_96 = 13
MLX5_MODI_OUT_SIPV6_95_64 = 14
MLX5_MODI_OUT_SIPV6_63_32 = 15
MLX5_MODI_OUT_SIPV6_31_0 = 16
MLX5_MODI_OUT_DIPV6_127_96 = 17
MLX5_MODI_OUT_DIPV6_95_64 = 18
MLX5_MODI_OUT_DIPV6_63_32 = 19
MLX5_MODI_OUT_DIPV6_31_0 = 20
MLX5_MODI_OUT_SIPV4 = 21
MLX5_MODI_OUT_DIPV4 = 22
MLX5_MODI_OUT_FIRST_VID = 23
MLX5_MODI_IN_SMAC_47_16 = 0x31
MLX5_MODI_IN_SMAC_15_0 = 0x32
MLX5_MODI_IN_ETHERTYPE = 0x33
MLX5_MODI_IN_DMAC_47_16 = 0x34
MLX5_MODI_IN_DMAC_15_0 = 0x35
MLX5_MODI_IN_IP_DSCP = 0x36
MLX5_MODI_IN_TCP_FLAGS = 0x37
MLX5_MODI_IN_TCP_SPORT = 0x38
MLX5_MODI_IN_TCP_DPORT = 0x39
MLX5_MODI_IN_IPV4_TTL = 0x3a
MLX5_MODI_IN_UDP_SPORT = 0x3b
MLX5_MODI_IN_UDP_DPORT = 0x3c
MLX5_MODI_IN_SIPV6_127_96 = 0x3d
MLX5_MODI_IN_SIPV6_95_64 = 0x3e
MLX5_MODI_IN_SIPV6_63_32 = 0x3f
MLX5_MODI_IN_SIPV6_31_0 = 0x40
MLX5_MODI_IN_DIPV6_127_96 = 0x41
MLX5_MODI_IN_DIPV6_95_64 = 0x42
MLX5_MODI_IN_DIPV6_63_32 = 0x43
MLX5_MODI_IN_DIPV6_31_0 = 0x44
MLX5_MODI_IN_SIPV4 = 0x45
MLX5_MODI_IN_DIPV4 = 0x46
MLX5_MODI_OUT_IPV6_HOPLIMIT = 0x47
MLX5_MODI_IN_IPV6_HOPLIMIT = 0x48
MLX5_MODI_META_DATA_REG_A = 0x49
MLX5_MODI_META_DATA_REG_B = 0x50
MLX5_MODI_META_REG_C_0 = 0x51
MLX5_MODI_META_REG_C_1 = 0x52
MLX5_MODI_META_REG_C_2 = 0x53
MLX5_MODI_META_REG_C_3 = 0x54
MLX5_MODI_META_REG_C_4 = 0x55
MLX5_MODI_META_REG_C_5 = 0x56
MLX5_MODI_META_REG_C_6 = 0x57
MLX5_MODI_META_REG_C_7 = 0x58
MLX5_MODI_OUT_TCP_SEQ_NUM = 0x59
MLX5_MODI_IN_TCP_SEQ_NUM = 0x5a
MLX5_MODI_OUT_TCP_ACK_NUM = 0x5b
MLX5_MODI_IN_TCP_ACK_NUM = 0x5c
MLX5_MODI_GTP_TEID = 0x6e


class _data0(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32, 5),
               ('rsvd0', ctypes.c_uint32, 3),
               ('offset', ctypes.c_uint32, 5),
               ('rsvd1', ctypes.c_uint32, 3),
               ('field', ctypes.c_uint32, 12),
               ('action_type', ctypes.c_uint32, 4),
              ]

class _data0_union(ctypes.Union):
    _fields_ = [('data0', ctypes.c_uint32),
               ('data0_struct', _data0),
              ]

class _data1(ctypes.Structure):
    _fields_ = [('rsvd2', ctypes.c_uint32, 8),
               ('dst_offset', ctypes.c_uint32, 5),
               ('rsvd3', ctypes.c_uint32, 3),
               ('dst_field', ctypes.c_uint32, 12),
               ('rsvd4', ctypes.c_uint32, 4),
              ]

class _data1_union(ctypes.Union):
    _fields_ = [('data1', ctypes.c_uint32),
               ('data', ctypes.c_ubyte * 4),
               ('data1_struct', _data1),
              ]

class mlx5_modification_cmd(ctypes.Structure):
    _fields_ = [('data0_u', _data0_union),
               ('data1_u', _data1_union),
               ]

def mlx5_ifc_encap_decap(bin_str):
    ETH_HDR_LEN = 28
    VLAN_HDR_LEN = 8
    IPV4_HDR_LEN = 40
    IPV6_HDR_LEN = 80
    UDP_HDR_LEN = 16
    VXLAN_HDR_LEN = 16
    length = 0
    ret = {}
    if not bin_str:
        return

    _len = len(bin_str)
    if _len >= 108:
        #mac + vlan + ip
        has_vlan = True
    else:
        #mac + ip
        has_vlan = False

    ret["dmac"] = pretty_mac('0x'+bin_str[0: 12])
    ret["smac"] = pretty_mac('0x'+bin_str[12: 24])
    if has_vlan:
        ret["vid"] = int(bin_str[28: 32], 16) & 0xfff
        ret["ethtype"] = (bin_str[32: 36])  # 0x0800; ipv4, 0x86DD, ipv6
    else:
        ret["ethtype"] = (bin_str[24: 28])  # 0x0800; ipv4, 0x86DD, ipv6

    if has_vlan:
        length += (ETH_HDR_LEN + VLAN_HDR_LEN)
        off = 0
    else:
        length += ETH_HDR_LEN
        off = VLAN_HDR_LEN

    if ret["ethtype"] == '0800':
        ret["ip_type"] = int (bin_str[length + IPV4_HDR_LEN - 22 : length + IPV4_HDR_LEN - 20], 16)  # udp/ip
        ret["src_ip"] = pretty_ip(bin_str[length + IPV4_HDR_LEN - 16 : length + IPV4_HDR_LEN - 8])
        ret["dst_ip"] = pretty_ip(bin_str[length + IPV4_HDR_LEN - 8  : length + IPV4_HDR_LEN])
        length += IPV4_HDR_LEN
    else :
        ret["ip_type"] = (bin_str[length + IPV6_HDR_LEN - 68 + off: length + IPV6_HDR_LEN - 66 + off])  # udp/ip
        ret["src_ip"] = pretty_ip('0x' + bin_str[length + IPV6_HDR_LEN - 64 : length + IPV6_HDR_LEN - 32])
        ret["dst_ip"] = pretty_ip('0x' + bin_str[length + IPV6_HDR_LEN - 32 : length + IPV6_HDR_LEN])
        length += IPV6_HDR_LEN

    ret["udp_port"] = int(bin_str[length + UDP_HDR_LEN - 12 : length + UDP_HDR_LEN - 8], 16)
    length += UDP_HDR_LEN
    ret["flag"] = (bin_str[length + VXLAN_HDR_LEN - 16 : length + VXLAN_HDR_LEN - 8])
    ret["vni"] = int(bin_str[length + VXLAN_HDR_LEN - 8 : length + VXLAN_HDR_LEN-2], 16)
    if has_vlan:
        str = "vxlan tnl_push(dmac=%s, smac=%s, vid=%s, sip=%s, dip=%s, port=%s, vni=%s)" % \
                           (ret["dmac"], ret["smac"], ret["vid"], ret["src_ip"], ret["dst_ip"],
                           ret["udp_port"], ret["vni"])
    else:
        str = "vxlan tnl_push(dmac=%s, smac=%s, vlan null, sip=%s, dip=%s, port=%s, vni=%s)" % \
                           (ret["dmac"], ret["smac"], ret["src_ip"], ret["dst_ip"],
                           ret["udp_port"], ret["vni"])
    return str

def int_repl(match):
   return str(int(match.group(), 16)) + "."

def remove_prefix_zero(match):
   return str(match.group()).lstrip('0') + ":"

def mlx5_ifc_modify_hdr(num_str, bin_str):
   pattern = re.compile('.{2}')
   hdr_str = ''
   for i in range(int(num_str)):
       cmd = mlx5_modification_cmd()
       cmd.data0_u.data0 = int(bin_str[i*16:i*16+8], 16)
       cmd.data1_u.data1 = int(bin_str[i*16+8:i*16+16], 16)
       if cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SMAC_47_16:
           hdr_str += ',smac=' + ':'.join(pattern.findall(bin_str[i*16+8:i*16+16])) + ":"
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SMAC_15_0:
           hdr_str += ':'.join(pattern.findall(bin_str[i*16+12:i*16+16]))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DMAC_47_16:
           hdr_str += ',dmac=' + ':'.join(pattern.findall(bin_str[i*16+8:i*16+16])) + ":"
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DMAC_15_0:
           hdr_str += ':'.join(pattern.findall(bin_str[i*16+12:i*16+16]))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SIPV4:
           hdr_str += ',sip4=' + pattern.sub(int_repl, bin_str[i*16+8:i*16+16]).rstrip('.')
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DIPV4:
           hdr_str += ',dip4=' + pattern.sub(int_repl, bin_str[i*16+8:i*16+16]).rstrip('.')
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SIPV6_127_96:
           pattern = re.compile('.{4}')
           hdr_str = ',sip6=' + pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SIPV6_95_64:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SIPV6_63_32:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_SIPV6_31_0:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16]).rstrip(":")
           hdr_str = (re.sub('(::+)', '::', hdr_str))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DIPV6_127_96:
           pattern = re.compile('.{4}')
           hdr_str += ',dip6=' + pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DIPV6_95_64:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DIPV6_63_32:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16])
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_DIPV6_31_0:
           hdr_str += pattern.sub(remove_prefix_zero, bin_str[i*16+8:i*16+16]).rstrip(":")
           hdr_str = (re.sub('(::+)', '::', hdr_str))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_TCP_SPORT:
           hdr_str = ',tcp_sport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_TCP_DPORT:
           hdr_str += ',tcp_dport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_IP_DSCP:
           hdr_str = ',ip_dscp=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_ETHERTYPE:
           #Fix ME. Contents in actions->conf
           hdr_str = ',modify_field'
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_IPV4_TTL:
           if cmd.data0_u.data0_struct.action_type == 1:
               hdr_str = ',ip4_ttl=' + str(int(bin_str[i*16+8:i*16+16], 16))
           elif cmd.data0_u.data0_struct.action_type == 2:
               #Add -1
               hdr_str = ',dec_ip4_ttl'
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_IPV6_HOPLIMIT:
           if cmd.data0_u.data0_struct.action_type == 1:
               hdr_str = ',ip6_hop=' + str(int(bin_str[i*16+8:i*16+16], 16))
           elif cmd.data0_u.data0_struct.action_type == 2:
               #Add -1
               hdr_str = ',dec_ip6_hop'
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_FIRST_VID:
           hdr_str = ',vid=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_UDP_SPORT:
           hdr_str = ',udp_sport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_UDP_DPORT:
           hdr_str = ',udp_dport=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_TCP_ACK_NUM:
           if int(bin_str[i*16+8:i*16+9], 16) > 7:
               hdr_str = ',dec_tcp_ack=' + str(pow(2, 32) - int(bin_str[i*16+8:i*16+16], 16))
           else:
               hdr_str = ',add_tcp_ack=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_OUT_TCP_SEQ_NUM:
           if int(bin_str[i*16+8:i*16+9], 16) > 7:
               hdr_str = ',dec_tcp_seq=' + str(pow(2, 32) - int(bin_str[i*16+8:i*16+16], 16))
           else:
               hdr_str = ',add_tcp_seq=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.action_type == 3:
           #COPY MREG
           hdr_str = ',cp_reg'
           if cmd.data0_u.data0_struct.field == MLX5_MODI_META_DATA_REG_A:
               hdr_str += '_a'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_DATA_REG_B:
               hdr_str += '_b'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_0:
               hdr_str += '_c0'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_1:
               hdr_str += '_c1'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_2:
               hdr_str += '_c2'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_3:
               hdr_str += '_c3'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_4:
               hdr_str += '_c4'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_5:
               hdr_str += '_c5'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_6:
               hdr_str += '_c6'
           elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_7:
               hdr_str += '_c7'
           if cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_DATA_REG_A:
               hdr_str += '_to_reg_a'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_DATA_REG_B:
               hdr_str = '_to_reg_b'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_0:
               hdr_str = '_to_reg_c0'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_1:
               hdr_str = '_to_reg_c1'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_2:
               hdr_str = '_to_reg_c2'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_3:
               hdr_str = '_to_reg_c3'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_4:
               hdr_str = '_to_reg_c4'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_5:
               hdr_str = '_to_reg_c5'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_6:
               hdr_str = '_to_reg_c6'
           elif cmd.data1_u.data1_struct.dst_field == MLX5_MODI_META_REG_C_7:
               hdr_str = '_to_reg_c7'
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_DATA_REG_A:
           hdr_str = ',set_reg_a=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_DATA_REG_B:
           hdr_str = ',set_reg_b=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_0:
           hdr_str = ',set_reg_c0=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_1:
           hdr_str = ',set_reg_c1=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_2:
           hdr_str = ',set_reg_c2=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_3:
           hdr_str = ',set_reg_c3=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_4:
           hdr_str = ',set_reg_c4=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_5:
           hdr_str = ',set_reg_c5=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_6:
           hdr_str = ',set_reg_c6=' + str(int(bin_str[i*16+8:i*16+16], 16))
       elif cmd.data0_u.data0_struct.field == MLX5_MODI_META_REG_C_7:
           hdr_str = ',set_reg_c7=' + str(int(bin_str[i*16+8:i*16+16], 16))
   return hdr_str
