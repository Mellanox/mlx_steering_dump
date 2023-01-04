#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *

#Define dictionaries for fields text values(tv) according to PRM
tv_l3_type = {0x0: "None", 0x1: "IPv4", 0x2: "IPv6", 0x3: "Reserved"}
tv_l4_type_bwc = {0x0: "None", 0x1: "TCP", 0x2: "UDP", 0x3: "IPSEC"}
tv_encap_type = {0x0: "no encapsulation", 0x1: "L2_tunneling", 0x2: "L3_tunneling", 0x3: "RoCE/R-RoCE"}
tv_first_vlan_qualifier = {0x0: "None", 0x1: "s-vlan", 0x2: "c-vlan", 0x3: "g-vlan"}
tv_l4_type = {0x0: "None", 0x1: "TCP", 0x2: "UDP", 0x3: "ICMP"}
for k in range(4, 16):
    tv_l4_type[k] = "Reserved"
tv_ipsec_layer = {0x0: "None", 0x1: "IPSECoIP", 0x2: "IPSECoUDP", 0x3: "Reserved"}
tv_l2_type = {0x0: "unicast" ,0x1: "multicast", 0x2: "broadcast", 0x3: "Reserved"}
tv_second_vlan_qualifier = {0x0: "None", 0x1: "s-vlan", 0x2: "c-vlan", 0x3: "g-vlan"}
class tv_ip:
    def get(self, ip):
        i_0 = (ip & 0xff000000) >> 24
        i_1 = (ip & 0x00ff0000) >> 16
        i_2 = (ip & 0x0000ff00) >> 8
        i_3 = ip & 0x000000ff
        return '%d.%d.%d.%d' % (i_0, i_1, i_2, i_3)

_fields_text_values = {
                        "l3_type_o": tv_l3_type,
                        "l3_type_i": tv_l3_type,
                        "l4_type_bwc_o": tv_l4_type_bwc,
                        "l4_type_bwc_i": tv_l4_type_bwc,
                        "encap_type_o": tv_encap_type,
                        "encap_type_i": tv_encap_type,
                        "first_vlan_qualifier_o": tv_first_vlan_qualifier,
                        "first_vlan_qualifier_i": tv_first_vlan_qualifier,
                        "l4_type_o": tv_l4_type,
                        "l4_type_i": tv_l4_type,
                        "ipsec_layer_o": tv_ipsec_layer,
                        "ipsec_layer_i": tv_ipsec_layer,
                        "l2_type_o": tv_l2_type,
                        "l2_type_i": tv_l2_type,
                        "second_vlan_qualifier_o": tv_second_vlan_qualifier,
                        "second_vlan_qualifier_i": tv_second_vlan_qualifier,
                        "src_ip_o": tv_ip(),
                        "src_ip_i": tv_ip(),
                        "dst_ip_o": tv_ip(),
                        "dst_ip_i": tv_ip(),
                        }


def dr_hl_dw_mask_parser(dw_fields, mask):
    fields_arr = []
    _len = 0

    #Go over the fields in the DW and compare with mask
    for i in range(len(dw_fields)):
        #Add "1" at the begining of the binary string so we won't lose the leading zeros
        field_bits = bin(int("1" + (dw_fields[i][1] * "1"), 2) & int("1" + mask[_len : _len + dw_fields[i][1]], 2))
        fields_arr.append((dw_fields[i][0], str(field_bits)[3:]))#Remove the "0b1" prefix of the binary string
        _len += dw_fields[i][1]

    return fields_arr


def dr_hl_fields_arr_add_suffix(arr, suffix):
    _arr = []

    for fields in arr:
        _fields = []
        for field in fields:
            _field = (field[0] + suffix, field[1])
            _fields.append(_field)
        _arr.append(_fields)

    return _arr


def dr_hl_fields_arr_add_prefix(prefix, arr):
    _arr = []

    for field in arr:
        _field = (prefix + field[0], field[1])
        _arr.append(_field)

    return _arr


"""
The following functions decribes the headers layout structs
The functions recieve hl_index which is the DWs offset according to the headers layout and the DW mask
The offset parameter inside the functions is the DW offset inside the specific headers layout struct
offset = (hl_index - "the starting offset of the hl struct in DW") % ("hl struct size in DW")
The dw_fields describes the specific hl struct, such that each array element in the array describes a DW and each DW described as (field name, bits size)
Returns the masked fields as an array (by calling dr_hl_dw_mask_parser function)
"""

def dr_hl_ib_l4_parser(hl_index, mask):
    offset = int((hl_index - 30) % 3)
    dw_fields = [
                 [('opcode', 8), ('qp', 24)],
                 [
                  ('se', 1), ('migreq', 1), ('ackreq', 1), ('fecn', 1), ('becn', 1),
                  ('bth', 1), ('deth', 1), ('dcceth', 1), ('reserved_at_28', 2),
                  ('pad_count', 2), ('tver', 4), ('p_key', 16)
                 ],
                 [('reserved_at_40', 8), ('deth_source_qp', 24)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_eth_l4_parser(hl_index, mask):
    offset = int((hl_index - 24) % 2)
    dw_fields = [
                 [('src_port', 16), ('dst_port', 16)],
                 [
                  ('data_offset', 4), ('l4_ok', 1), ('l3_ok', 1), ('ip_fragmented', 1),
                  ('tcp_ns', 1), ('tcp_cwr', 1), ('tcp_ece', 1), ('tcp_urg', 1),
                  ('tcp_ack', 1), ('tcp_psh', 1), ('tcp_rst', 1), ('tcp_syn', 1),
                  ('tcp_fin', 1), ('first_fragment', 1), ('reserved_at_31', 15)
                 ]
                ]

    suffix = DR_HL_OUTER if (hl_index < 26) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_eth_l2_parser(hl_index, mask):
    offset = int(hl_index % 4)
    dw_fields = [
                 [('dmac_47_16', 32)],
                 [('dmac_15_0', 16), ('l3_ethertype', 16)],
                 [
                  ('reserved_at_40', 1), ('sx_sniffer', 1), ('functional_lb', 1),
                  ('ip_fragmented', 1), ('qp_type', 2), ('encap_type', 2),
                  ('port_number', 2), ('l3_type', 2), ('l4_type_bwc', 2),
                  ('first_vlan_qualifier', 2), ('first_priority', 3),
                  ('first_cfi', 1), ('first_vlan_id', 12)
                 ],
                 [
                  ('l4_type', 4), ('reserved_at_64', 2), ('ipsec_layer', 2),
                  ('l2_type', 2), ('force_lb', 1), ('l2_ok', 1), ('l3_ok', 1),
                  ('l4_ok', 1), ('second_vlan_qualifier', 2),
                  ('second_priority', 3), ('second_cfi', 1),
                  ('second_vlan_id', 12)
                 ]
                ]

    suffix = DR_HL_OUTER if (hl_index < 4) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_eth_l3_parser(hl_index, mask):
    offset = int((hl_index - 14) % 5)
    dw_fields = [
                 [
                  ('ip_version', 4), ('ihl', 4), ('dscp', 6), ('ecn', 2),
                  ('time_to_live_hop_limit', 8), ('protocol_next_header', 8)
                 ],
                 [('identification', 16), ('flags', 3), ('fragment_offset', 13)],
                 [('ipv4_total_length', 16), ('checksum', 16)],
                 [('reserved_at_60', 12), ('flow_label', 20)],
                 [('packet_length', 16), ('ipv6_payload_length', 16)]
                ]

    suffix = DR_HL_OUTER if (hl_index < 19) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_ib_l2_parser(hl_index, mask):
    offset = int((hl_index - 12) % 2)
    dw_fields = [
                 [
                  ('sx_sniffer', 1), ('force_lb', 1), ('functional_lb', 1),
                  ('reserved_at_3', 3), ('port_number', 2), ('sl', 4),
                  ('qp_type', 2), ('lnh', 2), ('dlid', 16)
                 ],
                 [('vl', 4), ('lrh_packet_length', 12), ('slid', 16)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_eth_l2_src_parser(hl_index, mask):
    offset = int((hl_index - 8) % 2)
    dw_fields = [
                 [('smac_47_16', 32)],
                 [
                  ('smac_15_0', 16), ('loopback_syndrome', 8), ('l3_type', 2),
                  ('l4_type_bwc', 2), ('first_vlan_qualifier', 2),
                  ('ip_fragmented', 1), ('functional_lb', 1)
                 ]
                ]

    suffix = DR_HL_OUTER if (hl_index < 10) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_ipv4_src_dst_parser(hl_index, mask):
    offset = int((hl_index - 64) % 2)
    dw_fields = [
                 [('src_ip', 32)],
                 [('dst_ip', 32)]
                ]

    suffix = DR_HL_OUTER if (hl_index < 66) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_ipv6_addr_parser(hl_index, mask):
    offset = int((hl_index - 68) % 4)
    suffix = DR_HL_OUTER
    dw_fields = [
                 [('ipv6_address_127_96', 32)],
                 [('ipv6_address_95_64', 32)],
                 [('ipv6_address_63_32', 32)],
                 [('ipv6_address_31_0', 32)]
                ]

    if (hl_index > 79) or (hl_index > 71 and hl_index < 76):
        suffix = DR_HL_INNER

    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_oks1_parser(hl_index, mask):
    offset = int((hl_index - 33) % 1)
    dw_fields = [
                 [
                  ('second_ipv4_checksum_ok', 1), ('second_l4_checksum_ok', 1),
                  ('first_ipv4_checksum_ok', 1), ('first_l4_checksum_ok', 1),
                  ('second_l3_ok', 1), ('second_l4_ok', 1), ('first_l3_ok', 1),
                  ('first_l4_ok', 1), ('flex_parser7_steering_ok', 1),
                  ('flex_parser6_steering_ok', 1), ('flex_parser5_steering_ok', 1),
                  ('flex_parser4_steering_ok', 1), ('flex_parser3_steering_ok', 1),
                  ('flex_parser2_steering_ok', 1), ('flex_parser1_steering_ok', 1),
                  ('flex_parser0_steering_ok', 1), ('second_ipv6_extension_header_vld', 1),
                  ('first_ipv6_extension_header_vld', 1), ('l3_tunneling_ok', 1),
                  ('l2_tunneling_ok', 1), ('second_tcp_ok', 1), ('second_udp_ok', 1),
                  ('second_ipv4_ok', 1), ('second_ipv6_ok', 1), ('second_l2_ok', 1),
                  ('vxlan_ok', 1), ('gre_ok', 1), ('first_tcp_ok', 1), ('first_udp_ok', 1),
                  ('first_ipv4_ok', 1), ('first_ipv6_ok', 1), ('first_l2_ok', 1)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_oks2_parser(hl_index, mask):
    offset = int((hl_index - 34) % 1)
    dw_fields = [
                 [
                  ('reserved_at_0', 10), ('second_mpls_ok', 1), ('second_mpls4_s_bit', 1),
                  ('second_mpls4_qualifier', 1), ('second_mpls3_s_bit', 1),
                  ('second_mpls3_qualifier', 1), ('second_mpls2_s_bit', 1),
                  ('second_mpls2_qualifier', 1), ('second_mpls1_s_bit', 1),
                  ('second_mpls1_qualifier', 1), ('second_mpls0_s_bit', 1),
                  ('second_mpls0_qualifier', 1), ('first_mpls_ok', 1),
                  ('first_mpls4_s_bit', 1), ('first_mpls4_qualifier', 1),
                  ('first_mpls3_s_bit', 1), ('first_mpls3_qualifier', 1),
                  ('first_mpls2_s_bit', 1), ('first_mpls2_qualifier', 1),
                  ('first_mpls1_s_bit', 1), ('first_mpls1_qualifier', 1),
                  ('first_mpls0_s_bit', 1), ('first_mpls0_qualifier', 1)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_src_qp_gvmi_parser(hl_index, mask):
    offset = int((hl_index - 28) % 2)
    dw_fields = [
                 [
                  ('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2),
                  ('first_vlan_qualifier', 2), ('reserved_at_e', 1),
                  ('functional_lb', 1), ('source_gvmi', 16)
                 ],
                 [
                  ('force_lb', 1), ('ip_fragmented', 1), ('source_is_requestor', 1),
                  ('reserved_at_23', 5), ('source_qp', 24)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_voq_parser(hl_index, mask):
    offset = int((hl_index - 36) % 2)
    dw_fields = [
                 [
                  ('reserved_at_0', 24), ('ecn_ok', 1), ('congestion', 1),
                  ('profile', 2), ('internal_prio', 4)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_dest_ib_l3_parser(hl_index, mask):
    offset = int((hl_index - 84) % 4)
    dw_fields = [
                 [('dgid_dw0', 32)],
                 [('dgid_dw1', 32)],
                 [('dgid_dw2', 32)],
                 [('dgid_dw3', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_source_ib_l3_parser(hl_index, mask):
    offset = int((hl_index - 88) % 4)
    dw_fields = [
                 [('sgid_dw0', 32)],
                 [('sgid_dw1', 32)],
                 [('sgid_dw2', 32)],
                 [('sgid_dw3', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_udp_misc_parser(hl_index, mask):
    offset = int((hl_index - 92) % 1)
    dw_fields = [
                 [('length', 16), ('TCP/UDP Checksum', 16)]
                ]

    suffix = DR_HL_OUTER if (hl_index == 92) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_tcp_icmp_parser(hl_index, mask):
    offset = int((hl_index - 94) % 3)
    dw_fields = [
                 [('TCP_seq_numbuer / ICMP_DW1', 32)],
                 [('TCP_ack_numbuer / ICMP_DW2', 32)],
                 [('TCP_window size, TCP_urgent_pointer / ICMP_DW3', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_tunnel_header_parser(hl_index, mask):
    offset = int((hl_index - 97) % 4)
    dw_fields = [
                 [('tunnel_header0', 32)],
                 [('tunnel_header1', 32)],
                 [('tunnel_header2', 32)],
                 [('tunnel_header3', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_mpls_parser(hl_index, mask):
    offset = int((hl_index - 101) % 4)
    dw_fields = [
                 [('mpls0', 32)],
                 [('mpls1', 32)],
                 [('mpls2', 32)],
                 [('mpls3', 32)],
                 [('mpls4', 32)]
                ]

    suffix = DR_HL_OUTER if (hl_index < 106) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_configurable_headers_parser(hl_index, mask):
    offset = int((hl_index - 111) % 4)
    dw_fields = [
                 [
                  ('eth_l2_config_header0_present', 1), ('reserved', 15),
                  ('eth_l2_config_header0', 16)
                 ],
                 [('eth_l2_config_header0_dw', 32)],
                 [
                  ('eth_l2_config_header1_present', 1), ('reserved', 15),
                  ('eth_l2_config_header1', 16)
                 ],
                 [('eth_l2_config_header1_dw', 32)]
                ]

    suffix = DR_HL_OUTER if (hl_index < 115) else DR_HL_INNER
    _dw_fields = dr_hl_fields_arr_add_suffix(dw_fields, suffix)
    return dr_hl_dw_mask_parser(_dw_fields[offset], mask)

def dr_hl_random_number_parser(hl_index, mask):
    offset = int((hl_index - 119) % 1)
    dw_fields = [
                 [('random_number', 16), ('reserved', 16)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ipsec_parser(hl_index, mask):
    offset = int((hl_index - 120) % 3)
    dw_fields = [
                 [('SPI', 32)],
                 [('sequence_number', 32)],
                 [
                  ('reserved', 16), ('IPSec_syndrome', 8),
                  ('IPSec_next_header', 8)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_metadata_to_cqe_parser(hl_index, mask):
    offset = int((hl_index - 123) % 1)
    dw_fields = [
                 [('metadata_to_cqe', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_general_purpose_field_parser(hl_index, mask):
    offset = int((hl_index - 124) % 1)
    dw_fields = [
                 [('general_purpose_lookup_field', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_accumulated_hash_parser(hl_index, mask):
    offset = int((hl_index - 125) % 1)
    dw_fields = [
                 [('accumulated_hash_register', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_utc_timestamp_parser(hl_index, mask):
    offset = int((hl_index - 126) % 2)
    dw_fields = [
                 [('utc_timestamp_h', 32)],
                 [('utc_timestamp_l', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_free_runing_timestamp_parser(hl_index, mask):
    offset = int((hl_index - 128) % 2)
    dw_fields = [
                 [('frc_timestamp_h', 32)],
                 [('frc_timestamp_l', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_flex_parser_parser(hl_index, mask):
    offset = int((hl_index - 130) % 8)
    dw_fields = [
                 [('flex_parser_7', 32)],
                 [('flex_parser_6', 32)],
                 [('flex_parser_5', 32)],
                 [('flex_parser_4', 32)],
                 [('flex_parser_3', 32)],
                 [('flex_parser_2', 32)],
                 [('flex_parser_1', 32)],
                 [('flex_parser_0', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_registers_parser(hl_index, mask):
    offset = int((hl_index - 138) % 12)
    dw_fields = [
                 [('steering_reg_10', 32)],
                 [('steering_reg_11', 32)],
                 [('steering_reg_8', 32)],
                 [('steering_reg_9', 32)],
                 [('steering_reg_6', 32)],
                 [('steering_reg_7', 32)],
                 [('steering_reg_4', 32)],
                 [('steering_reg_5', 32)],
                 [('steering_reg_2', 32)],
                 [('steering_reg_3', 32)],
                 [('steering_reg_0', 32)],
                 [('steering_reg_1', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ib_l3_extended_parser(hl_index, mask):
    offset = int((hl_index - 150) % 2)
    dw_fields = [
                 [
                  ('ip_ver', 1), ('reserved', 3), ('traffic_class', 8),
                  ('flow_label', 20)
                 ],
                 [('q_key', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_rwh_parser(hl_index, mask):
    offset = int((hl_index - 152) % 1)
    dw_fields = [
                 [('reserved', 16), ('rwh_ethertype', 16)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_dcceth_parser(hl_index, mask):
    offset = int((hl_index - 153) % 1)
    dw_fields = [
                 [
                  ('dc_control_request_opcode', 4), ('dc_path_parameters', 8),
                  ('reserved', 16)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_dceth_parser(hl_index, mask):
    offset = int((hl_index - 154) % 5)
    dw_fields = [
                 [('dceth_dw0', 32)],
                 [('dceth_dw1', 32)],
                 [('dceth_dw2', 32)],
                 [('dceth_dw3', 32)],
                 [('dceth_dw4', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_dcaeth_parser(hl_index, mask):
    offset = int((hl_index - 159) % 1)
    dw_fields = [
                 [
                  ('dc_control_response_opcode', 4), ('reserved', 23),
                  ('dc_control_nack_parameter', 5)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_hro_parser(hl_index, mask):
    offset = int((hl_index - 160) % 1)
    dw_fields = [
                 [
                  ('reserved', 10), ('header_split_anchor', 6), ('reserved', 8),
                  ('header_split_offset_from_anchor', 8)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ipv6_extended_parser(hl_index, mask):
    offset = int((hl_index - 161) % 1)
    dw_fields = [
                 [
                  ('inner_last_extension_next_header', 8),
                  ('inner_last_extension_next_header', 8),
                  ('outer_last_extension_next_header', 8),
                  ('outer_header_next_header', 8)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_macsec_parser(hl_index, mask):
    offset = int((hl_index - 162) % 5)
    dw_fields = [
                 [('macsec_dw0', 32)],
                 [('macsec_dw1', 32)],
                 [('macsec_dw2', 32)],
                 [('macsec_dw3', 32)],
                 [('reserved', 24), ('macsec_syndrome', 8)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_psp_parser(hl_index, mask):
    offset = int((hl_index - 167) % 11)
    dw_fields = [
                 [('psp_dw0', 32)],
                 [('psp_dw1', 32)],
                 [('psp_dw2', 32)],
                 [('psp_dw3', 32)],
                 [('psp_dw4', 32)],
                 [('psp_dw5', 32)],
                 [('psp_dw6', 32)],
                 [('psp_dw7', 32)],
                 [('psp_dw8', 32)],
                 [('psp_dw9', 32)],
                 [('reserved', 24), ('psp_syndrome', 8)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

""" dr_hl_dw_parser(hl_index, mask):
This function describes the header layout.
Parameters:
hl_index: the DWs offset according to the headers layout.
mask: the DW mask.
Return:
Returns the masked fields as an array (by calling dr_hl_dw_mask_parser function).
"""
def dr_hl_dw_parser(hl_index, mask):
    if hl_index in range(0, 8):
        return dr_hl_eth_l2_parser(hl_index, mask)
    elif hl_index in range(8, 12):
        return dr_hl_eth_l2_src_parser(hl_index, mask)
    elif hl_index in range(12, 14):
        return dr_hl_ib_l2_parser(hl_index, mask)
    elif hl_index in range(14, 24):
        return dr_hl_eth_l3_parser(hl_index, mask)
    elif hl_index in range(24, 28):
        return dr_hl_eth_l4_parser(hl_index, mask)
    elif hl_index in range(28, 30):
        return dr_hl_src_qp_gvmi_parser(hl_index, mask)
    elif hl_index in range(30, 33):
        return dr_hl_ib_l4_parser(hl_index, mask)
    elif hl_index in range(33, 34):
        return dr_hl_oks1_parser(hl_index, mask)
    elif hl_index in range(34, 35):
        return dr_hl_oks2_parser(hl_index, mask)
    elif hl_index in range(35, 36):
        return dr_hl_voq_parser(hl_index, mask)
    elif hl_index in range(64, 68):
        return dr_hl_ipv4_src_dst_parser(hl_index, mask)
    elif hl_index in range(68, 84):
        return dr_hl_ipv6_addr_parser(hl_index, mask)
    elif hl_index in range(84, 88):
        return dr_hl_dest_ib_l3_parser(hl_index, mask)
    elif hl_index in range(88, 92):
        return dr_hl_source_ib_l3_parser(hl_index, mask)
    elif hl_index in range(92, 94):
        return dr_hl_udp_misc_parser(hl_index, mask)
    elif hl_index in range(94, 97):
        return dr_hl_tcp_icmp_parser(hl_index, mask)
    elif hl_index in range(97, 101):
        return dr_hl_tunnel_header_parser(hl_index, mask)
    elif hl_index in range(101, 111):
        return dr_hl_mpls_parser(hl_index, mask)
    elif hl_index in range(111, 119):
        return dr_hl_configurable_headers_parser(hl_index, mask)
    elif hl_index in range(119, 120):
        return dr_hl_random_number_parser(hl_index, mask)
    elif hl_index in range(120, 123):
        return dr_hl_ipsec_parser(hl_index, mask)
    elif hl_index in range(123, 124):
        return dr_hl_metadata_to_cqe_parser(hl_index, mask)
    elif hl_index in range(124, 125):
        return dr_hl_general_purpose_field_parser(hl_index, mask)
    elif hl_index in range(125, 126):
        return dr_hl_accumulated_hash_parser(hl_index, mask)
    elif hl_index in range(126, 128):
        return dr_hl_utc_timestamp_parser(hl_index, mask)
    elif hl_index in range(128, 130):
        return dr_hl_free_runing_timestamp_parser(hl_index, mask)
    elif hl_index in range(130, 138):
        return dr_hl_flex_parser_parser(hl_index, mask)
    elif hl_index in range(138, 150):
        return dr_hl_registers_parser(hl_index, mask)
    elif hl_index in range(150, 152):
        return dr_hl_ib_l3_extended_parser(hl_index, mask)
    elif hl_index in range(152, 153):
        return dr_hl_rwh_parser(hl_index, mask)
    elif hl_index in range(153, 154):
        return dr_hl_dcceth_parser(hl_index, mask)
    elif hl_index in range(154, 159):
        return dr_hl_dceth_parser(hl_index, mask)
    elif hl_index in range(159, 160):
        return dr_hl_dcaeth_parser(hl_index, mask)
    elif hl_index in range(160, 161):
        return dr_hl_hro_parser(hl_index, mask)
    elif hl_index in range(161, 162):
        return dr_hl_ipv6_extended_parser(hl_index, mask)
    elif hl_index in range(162, 167):
        return dr_hl_macsec_parser(hl_index, mask)
    elif hl_index in range(167, 178):
        return dr_hl_psp_parser(hl_index, mask)
    else:
        return []
