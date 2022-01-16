#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *


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

"""
The following functions decribes the headers layout structs
The functions recieve hl_index which is the DWs offset according to the headers layout and the DW mask
The offset parameter inside the functions is the DW offset inside the specific headers layout struct
oofset = (hl_index - "the starting offset of the hl struct") % ("hl struct size")
The dw_fields describes the specific hl struct, such that each array element in the array describes a DW and each DW described as (field name, bits size)
Returns the masked fields as an array (by calling dr_hl_dw_mask_parser function)
"""

def dr_hl_ib_l4_parser(hl_index, mask):
    offset = (hl_index - 30) % 3
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
    offset = (hl_index - 24) % 2
    dw_fields = [
                 [('src_port', 16), ('dst_port', 16)],
                 [
                  ('data_offset', 4), ('l4_ok', 1), ('l3_ok', 1), ('ip_fragmented', 1),
                  ('tcp_ns', 1), ('tcp_cwr', 1), ('tcp_ece', 1), ('tcp_urg', 1),
                  ('tcp_ack', 1), ('tcp_psh', 1), ('tcp_rst', 1), ('tcp_syn', 1),
                  ('tcp_fin', 1), ('first_fragment', 1), ('reserved_at_31', 15)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_eth_l2_parser(hl_index, mask):
    offset = int(hl_index % 4)
    dw_fields = [
                 [('dmac_47_16', 32)],
                 [('dmac_15_0', 16), ('l3_ethertype', 16)],
                 [
                  ('reserved_at_40', 1), ('sx_sniffer', 1), ('functional_lb', 1),
                  ('ip_fragmented', 1), ('qp_type', 2), ('encap_type', 2),
                  ('port_number', 2), ('l3_type', 2), ('l4_type_bwc', 2),
                  ('first_vlan_qualifier', 2), ('first_priority', 3), ('first_cfi', 1),
                  ('first_vlan_id', 12)
                 ],
                 [
                  ('l4_type', 4), ('reserved_at_64', 2), ('ipsec_layer', 2),
                  ('l2_type', 2), ('force_lb', 1), ('l2_ok', 1), ('l3_ok', 1),
                  ('l4_ok', 1), ('second_vlan_qualifier', 2), ('second_priority', 3),
                  ('second_cfi', 1), ('second_vlan_id', 12)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_eth_l3_parser(hl_index, mask):
    offset = (hl_index - 14) % 5
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

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ib_l2_parser(hl_index, mask):
    offset = (hl_index - 12) % 2
    dw_fields = [
                 [
                  ('sx_sniffer', 1), ('force_lb', 1), ('functional_lb', 1),
                  ('reserved_at_3', 3), ('port_number', 2), ('sl', 4), ('qp_type', 2),
                  ('lnh', 2), ('dlid', 16)
                 ],
                 [('vl', 4), ('lrh_packet_length', 12), ('slid', 16)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_eth_l2_src_parser(hl_index, mask):
    offset = (hl_index - 8) % 2
    dw_fields = [
                 [('smac_47_16', 32)],
                 [
                  ('smac_15_0', 16), ('loopback_syndrome', 8), ('l3_type', 2),
                  ('l4_type_bwc', 2), ('first_vlan_qualifier', 2),
                  ('ip_fragmented', 1), ('functional_lb', 1)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ipv4_src_dst_parser(hl_index, mask):
    offset = (hl_index - 64) % 2
    dw_fields = [
                 [('src_address', 32)],
                 [('dst_address', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_ipv6_addr_parser(hl_index, mask):
    offset = (hl_index - 68) % 4
    dw_fields = [
                 [('ipv6_address_127_96', 32)],
                 [('ipv6_address_95_64', 32)],
                 [('ipv6_address_63_32', 32)],
                 [('ipv6_address_31_0', 32)]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_flex_parser_parser(offset, mask):
    dw_fields = [
                 [
                  ('version', 3), ('proto_type', 1), ('reserved1', 1), ('ext_hdr_flag', 1),
                  ('seq_num_flag', 1), ('pdu_flag', 1), ('msg_type', 8), ('msg_len', 8),
                  ('teid', 32), ('seq_num', 16), ('pdu_num', 8), ('next_ext_hdr_type', 8), ('len', 8)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_oks1_parser(hl_index, mask):
    offset = hl_index - 33
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
    offset = hl_index - 34
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
    offset = (hl_index - 28) % 2
    dw_fields = [
                 [
                  ('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2),
                  ('first_vlan_qualifier', 2), ('reserved_at_e', 1), ('functional_lb', 1),
                  ('source_gvmi', 16)
                 ],
                 [
                  ('force_lb', 1), ('ip_fragmented', 1), ('source_is_requestor', 1),
                  ('reserved_at_23', 5), ('source_qp', 24)
                 ]
                ]

    return dr_hl_dw_mask_parser(dw_fields[offset], mask)

def dr_hl_voq_parser(hl_index, mask):
    offset = hl_index - 36
    dw_fields = [
                 [
                  ('reserved_at_0', 24), ('ecn_ok', 1), ('congestion', 1),
                  ('profile', 2), ('internal_prio', 4)
                 ]
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
    else:
        return []
