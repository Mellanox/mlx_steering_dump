#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *


dr_hl_dic = {
    "ib_l4": [[('opcode', 8), ('qp', 24)], [('se', 1), ('migreq', 1), ('ackreq', 1), ('fecn', 1), ('becn', 1), ('bth', 1), ('deth', 1), ('dcceth', 1), ('reserved_at_28', 2), ('pad_count', 2), ('tver', 4), ('p_key', 16)], [('reserved_at_40', 8), ('deth_source_qp', 24)]],
    "eth_l4": [[('source_port', 16), ('destination_port', 16)], [('data_offset', 4), ('l4_ok', 1), ('l3_ok', 1), ('ip_fragmented', 1), ('tcp_ns', 1), ('tcp_cwr', 1), ('tcp_ece', 1), ('tcp_urg', 1), ('tcp_ack', 1), ('tcp_psh', 1), ('tcp_rst', 1), ('tcp_syn', 1), ('tcp_fin', 1), ('first_fragment', 1), ('reserved_at_31', 15)]],
    "eth_l2": [[('dmac_47_16', 32)], [('dmac_15_0', 16), ('l3_ethertype', 16)], [('reserved_at_40', 1), ('sx_sniffer', 1), ('functional_lb', 1), ('ip_fragmented', 1), ('qp_type', 2), ('encap_type', 2), ('port_number', 2), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('first_priority', 3), ('first_cfi', 1), ('first_vlan_id', 12)], [('l4_type', 4), ('reserved_at_64', 2), ('ipsec_layer', 2), ('l2_type', 2), ('force_lb', 1), ('l2_ok', 1), ('l3_ok', 1), ('l4_ok', 1), ('second_vlan_qualifier', 2), ('second_priority', 3), ('second_cfi', 1), ('second_vlan_id', 12)]],
    "eth_l3": [[('ip_version', 4), ('ihl', 4), ('dscp', 6), ('ecn', 2), ('time_to_live_hop_limit', 8), ('protocol_next_header', 8)], [('identification', 16), ('flags', 3), ('fragment_offset', 13)], [('ipv4_total_length', 16), ('checksum', 16)], [('reserved_at_60', 12), ('flow_label', 20)], [('packet_length', 16), ('ipv6_payload_length', 16)]],
    "ib_l2": [[('sx_sniffer', 1), ('force_lb', 1), ('functional_lb', 1), ('reserved_at_3', 3), ('port_number', 2), ('sl', 4), ('qp_type', 2), ('lnh', 2), ('dlid', 16)], [('vl', 4), ('lrh_packet_length', 12), ('slid', 16)]],
    "eth_l2_src": [[('smac_47_16', 32)], [('smac_15_0', 16), ('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('ip_fragmented', 1), ('functional_lb', 1)]],
    "ipv4_src_dst": [[('source_address', 32)], [('destination_address', 32)]],
    "ipv6_addr": [[('ipv6_address_127_96', 32)], [('ipv6_address_95_64', 32)], [('ipv6_address_63_32', 32)], [('ipv6_address_31_0', 32)]],
    "flex_parser": [[('version', 3), ('proto_type', 1), ('reserved1', 1), ('ext_hdr_flag', 1), ('seq_num_flag', 1), ('pdu_flag', 1), ('msg_type', 8), ('msg_len', 8), ('teid', 32), ('seq_num', 16), ('pdu_num', 8), ('next_ext_hdr_type', 8), ('len', 8)]],
    "oks2": [[('reserved_at_0', 10), ('second_mpls_ok', 1), ('second_mpls4_s_bit', 1), ('second_mpls4_qualifier', 1), ('second_mpls3_s_bit', 1), ('second_mpls3_qualifier', 1), ('second_mpls2_s_bit', 1), ('second_mpls2_qualifier', 1), ('second_mpls1_s_bit', 1), ('second_mpls1_qualifier', 1), ('second_mpls0_s_bit', 1), ('second_mpls0_qualifier', 1), ('first_mpls_ok', 1), ('first_mpls4_s_bit', 1), ('first_mpls4_qualifier', 1), ('first_mpls3_s_bit', 1), ('first_mpls3_qualifier', 1), ('first_mpls2_s_bit', 1), ('first_mpls2_qualifier', 1), ('first_mpls1_s_bit', 1), ('first_mpls1_qualifier', 1), ('first_mpls0_s_bit', 1), ('first_mpls0_qualifier', 1)]],
    "oks1": [[('second_ipv4_checksum_ok', 1), ('second_l4_checksum_ok', 1), ('first_ipv4_checksum_ok', 1), ('first_l4_checksum_ok', 1), ('second_l3_ok', 1), ('second_l4_ok', 1), ('first_l3_ok', 1), ('first_l4_ok', 1), ('flex_parser7_steering_ok', 1), ('flex_parser6_steering_ok', 1), ('flex_parser5_steering_ok', 1), ('flex_parser4_steering_ok', 1), ('flex_parser3_steering_ok', 1), ('flex_parser2_steering_ok', 1), ('flex_parser1_steering_ok', 1), ('flex_parser0_steering_ok', 1), ('second_ipv6_extension_header_vld', 1), ('first_ipv6_extension_header_vld', 1), ('l3_tunneling_ok', 1), ('l2_tunneling_ok', 1), ('second_tcp_ok', 1), ('second_udp_ok', 1), ('second_ipv4_ok', 1), ('second_ipv6_ok', 1), ('second_l2_ok', 1), ('vxlan_ok', 1), ('gre_ok', 1), ('first_tcp_ok', 1), ('first_udp_ok', 1), ('first_ipv4_ok', 1), ('first_ipv6_ok', 1), ('first_l2_ok', 1)]],
    "src_qp_gvmi": [[('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('reserved_at_e', 1), ('functional_lb', 1), ('source_gvmi', 16)], [('force_lb', 1), ('ip_fragmented', 1), ('source_is_requestor', 1), ('reserved_at_23', 5), ('source_qp', 24)]],
    "voq": [[('reserved_at_0', 24), ('ecn_ok', 1), ('congestion', 1), ('profile', 2), ('internal_prio', 4)]],
    }

dr_hl_array = [
    ("eth_l2", 0),
    ("eth_l2", 1),
    ("eth_l2", 2),
    ("eth_l2", 3),
    ("eth_l2", 0),
    ("eth_l2", 1),
    ("eth_l2", 2),
    ("eth_l2", 3),
    ("eth_l2_src", 0),
    ("eth_l2_src", 1),
    ("eth_l2_src", 0),
    ("eth_l2_src", 1),
    ("ib_l2", 0),
    ("ib_l2", 1),
    ("eth_l3", 0),
    ("eth_l3", 1),
    ("eth_l3", 2),
    ("eth_l3", 3),
    ("eth_l3", 4),
    ("eth_l3", 0),
    ("eth_l3", 1),
    ("eth_l3", 2),
    ("eth_l3", 3),
    ("eth_l3", 4),
    ("eth_l4", 0),
    ("eth_l4", 1),
    ("eth_l4", 0),
    ("eth_l4", 1),
    ("src_qp_gvmi", 0),
    ("src_qp_gvmi", 1),
    ("ib_l4", 0),
    ("ib_l4", 1),
    ("ib_l4", 2),
    ("oks1", 0),
    ("oks2", 1),
    ("voq", 0),
    ("ipv4_src_dst", 0),
    ("ipv4_src_dst", 1),
    ("ipv4_src_dst", 0),
    ("ipv4_src_dst", 1),
    ("ipv6_addr", 0),
    ("ipv6_addr", 1),
    ("ipv6_addr", 2),
    ("ipv6_addr", 3),
    ("ipv6_addr", 0),
    ("ipv6_addr", 1),
    ("ipv6_addr", 2),
    ("ipv6_addr", 3),
    ("ipv6_addr", 0),
    ("ipv6_addr", 1),
    ("ipv6_addr", 2),
    ("ipv6_addr", 3),
    ("ipv6_addr", 0),
    ("ipv6_addr", 1),
    ("ipv6_addr", 2),
    ("ipv6_addr", 3),
    ]

DEFINERS = {}

def dr_definer_dw_parser(hl_index, mask):
    fields_arr = []

    if hl_index >= len(dr_hl_array):
        return []

    dw_fields = dr_hl_dic[dr_hl_array[hl_index][0]][dr_hl_array[hl_index][1]]
    _len = 0

    for i in range(len(dw_fields)):
        field_bits = bin(int("1" + (dw_fields[i][1] * "1"), 2) & int("1" + mask[_len : _len + dw_fields[i][1]], 2))
        fields_arr.append((dw_fields[i][0], str(field_bits)[3:]))

    return fields_arr


class dr_parse_definer():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "mt_id", "definer_obj_id",
                "dw_selector_0", "dw_selector_1", "dw_selector_2",
                "dw_selector_3", "dw_selector_4", "dw_selector_5",
                "byte_selector_0", "byte_selector_1", "byte_selector_2",
                "byte_selector_3", "byte_selector_4", "byte_selector_5",
                "byte_selector_6", "byte_selector_7", "mask_tag_0", "mask_tag_1",
                "mask_tag_2", "mask_tag_3", "mask_tag_4", "mask_tag_5",
                "mask_tag_6", "mask_tag_7", "mask_tag_8", "mask_tag_9",
                "mask_tag_10", "mask_tag_11", "mask_tag_12", "mask_tag_13",
                "mask_tag_14", "mask_tag_15", "mask_tag_16", "mask_tag_17",
                "mask_tag_18", "mask_tag_19", "mask_tag_20", "mask_tag_21",
                "mask_tag_22", "mask_tag_23", "mask_tag_24", "mask_tag_25",
                "mask_tag_26", "mask_tag_27", "mask_tag_28", "mask_tag_29",
                "mask_tag_30", "mask_tag_31"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.dw_fields = None
        self.byte_fields = None
        self.parse_data()

    def get_definer_obj_id(self):
        return self.data["definer_obj_id"]

    def dump_str(self, verbosity):
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "mt_id",
                                 "definer_obj_id", "dw_selector_0", "dw_selector_1",
                                 "dw_selector_2", "dw_selector_3", "dw_selector_4",
                                 "dw_selector_5", "byte_selector_0", "byte_selector_1",
                                 "byte_selector_2", "byte_selector_3", "byte_selector_4",
                                 "byte_selector_5", "byte_selector_6", "byte_selector_7"],
                                 self.data)

    def dump_fields(self):
        _str = ""
        union_fields = {"smac_47_16": 0, "smac_15_0": 0, "dmac_47_16": 0,
                        "dmac_15_0": 0, "ipv6_address_127_96": 0,
                        "ipv6_address_95_64": 0, "ipv6_address_63_32": 0,
                        "ipv6_address_31_0": 0}
        tmp_arr = []
        fields = {}
        for arr in list(self.dw_fields.values()):
            tmp_arr.extend(arr)

        for arr in list(self.byte_fields.values()):
            tmp_arr.extend(arr)

        for e in tmp_arr:
            _key = e[0]
            _data = e[1]
            if int(_data, 2) == 0:
                continue

            if _key in union_fields:
                union_fields[_key] = union_fields[_key] | int(_data, 2)
            else:
                fields[_key] = int(_data, 2)

        if union_fields["smac_47_16"] != 0 or union_fields["smac_15_0"] != 0:
            fields["smac"] = (union_fields["smac_47_16"] << 16) | union_fields["smac_15_0"]

        if union_fields["dmac_47_16"] != 0 or union_fields["dmac_15_0"] != 0:
            fields["dmac"] = (union_fields["dmac_47_16"] << 16) | union_fields["dmac_15_0"]

        if (union_fields["ipv6_address_127_96"] != 0 or
            union_fields["ipv6_address_95_64"] != 0 or
            union_fields["ipv6_address_63_32"] != 0 or
            union_fields["ipv6_address_31_0"] != 0):
            fields["ipv6_address"] = union_fields["ipv6_address_127_96"] << 96
            fields["ipv6_address"] |= union_fields["ipv6_address_95_64"] << 64
            fields["ipv6_address"] |= union_fields["ipv6_address_63_32"] << 32
            fields["ipv6_address"] |= union_fields["ipv6_address_31_0"]

        for _key in fields:
            if _str != "":
                _str += ", "
            _str += _key + ": " + str(hex(fields[_key]))

        return _str

    def definer_dws_parser(self):
        fields_dic = {}

        for i in range(6):
            dw_selector = "dw_selector_" + str(i)
            hl_index = int(self.data[dw_selector], 16)
            tag_index = 8 + (4 * i)
            mask = hex_to_bin_str(self.data["mask_tag_" + str(tag_index)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 1)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 2)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 3)])
            fields_dic[dw_selector] = dr_definer_dw_parser(hl_index, mask)

        return fields_dic

    def definer_bytes_parser(self):
        fields_dic = {}

        for i in range(8):
            byte_selector = "byte_selector_" + str(i)
            hl_byte_index = int(self.data[byte_selector], 16)
            hl_dw_index = hl_byte_index / 4
            hl_byte_offset = hl_byte_index % 4
            mask = (hl_byte_offset * 8) * "0"
            mask += hex_to_bin_str(self.data["mask_tag_" + str(i)])
            mask += ((3 - hl_byte_offset) * 8) * "0"

            fields_dic[byte_selector] = dr_definer_dw_parser(hl_dw_index, mask)

        return fields_dic


    def parse_data(self):
        self.dw_fields = self.definer_dws_parser()
        self.byte_fields = self.definer_bytes_parser()
