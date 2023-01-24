#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_utilities import hex_2_bin, get_indent_str, dr_utils_dic
from src.dr_constants import *


L2_OUT_0 = 0x00
L2_OUT_1 = 0x01
L2_OUT_2 = 0x02
SRC_L2_OUT_0 = 0x08
SRC_L2_OUT_1 = 0x09
L3_OUT_0 = 0x0e
L4_OUT_0 = 0x18
L4_OUT_1 = 0x19
IPV4_OUT_0 = 0x40
IPV4_OUT_1 = 0x41
IPV6_DST_OUT_0 = 0x44
IPV6_DST_OUT_1 = 0x45
IPV6_DST_OUT_2 = 0x46
IPV6_DST_OUT_3 = 0x47
IPV6_SRC_OUT_0 = 0x4c
IPV6_SRC_OUT_1 = 0x4d
IPV6_SRC_OUT_2 = 0x4e
IPV6_SRC_OUT_3 = 0x4f
TCP_MISC_0 = 0x5e
TCP_MISC_1 = 0x5f
METADATA_2_CQE = 0x7b
GNRL_PURPOSE = 0x7c
FLEX_PARSER_7 = 0x82
FLEX_PARSER_6 = 0x83
FLEX_PARSER_5 = 0x84
FLEX_PARSER_4 = 0x85
FLEX_PARSER_3 = 0x86
FLEX_PARSER_2 = 0x87
FLEX_PARSER_1 = 0x88
FLEX_PARSER_0 = 0x89
REGISTER_2_0 = 0x90
REGISTER_2_1 = 0x91
REGISTER_1_0 = 0x92
REGISTER_1_1 = 0x93
REGISTER_0_0 = 0x94
REGISTER_0_1 = 0x95

MDFY_HDR_FIELDS = {
    (SRC_L2_OUT_0, 0, 31): "OUT_SMAC_47_16",
    (SRC_L2_OUT_1, 16, 31): "OUT_SMAC_15_0",
    (L2_OUT_1, 0, 15): "OUT_ETHERTYPE",
    (L2_OUT_0, 0, 31): "OUT_DMAC_47_16",
    (L2_OUT_1, 16, 31): "OUT_DMAC_15_0",
    (L3_OUT_0, 18, 23): "OUT_IP_DSCP",
    (L3_OUT_0, 16, 17): "OUT_IP_ECN",
    (L4_OUT_1, 16, 24): "OUT_TCP_FLAGS",
    (L4_OUT_0, 16, 31): "OUT_TCP_SPORT",
    (L4_OUT_0, 0, 15): "OUT_TCP_DPORT",
    (L3_OUT_0, 8, 15): "OUT_IP_TTL",
    (L3_OUT_0, 8, 15): "OUT_IPV6_HOPLIMIT",
    (L4_OUT_0, 16, 31): "OUT_UDP_SPORT",
    (L4_OUT_0, 0, 15): "OUT_UDP_DPORT",
    (IPV6_SRC_OUT_0, 0, 31): "OUT_SIPV6_127_96",
    (IPV6_SRC_OUT_1, 0, 31): "OUT_SIPV6_95_64",
    (IPV6_SRC_OUT_2, 0, 31): "OUT_SIPV6_63_32",
    (IPV6_SRC_OUT_3, 0, 31): "OUT_SIPV6_31_0",
    (IPV6_DST_OUT_0, 0, 31): "OUT_DIPV6_127_96",
    (IPV6_DST_OUT_1, 0, 31): "OUT_DIPV6_95_64",
    (IPV6_DST_OUT_2, 0, 31): "OUT_DIPV6_63_32",
    (IPV6_DST_OUT_3, 0, 31): "OUT_DIPV6_31_0",
    (IPV4_OUT_0, 0, 31): "OUT_SIPV4",
    (IPV4_OUT_1, 0, 31): "OUT_DIPV4",
    (GNRL_PURPOSE, 0, 31): "OUT_METADATA_REGA",
    (METADATA_2_CQE, 0, 31): "OUT_METADATA_REGB",
    (REGISTER_0_0, 0, 31): "OUT_METADATA_REGC_0",
    (REGISTER_0_1, 0, 31): "OUT_METADATA_REGC_1",
    (REGISTER_1_0, 0, 31): "OUT_METADATA_REGC_2",
    (REGISTER_1_1, 0, 31): "OUT_METADATA_REGC_3",
    (REGISTER_2_0, 0, 31): "OUT_METADATA_REGC_4",
    (REGISTER_2_1, 0, 31): "OUT_METADATA_REGC_5",
    (TCP_MISC_0, 0, 31): "OUT_TCP_SEQ_NUM",
    (TCP_MISC_1, 0, 31): "OUT_TCP_ACK_NUM",
    (L2_OUT_2, 0, 15): "OUT_FIRST_VID",
}

MDFY_HDR_ANCHORS = {
    0x00: "START_OUTER",
    0x02: "1ST_VLAN",
    0x07: "IPV6_IPV4",
    0x13: "INNER_MAC",
    0x19: "INNER_IPV6_IPV4",
}

MLX5_MODIFY_HEADER_V1_QW_OFFSET = 0x20
V1_TO_V2_HL_DIFF = 0x4
V1_TO_V2_HL_BOUND = FLEX_PARSER_0

def dr_action_nop_parser(action):
    return "NOP"

def get_modify_hdr_field(dw_offset, left_shifter, length):
    sw_format_ver = dr_utils_dic.get("sw_format_ver")
    if sw_format_ver == MLX5_HW_CONNECTX_6DX:
        if dst_dw_offset > V1_TO_V2_HL_BOUND:
            dw_offset += V1_TO_V2_HL_DIFF

    end = left_shifter + length - 1
    return MDFY_HDR_FIELDS.get((dw_offset, left_shifter, end))



def dr_action_copy_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "Copy"}
    dst_dw_offset = int(action_dw_0[8 : 16], 2)
    dst_left_shifter = int(action_dw_0[18 : 24], 2) - MLX5_MODIFY_HEADER_V1_QW_OFFSET
    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    field = get_modify_hdr_field(dst_dw_offset, dst_left_shifter, length)

    if field != None:
        action["dst_field"] = field
    else:
        action["dst_offset"] = dst_dw_offset

    action["dst_left_shifter"] = dst_left_shifter
    action["length"] = length

    src_dw_offset = int(action_dw_1[8 : 16], 2)
    src_right_shifter = int(action_dw_1[18 : 24], 2) - MLX5_MODIFY_HEADER_V1_QW_OFFSET
    field = get_modify_hdr_field(src_dw_offset, src_right_shifter, length)

    if field != None:
        action["src_field"] = field
    else:
        action["src_offset"] = src_dw_offset

    action["src_right_shifter"] = src_right_shifter

    return action_pretiffy(action)

def dr_action_set_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "Set"}
    dw_offset = int(action_dw_0[8 : 16], 2)
    left_shifter = int(action_dw_0[18 : 24], 2) - MLX5_MODIFY_HEADER_V1_QW_OFFSET
    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    field = get_modify_hdr_field(dw_offset, left_shifter, length)

    if field != None:
        action["field"] = field
    else:
        action["dw_offset"] = dw_offset

    action["length"] = length
    action["left_shifter"] = left_shifter
    action["data"] = int(action_dw_1, 2)

    return action_pretiffy(action)

def dr_action_add_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "Add"}
    dw_offset = int(action_dw_0[8 : 16], 2)
    left_shifter = int(action_dw_0[18 : 24], 2) - MLX5_MODIFY_HEADER_V1_QW_OFFSET
    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    field = get_modify_hdr_field(dw_offset, left_shifter, length)

    if field != None:
        action["field"] = field
    else:
        action["dw_offset"] = dw_offset

    action["length"] = length
    action["left_shifter"] = left_shifter
    action["value"] = int(action_dw_1, 2)

    return action_pretiffy(action)

def dr_action_remove_by_size_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "Remove by size"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = MDFY_HDR_ANCHORS.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    action["outer_l4_removed"] = int(action_dw_0[16 : 17], 2)
    action["start_offset"] = int(action_dw_0[18 : 25], 2)
    action["size"] = int(action_dw_0[26 : 32], 2)

    return action_pretiffy(action)

def dr_action_remove_header2header_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "remove header2header"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    end_anchor = int(action_dw_0[18 : 24], 2)
    field = MDFY_HDR_ANCHORS.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    field = MDFY_HDR_ANCHORS.get(end_anchor)
    action["end_anchor"] = field if field != None else end_anchor
    action["decap"] = int(action_dw_0[28 : 29], 2)
    action["vni_to_cqe"] = int(action_dw_0[29 : 30], 2)
    action["qos_profile "] = int(action_dw_0[30 : 32], 2)

    return action_pretiffy(action)

def dr_action_insert_inline_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "insert with inline"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = MDFY_HDR_ANCHORS.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    end_anchor = int(action_dw_0[18 : 24], 2)
    field = MDFY_HDR_ANCHORS.get(end_anchor)
    action["end_anchor"] = field if field != None else end_anchor
    action["insert_data_inline"] = int(action_dw_1[0 : 32], 2)

    return action_pretiffy(action)

def dr_action_insert_pointer_parser(action):
    action_dw_0 = action[0 : 32]
    action_dw_1 = action[32 : 64]
    action = {"type" : "insert with pointer"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = MDFY_HDR_ANCHORS.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    end_anchor = int(action_dw_0[18 : 24], 2)
    field = MDFY_HDR_ANCHORS.get(end_anchor)
    action["end_anchor"] = field if field != None else end_anchor
    action["size"] = int(action_dw_0[24 : 29], 2)
    action["attributes"] = int(action_dw_0[29 : 32], 2)
    action["pointer"] = int(action_dw_1[0 : 32], 2)

    return action_pretiffy(action)


switch_ptrn_args_actions_parser = {
    DR_ACTION_PTRN_ARGS_NOP: dr_action_nop_parser,
    DR_ACTION_PTRN_ARGS_COPY: dr_action_copy_parser,
    DR_ACTION_PTRN_ARGS_SET: dr_action_set_parser,
    DR_ACTION_PTRN_ARGS_ADD: dr_action_add_parser,
    DR_ACTION_PTRN_ARGS_REMOVE_BY_SIZE: dr_action_remove_by_size_parser,
    DR_ACTION_PTRN_ARGS_REMOVE_HEADER_TO_HEADER: dr_action_remove_header2header_parser,
    DR_ACTION_PTRN_ARGS_INSERT_INLINE: dr_action_insert_inline_parser,
    DR_ACTION_PTRN_ARGS_INSERT_POINTER: dr_action_insert_pointer_parser,
}

def dr_ptrn_and_args_parser(arr):
    index = 0
    result = ""
    indent = get_indent_str() + (" " * 10)
    for _arr in arr:
        bin_action = hex_2_bin(_arr[2:])
        action_type = int(bin_action[0 : 8], 2)
        parser = switch_ptrn_args_actions_parser.get(action_type)
        if parser != None:
            res = parser(bin_action)
            result += "\n%s%s" % (indent,res)
        else:
            result += "\n%sUnknown: %s" % (indent, _arr)

    return result

def action_pretiffy(action):
    action_type = action.get("type")
    _str = action_type
    first = True
    for field in action:
        if field != "type":
            if first:
                _str += ': '
                first = False
            else:
                _str += ', '
            _str += field + ': '
            val = action.get(field)
            if type(val) is str:
                _str += val
            else:
                _str += hex(val)

    return _str
