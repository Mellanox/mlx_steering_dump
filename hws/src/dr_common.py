#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

import subprocess as sp
from src.dr_db import _config_args

BYTE_SZ = 8
DW_SZ = 32
DW_SZ_IN_BYTES = 4
STE_SIZE_IN_BYTES = 64
STE_SIZE_IN_BITS = STE_SIZE_IN_BYTES * BYTE_SZ
MODIFY_ARGUMENT_BYTES_SZ = MODIFY_PATTERN_BYTES_SZ = 8

DW_SELECTORS = 9
BYTE_SELECTORS = 8

STE_ALWAYS_HIT_ADDRESS = 0xFFFFFFFFE
RESOURCE_DUMP_SEGMENT_TYPE_STE = '0x0014003E'
RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN = '14003e'
RESOURCE_DUMP_SEGMENT_TYPE_STC_BIN = '14003c'
RESOURCE_DUMP_SEGMENT_TYPE_ACTION_STC_BIN = 'c003b'
RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_PAT_BIN = '1c1035'
RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_ARG_BIN = '14003d'

STE_ENTRY_TYPE_MATCH = 0x4
STE_ENTRY_TYPE_JUMBO_MATCH = 0x5
STE_ENTRY_TYPE_RANGE_MATCH = 0x7

DR_TBL_TYPE_NIC_RX = 'NIC_RX'
DR_TBL_TYPE_NIC_TX = 'NIC_TX'
DR_TBL_TYPE_FDB = 'FDB'

DR_ROOT_TBL_LEVEL = 0

dr_table_type = [DR_TBL_TYPE_NIC_RX, DR_TBL_TYPE_NIC_TX, DR_TBL_TYPE_FDB]

""" dump_obj_str(keys, data):
This functions print the data dictionary acording to the keys.
Parameters:
keys: an array of keys to be printed from the data dictionary.
data: a dictionary to print the data from acording to the keys.
Return:
Returns the output string.
"""
def dump_obj_str(keys, data):
    _str = ""
    length = len(keys)
    for i in range(length):
        key = keys[i]
        if key == "id":
            continue

        if key == "mlx5dr_debug_res_type":
            _str = _str + class_name_arr[data[key]]
            if "id" in keys:
                _str = _str + " " + data["id"]
            _str = _str + ": "
            continue

        _str = _str + key + " "
        if data[key] == None:
            _str = _str + "NONE"
        else:
            _str = _str + data[key]
        if i < (length - 1):
            _str = _str + ", "

    return _str + "\n"


MLX5DR_DEBUG_RES_TYPE_CONTEXT = "4000"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR = "4001"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS = "4002"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE = "4003"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING = "4004"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_STC = "4005"

MLX5DR_DEBUG_RES_TYPE_TABLE = "4100"

MLX5DR_DEBUG_RES_TYPE_MATCHER = "4200"
MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR = "4201"
MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE = "4202"
MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_MATCH_DEFINER = "4203"
MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE = "4204"
MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_HASH_DEFINER = "4205"
MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_RANGE_DEFINER = "4206"

#HWS HW resources
MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START = "4900"
MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END = "4901"
MLX5DR_DEBUG_RES_TYPE_ADDRESS = "4910"
MLX5DR_DEBUG_RES_TYPE_PATTERN = "4911"
MLX5DR_DEBUG_RES_TYPE_ARGUMENT = "4912"
MLX5DR_DEBUG_RES_TYPE_FW_STE = "4920"
MLX5DR_DEBUG_RES_TYPE_FW_STE_STATS = "4921"
MLX5DR_DEBUG_RES_TYPE_STE = "4930"


class_name_arr = {
    MLX5DR_DEBUG_RES_TYPE_CONTEXT: "Context",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR: "Attr",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS: "Caps",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE: "Send_engine",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING: "Send_ring",
    MLX5DR_DEBUG_RES_TYPE_TABLE: "Table",
    MLX5DR_DEBUG_RES_TYPE_MATCHER: "Matcher",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR: "Attr",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE: "Match_template",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_MATCH_DEFINER: "Definer",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE: "Action_template",
    MLX5DR_DEBUG_RES_TYPE_FW_STE: "FW_STE_OBJ",
    MLX5DR_DEBUG_RES_TYPE_STE: "STE",
}


DR_ACTION_NOPE = 0x0
DR_ACTION_COPY = 0x5
DR_ACTION_SET = 0x6
DR_ACTION_ADD = 0x7
DR_ACTION_REMOVE_BY_SIZE = 0x8
DR_ACTION_REMOVE_HEADER2HEADER = 0x9
DR_ACTION_INSERT_INLINE = 0xa
DR_ACTION_INSERT_POINTER = 0xb
DR_ACTION_FLOW_TAG = 0xc
DR_ACTION_ACCELERATED_MODIFY_LIST = 0xe
DR_ACTION_ASO = 0x12
DR_ACTION_COUNTER = 0x14

def hex_to_bin_str(_n, _len):
    n = str(bin(int(_n, 16)))[2:]
    z = (_len - len(n)) * "0"
    return z + n


TAB = "    "

DR_HL_OUTER = '_o'
DR_HL_INNER = '_i'

MEM_MODE_MIN_MFT_VERSION = 'mft 4.20.0-00'

STC_ACTION_JUMP_TO_TIR = '81'
STC_ACTION_JUMP_TO_FLOW_TABLE = '82'
STC_ACTION_JUMP_TO_VPORT = '85'


def hit_addr_calc(next_table_base_39_32, next_table_base_31_5):
    hit_addr = next_table_base_39_32 << 32
    hit_addr |= (next_table_base_31_5 << 5)
    hit_addr = (hit_addr >> 6) & 0xffffffff

    return hit_addr


def call_resource_dump(dev, dev_name, segment, index1, num_of_obj1, num_of_obj2, depth):
    _input = 'resourcedump dump -d ' + dev
    _input += ' --segment ' + segment
    _input += ' --index1 ' + index1
    if num_of_obj1 != None:
        _input += ' --num-of-obj1 ' + num_of_obj1
    if num_of_obj2 != None:
        _input += ' --num-of-obj2 ' + num_of_obj2
    if depth != None:
        _input += ' --depth=' + depth
    if _config_args.get("resourcedump_mem_mode"):
        _input += ' --mem ' + dev_name
        _input += ' --bin ' + _config_args.get("tmp_file_path")

    vhca_id = _config_args.get("_vhca_id")
    if vhca_id != None and vhca_id != "0":
        _input += ' --virtual-hca-id ' + vhca_id

    output = sp.getoutput(_input)
    if (len(output) >= 10) and ('Error' in output[0:10]):
        print(output)
        print('MFT Error')
        exit()

    return output


PAT_ARG_BULK_SIZE = 8


modify_pattern_field_dic = {
    0x1: "OUT_SMAC_47_16",
    0x2: "OUT_SMAC_15_0",
    0x3: "OUT_ETHERTYPE",
    0x4: "OUT_DMAC_47_16",
    0x5: "OUT_DMAC_15_0",
    0x6: "OUT_IP_DSCP",
    0x7: "OUT_TCP_FLAGS",
    0x8: "OUT_TCP_SPORT",
    0x9: "OUT_TCP_DPORT",
    0xA: "OUT_IPV4_TTL",
    0xB: "OUT_UDP_SPORT",
    0xC: "OUT_UDP_DPORT",
    0xD: "OUT_SIPV6_127_96",
    0xE: "OUT_SIPV6_95_64",
    0xF: "OUT_SIPV6_63_32",
    0x10: "OUT_SIPV6_31_0",
    0x11: "OUT_DIPV6_127_96",
    0x12: "OUT_DIPV6_95_64",
    0x13: "OUT_DIPV6_63_32",
    0x14: "OUT_DIPV6_31_0",
    0x15: "OUT_SIPV4",
    0x16: "OUT_DIPV4",
    0x17: "OUT_FIRST_VID",
    0x31: "IN_SMAC_47_16",
    0x32: "IN_SMAC_15_0",
    0x33: "IN_ETHERTYPE",
    0x34: "IN_DMAC_47_16",
    0x35: "IN_DMAC_15_0",
    0x36: "IN_IP_DSCP",
    0x37: "IN_TCP_FLAGS",
    0x38: "IN_TCP_SPORT",
    0x39: "IN_TCP_DPORT",
    0x3A: "IN_IPV4_TTL",
    0x3B: "IN_UDP_SPORT",
    0x3C: "IN_UDP_DPORT",
    0x3D: "IN_SIPV6_127_96",
    0x3E: "IN_SIPV6_95_64",
    0x3F: "IN_SIPV6_63_32",
    0x40: "IN_SIPV6_31_0",
    0x41: "IN_DIPV6_127_96",
    0x42: "IN_DIPV6_95_64",
    0x43: "IN_DIPV6_63_32",
    0x44: "IN_DIPV6_31_0",
    0x45: "IN_SIPV4",
    0x46: "IN_DIPV4",
    0x47: "OUT_IPV6_HOPLIMIT",
    0x48: "IN_IPV6_HOPLIMIT",
    0x49: "METADATA_REG_A",
    0x50: "METADATA_REG_B",
    0x51: "METADATA_REG_C_0",
    0x52: "METADATA_REG_C_1",
    0x53: "METADATA_REG_C_2",
    0x54: "METADATA_REG_C_3",
    0x55: "METADATA_REG_C_4",
    0x56: "METADATA_REG_C_5",
    0x57: "METADATA_REG_C_6",
    0x58: "METADATA_REG_C_7",
    0x59: "OUT_TCP_SEQ_NUM",
    0x5A: "IN_TCP_SEQ_NUM",
    0x5B: "OUT_TCP_ACK_NUM",
    0x5C: "IN_TCP_ACK_NUM",
    0x5D: "IPSEC_SYNDROME",
    0x5E: "OUT_ESP_SPI",
    0x5F: "IN_ESP_SPI",
    0x60: "LRH_SLID",
    0x61: "LRH_DLID",
    0x62: "GRH_FL",
    0x63: "GRH_TClass",
    0x64: "GRH_SGID_127_96",
    0x65: "GRH_SGID_95_64",
    0x66: "GRH_SGID_63_32",
    0x67: "GRH_SGID_31_0",
    0x68: "GRH_DGID_127_96",
    0x69: "GRH_DGID_95_64",
    0x6A: "GRH_DGID_63_32",
    0x6B: "GRH_DGID_31_0",
    0x6C: "BTH_PKey",
    0x6D: "BTH_DQPN",
    0x6E: "GTPU_TEID",
    0x6F: "OUT_EMD_TAG_DATA_0_1",
    0x70: "OUT_EMD_TAG_DATA_2_5",
    0x71: "NISP_SYNDROME",
    0x72: "MACSEC_SYNDROME",
    0x73: "OUT_IP_ECN",
    0x74: "IN_IP_ECN",
    0x75: "TUNNEL_HDR_DW_1",
    0x76: "GTPU_FIRST_EXT_DW_0",
    0x77: "NISP_HEADER_0",
    0x78: "NISP_HEADER_1",
    0x79: "NISP_HEADER_2",
    0x7A: "NISP_HEADER_3",
    0x7B: "NISP_HEADER_4",
    0x7C: "NISP_HEADER_5",
    0x7D: "NISP_HEADER_6",
    0x7E: "NISP_HEADER_7",
    0x7F: "NISP_HEADER_8",
    0x80: "NISP_HEADER_9",
    0x81: "HASH_RESULT",
    0x82: "OUT_ESP_SEQ_NUM",
    0x83: "IN_ESP_SEQ_NUM",
    0x84: "IN_TUNNEL_HDR_DW_1",
    0x100: "IN2_SMAC_47_16",
    0x101: "IN2_SMAC_15_0",
    0x102: "IN2_ETHERTYPE",
    0x103: "IN2_DMAC_47_16",
    0x104: "IN2_DMAC_15_0",
    0x105: "IN2_IP_DSCP",
    0x106: "IN2_TCP_FLAGS",
    0x107: "IN2_TCP_SPORT",
    0x108: "IN2_TCP_DPORT",
    0x109: "IN2_IPV4_TTL",
    0x10A: "IN2_UDP_SPORT",
    0x10B: "IN2_UDP_DPORT",
    0x10C: "IN2_SIPV6_127_96",
    0x10D: "IN2_SIPV6_95_64",
    0x10E: "IN2_SIPV6_63_32",
    0x10F: "IN2_SIPV6_31_0",
    0x110: "IN2_DIPV6_127_96",
    0x111: "IN2_DIPV6_95_64",
    0x112: "IN2_DIPV6_63_32",
    0x113: "IN2_DIPV6_31_0",
    0x114: "IN2_SIPV4",
    0x115: "IN2_DIPV4",
    0x116: "IN2_IPV6_HOPLIMIT",
    0x117: "IN2_TCP_SEQ_NUM",
    0x118: "IN2_TCP_ACK_NUM",
    0x119: "IN2_ESP_SPI",
    0x11A: "IN2_IP_ECN",
    0x11B: "IN2_ESP_SEQ_NUM",
}

modify_pattern_anchor_dic = {
    0x0: "PACKET_START",
    0x1: "MAC_START",
    0x2: "FIRST_VLAN",
    0x3: "SECOND_VLAN",
    0x4: "FIRST_CFG_ETHERTYPE",
    0x5: "SECOND_CFG_ETHERTYPE",
    0x6: "FIRST_MPLS",
    0x7: "IP_START",
    0x8: "ESP",
    0x9: "TCP_UDP_START",
    0xA: "TUNNEL_HEADER_START",
    0xB: "FlexParser0",
    0xC: "FlexParser1",
    0xD: "FlexParser2",
    0xE: "FlexParser3",
    0xF: "FlexParser4",
    0x10: "FlexParser5",
    0x11: "FlexParser6",
    0x12: "FlexParser7",
    0x13: "IN_MAC_START",
    0x14: "IN_FIRST_VLAN",
    0x15: "IN_SECOND_VLAN",
    0x16: "IN_FIRST_CFG_ETHERTYPE",
    0x17: "IN_SECOND_CFG_ETHERTYPE",
    0x18: "IN_FIRST_MPLS",
    0x19: "IN_IP_START",
    0x1A: "IN_TCP_UDP_START",
    0x1B: "L4_PAYLOAD_START",
    0x1C: "IN_L4_PAYLOAD_START",
    0x1D: "MACSEC",
    0x1E: "NISP",
    0x1F: "NISP_PAYLOAD",
    0x20: "L2_END",
    0x21: "IN_L2_END",
    0x22: "FIRST_CFG_ETHERTYPE_END",
    0x23: "SECOND_CFG_ETHERTYPE_END",
    0x24: "IN_FIRST_CFG_ETHER-TYPE_END",
    0x25: "IN_SECOND_CFG_ETHER-TYPE_END",
    0x26: "MPLS_END",
    0x27: "IN_MPLS_END",
    0x28: "IP_END",
    0x29: "IN_IP_END",
    0x2A: "ESP_END",
    0x2B: "TUNNEL_HEADER_END",
    0x2C: "MACSEC_END",
    0x2D: "IN2_MAC_START",
    0x2E: "IN2_FIRST_VLAN",
    0x2F: "IN2_SECOND_VLAN",
    0x30: "IN2_FIRST_CFG_ETHERTYPE",
    0x31: "IN2_SECOND_CFG_ETHERTYPE",
    0x32: "IN2_MPLS",
    0x33: "IN2_IP_START",
    0x34: "IN2_ESP",
    0x35: "IN2_TCP_UDP_START",
    0x36: "IN_TUNNEL_HEADER_START",
    0x37: "IN2_L2_END",
    0x38: "IN2_FIRST_CFG_ETHER-TYPE_END",
    0x39: "IN2_SECOND_CFG_ETHER-TYPE_END",
    0x3A: "IN2_MPLS_END",
    0x3B: "IN2_IP_END",
}


FW_VERSION_MAJOR_CX7 = 28
FLEX_PARSER_0_HL_OFFSET = 137
V1_TO_V2_HL_OFFSET_DIFF = 4


PARSING_THE_RULES_STR = "Parsing the rules:      "
DUMPING_HW_RESOURCES = "Dumping HW resources:   "
OUTPUT_FILE_STR = "Output file:            "
PARSED_OUTPUT_FILE_STR = "Parsed output file:     "
