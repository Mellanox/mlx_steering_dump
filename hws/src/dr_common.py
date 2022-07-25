#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

BYTE_SZ = 8
DW_SZ = 32
DW_SZ_IN_BYTES = 4
STE_SIZE_IN_BYTES = 64
STE_SIZE_IN_BITS = STE_SIZE_IN_BYTES * BYTE_SZ

DW_SELECTORS = 6
BYTE_SELECTORS = 8

STE_ALWAYS_HIT_ADDRESS = 0xFFFFFFFFE
RESOURCE_DUMP_SEGMENT_TYPE_STE = '0x0014003E'
RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN = '14003e'

STE_ENTRY_TYPE_MATCH = 0x4
STE_ENTRY_TYPE_JUMBO_MATCH = 0x5

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

MLX5DR_DEBUG_RES_TYPE_TABLE = "4100"

MLX5DR_DEBUG_RES_TYPE_MATCHER = "4200"
MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR = "4201"
MLX5DR_DEBUG_RES_TYPE_MATCHER_MATCH_TEMPLATE = "4202"
MLX5DR_DEBUG_RES_TYPE_DEFINER = "4203"
MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE = "4204"

#HWS HW resources
MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START = "4900"
MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END = "4901"
MLX5DR_DEBUG_RES_TYPE_FW_STE = "4920"
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
    MLX5DR_DEBUG_RES_TYPE_DEFINER: "Definer",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ACTION_TEMPLATE: "Action_template",
    MLX5DR_DEBUG_RES_TYPE_FW_STE: "FW_STE_OBJ",
    MLX5DR_DEBUG_RES_TYPE_STE: "STE",
}


def hex_to_bin_str(_n, _len):
    n = str(bin(int(_n, 16)))[2:]
    z = (_len - len(n)) * "0"
    return z + n


TAB = "    "

DR_HL_OUTER = '_o'
DR_HL_INNER = '_i'

MEM_MODE_MIN_MFT_VERSION = 'mft 4.20.0-00'
