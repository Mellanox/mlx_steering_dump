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

import sys
from enum import Enum

# sw steering dump tool version
g_version = "1.0.1"
g_indent = 0
TAB = "   "


class mlx5_ifc_steering_format_version():
    MLX5_HW_CONNECTX_5 = 0x0
    MLX5_HW_CONNECTX_6DX = 0x1


class dr_ste_entry_format():
    DR_STE_TYPE_BWC_BYTE = 0x0
    DR_STE_TYPE_BWC_DW = 0x1
    DR_STE_TYPE_MATCH = 0x2


# Lookup type is built from 2B: [ Definer mode 1B ][ Definer index 1B ]
class dr_ste_v1_lu_type():
    DR_STE_V1_LU_TYPE_DONT_CARE = 0x000f
    DR_STE_V1_LU_TYPE_ETHL2_HEADERS_I = 0x0106
    DR_STE_V1_LU_TYPE_ETHL2_HEADERS_O = 0x0105
    DR_STE_V1_LU_TYPE_ETHL2_I = 0x0004
    DR_STE_V1_LU_TYPE_ETHL2_O = 0x0003
    DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_I = 0x000c
    DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_O = 0x000b
    DR_STE_V1_LU_TYPE_ETHL2_SRC_I = 0x0006
    DR_STE_V1_LU_TYPE_ETHL2_SRC_O = 0x0005
    DR_STE_V1_LU_TYPE_ETHL2_TNL = 0x0002
    DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_I = 0x0008
    DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_O = 0x0007
    DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_I = 0x000f
    DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_O = 0x000d
    DR_STE_V1_LU_TYPE_ETHL4_I = 0x000a
    DR_STE_V1_LU_TYPE_ETHL4_MISC_I = 0x0114
    DR_STE_V1_LU_TYPE_ETHL4_MISC_O = 0x0113
    DR_STE_V1_LU_TYPE_ETHL4_O = 0x0009
    DR_STE_V1_LU_TYPE_FLEX_PARSER_0 = 0x0111
    DR_STE_V1_LU_TYPE_FLEX_PARSER_1 = 0x0112
    DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER = 0x000e
    DR_STE_V1_LU_TYPE_GENERAL_PURPOSE = 0x010e
    DR_STE_V1_LU_TYPE_GRE = 0x010d
    DR_STE_V1_LU_TYPE_IBL3_EXT = 0x0102
    DR_STE_V1_LU_TYPE_IBL4 = 0x0103
    DR_STE_V1_LU_TYPE_INVALID = 0x00ff
    DR_STE_V1_LU_TYPE_IPV6_DES_I = 0x0108
    DR_STE_V1_LU_TYPE_IPV6_DES_O = 0x0107
    DR_STE_V1_LU_TYPE_IPV6_SRC_I = 0x010a
    DR_STE_V1_LU_TYPE_IPV6_SRC_O = 0x0109
    DR_STE_V1_LU_TYPE_MPLS_I = 0x010c
    DR_STE_V1_LU_TYPE_MPLS_O = 0x010b
    DR_STE_V1_LU_TYPE_NOP = 0x0000
    DR_STE_V1_LU_TYPE_SRC_QP_GVMI = 0x0104
    DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0 = 0x010f
    DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1 = 0x0110


class dr_dump_view(Enum):
    DR_DUMP_VIEW_RULE = 0,
    DR_DUMP_VIEW_TREE = 1,


# Enum of csv records types that can be parsed, same enum as in rdma-core providers/mlx5/dr_dbg.c
class dr_dump_rec_type(Enum):
    DR_DUMP_REC_TYPE_DOMAIN = 3000,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER = 3001,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR = 3002,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT = 3003,
    DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS = 3004,
    DR_DUMP_REC_TYPE_DOMAIN_SEND_RING = 3005,

    DR_DUMP_REC_TYPE_TABLE = 3100,
    DR_DUMP_REC_TYPE_TABLE_RX = 3101,
    DR_DUMP_REC_TYPE_TABLE_TX = 3102,

    DR_DUMP_REC_TYPE_MATCHER = 3200,
    DR_DUMP_REC_TYPE_MATCHER_MASK = 3201,
    DR_DUMP_REC_TYPE_MATCHER_RX = 3202,
    DR_DUMP_REC_TYPE_MATCHER_TX = 3203,
    DR_DUMP_REC_TYPE_MATCHER_BUILDER = 3204,

    DR_DUMP_REC_TYPE_RULE = 3300,
    DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V0 = 3301,
    DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V0 = 3302,
    DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V1 = 3303,
    DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V1 = 3304,
 
    DR_DUMP_REC_TYPE_ACTION_ENCAP_L2 = 3400,
    DR_DUMP_REC_TYPE_ACTION_ENCAP_L3 = 3401,
    DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR = 3402,
    DR_DUMP_REC_TYPE_ACTION_DROP = 3403,
    DR_DUMP_REC_TYPE_ACTION_QP = 3404,
    DR_DUMP_REC_TYPE_ACTION_FT = 3405,
    DR_DUMP_REC_TYPE_ACTION_CTR = 3406,
    DR_DUMP_REC_TYPE_ACTION_TAG = 3407,
    DR_DUMP_REC_TYPE_ACTION_VPORT = 3408,
    DR_DUMP_REC_TYPE_ACTION_DECAP_L2 = 3409,
    DR_DUMP_REC_TYPE_ACTION_DECAP_L3 = 3410,
    DR_DUMP_REC_TYPE_ACTION_DEVX_TIR = 3411,
    DR_DUMP_REC_TYPE_ACTION_PUSH_VLAN = 3412,
    DR_DUMP_REC_TYPE_ACTION_POP_VLAN = 3413,
    DR_DUMP_REC_TYPE_ACTION_METER = 3414,

    @classmethod
    def find_name(self, index):
        index = int(index)
        for x in dr_dump_rec_type:
            val = x.value[0]
            if (val == index):
                return x.name
        return None

    @classmethod
    def find_index(self, name):
        for x in dr_dump_rec_type:
            if (x.name == name):
                return x.value[0]
        return None


def _srd(cur_dict, key):
    # Safe Read from Dict (SRD)
    if (key in cur_dict.keys()):
        return str(cur_dict[key])
    else:
        return "None"


class dr_dump_ctx(object):
    domain = None
    table = None
    matcher = None
    rule = None


# Base class for all SW steering object that will be read from a CSV dump file.
# Abstract class only (don't create instance).
class dr_obj(object):
    def __init__(self):
        self.data = {}

    def get(self, field_name):
        return self.data[field_name]

    def set(self, field_name, value):
        self.data[field_name] = value

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


def inc_indent():
    global g_indent
    g_indent += 1


def dec_indent():
    global g_indent
    g_indent -= 1


def get_indet():
    return g_indent


def get_indent_str():
    global g_indent
    return TAB * g_indent



def print_dr(*args):
    global g_indent
    tab = TAB * g_indent
    str_ = tab + " ".join(map(str, args))
    sys.stdout.write(str_)


def dict_join_str(in_dict):
    attrs = []
    for k, v in in_dict.items():
        attrs.append(str(k) + ": " + str(v))

    return ', '.join(attrs)


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


def hex_2_bin(hex_str):
    arr = {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
           "4": "0100", "5": "0101", "6": "0110", "7": "0111",
           "8": "1000", "9": "1001", "a": "1010", "b": "1011",
           "c": "1100", "d": "1101", "e": "1110", "f": "1111"}
    bin_str = ""
    for i in range(0, len(hex_str)):
        bin_str += arr[hex_str[i]]
    return bin_str
