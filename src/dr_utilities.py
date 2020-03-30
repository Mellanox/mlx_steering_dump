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
    DR_DUMP_REC_TYPE_RULE_RX_ENTRY = 3301,
    DR_DUMP_REC_TYPE_RULE_TX_ENTRY = 3302,

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
