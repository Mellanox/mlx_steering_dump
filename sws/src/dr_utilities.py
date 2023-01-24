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
import ctypes
import re
from src.dr_prettify import pretty_ip, pretty_mac

# sw steering dump tool version
g_version = "1.0.1"
g_indent = 0
TAB = "   "
COLORED_PRINTS = False


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
    counter = {}
    encap_decap = {}
    modify_hdr = {}


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
        print_dr(dr_print_color.RESET, self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.RESET, self.dump_str())


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


def set_colored_prints():
    global COLORED_PRINTS
    COLORED_PRINTS = True


class dr_print_color():
    color = {
        'darkwhite': "\033[0;37m",
        'darkyellow': "\033[0;33m",
        'darkgreen': "\033[1;32m",
        'darkblue': "\033[1;34m",
        'darkcyan': "\033[1;36m",
        'darkred': "\033[2;31m",
        'darkmagenta': "\033[0;35m",
        'off': "\033[0;0m"
    }

    DOMAIN = color["darkwhite"]
    TABLE = color["darkyellow"]
    MATCHER = color["darkblue"]
    MATCHER_MASK = color["darkblue"]
    RULE = color["darkgreen"]
    RULE_MATCH = color["darkgreen"]
    RULE_ACTIONS = color["darkgreen"]
    ERROR = color["darkred"]
    RESET = color["off"]


def print_dr(color, *args):
    global g_indent
    tab = TAB * g_indent
    str_ = tab + " ".join(map(str, args))

    if COLORED_PRINTS == True:
        sys.stdout.write(color)

    sys.stdout.write(str_)
    if COLORED_PRINTS == True:
        sys.stdout.write(dr_print_color.RESET)


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
    # To save the first zeroes from being compressed by 'bin'
    hex_str = 'f' + hex_str
    # convert to binary and remove "0b1111"
    bin_str = bin(int(hex_str, 16))[6:]
    return bin_str


#Use the % for printing instead of hex() func here to not get the trailing L for Long numbers
def to_hex(_int):
    return "0x%x" % _int

#Use this struct to save info and access from everywhere
dr_utils_dic = {}
