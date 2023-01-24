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

from src.dr_utilities import _srd, dec_indent, dr_obj, inc_indent, print_dr, dr_print_color, dr_utils_dic
from src.dr_constants import DR_DUMP_REC_TYPE_DOMAIN_OBJS


def dr_rec_type_is_domain(rec_type):
    if rec_type.startswith(DR_DUMP_REC_TYPE_DOMAIN_OBJS):
        return True
    return False


def domain_type_str(type_str):
    switch = {"0": "NIC_RX",
              "1": "NIC_TX",
              "2": "FDB",
              }
    if type_str not in switch.keys():
        print("Err: Unsupported domain type")
        exit(-1)
    return switch[type_str]


class dr_dump_domain(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "type", "gvmi", "support_sw_steering", "package_version", "dev_name", "flags", "num_ste_buddy", "num_mh_buddy", "num_ptrn_buddy", "sw_format_ver"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.fix_data()
        self.table_list = []
        self.dev_attr = None
        self.caps = None
        self.send_ring = None
        self.vports = []
        self.flex_parsers = []
        sw_format_ver = self.data.get("sw_format_ver")
        if sw_format_ver != None:
            dr_utils_dic["sw_format_ver"] = int(sw_format_ver);

    def dump_str(self):
        return "domain %s: type: %s, gvmi: %s, support_sw_steering %s, dev_name %s, package_version %s, flags %s, ste_buddies %s, mh_buddies %s, ptrn_buddies %s\n" % (
            _srd(self.data, "id"),
            _srd(self.data, "type"),
            _srd(self.data, "gvmi"),
            _srd(self.data, "support_sw_steering"),
            _srd(self.data, "dev_name"),
            _srd(self.data, "package_version"),
            _srd(self.data, "flags"),
            _srd(self.data, "num_ste_buddy"),
            _srd(self.data, "num_mh_buddy"),
            _srd(self.data, "num_ptrn_buddy"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(dr_print_color.DOMAIN, self.dump_str())
        inc_indent()
        if verbose > 1:
            if self.dev_attr:
                print_dr(dr_print_color.DOMAIN, self.dev_attr.dump_string())
            if self.caps:
                print_dr(dr_print_color.DOMAIN, self.caps.dump_string())
            if self.send_ring:
                print_dr(dr_print_color.DOMAIN, self.send_ring.dump_string())
        if verbose > 2:
            if len(self.flex_parsers) > 0:
                for f_p in self.flex_parsers:
                    print_dr(dr_print_color.DOMAIN, f_p.dump_string())
            if len(self.vports) > 0:
                for vport in self.vports:
                    print_dr(dr_print_color.DOMAIN, vport.dump_string())

        inc_indent()
        for t in self.table_list:
            dump_ctx.table = t
            dump_ctx.matcher = None
            dump_ctx.rule = None
            t.print_tree_view(dump_ctx, verbose, raw)

        dec_indent()
        dec_indent()

    def print_rule_view(self, dump_ctx, verbose, raw):
        for t in self.table_list:
            dump_ctx.table = t
            dump_ctx.matcher = None
            dump_ctx.rule = None
            t.print_rule_view(dump_ctx, verbose, raw)

    def fix_data(self):
        self.data["type"] = domain_type_str(self.data["type"])
        self.data["gvmi"] = hex(int(self.data["gvmi"], 16))
        self.data["support_sw_steering"] = True if self.data["support_sw_steering"] is "1" else False

    def add_table(self, table):
        self.table_list.append(table)

    def add_send_ring(self, send_ring):
        self.send_ring = send_ring

    def add_dev_attr(self, attr):
        self.dev_attr = attr

    def add_caps(self, caps):
        self.caps = caps

    def add_vport(self, vport):
        self.vports.append(vport)

    def add_flex_parser(self, flex_p):
        self.flex_parsers.append(flex_p)


class dr_dump_domain_info_dev_attr(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "domain_id", "ports_num", "fw_version"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        return "device: ports_num %s, FW version %s\n" % (
            _srd(self.data, "ports_num"),
            _srd(self.data, "fw_version"))


class dr_dump_domain_info_flex_parser(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "domain_id", "name", "value"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        return "flex parser: name %s, value %s\n" % (
            _srd(self.data, "name"),
            _srd(self.data, "value"))


class dr_dump_domain_info_caps(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "domain_id", "gvmi", "nic_rx_drop_address", "nic_tx_drop_address", "flex_protocols",
                "num_vports", "eswitch_manager"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        flex_str = felx_parser_dump_string(int(self.data["flex_protocols"], 16))

        return "caps: eswitch_manager %s, num_vports %s, flex_protocols: %s, nic_rx_drop_address %s, " \
               "nic_tx_drop_address %s\n" % (
            _srd(self.data, "eswitch_manager"),
            _srd(self.data, "num_vports"),
            flex_str,
            _srd(self.data, "nic_rx_drop_address"),
            _srd(self.data, "nic_tx_drop_address"))


class dr_dump_domain_info_vport(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "domain_id", "index", "gvmi", "icm_addr_rx", "icm_addr_tx"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        return "vport: index %s, gvmi %s, icm_addr_rx %s, icm_addr_tx %s\n" % (
            _srd(self.data, "index"),
            _srd(self.data, "gvmi"),
            _srd(self.data, "icm_addr_rx"),
            _srd(self.data, "icm_addr_tx"))


class dr_dump_domain_send_ring(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "domain_id", "cq_num", "qp_num"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_string(self):
        return "send ring: CQ num %s, QP num %s\n" % (
            _srd(self.data, "cq_num"),
            _srd(self.data, "qp_num"))


def dr_matcher_supp_flex_parser_vxlan_gpe(flex_protocols):
    MLX5_FLEX_PARSER_VXLAN_GPE_ENABLED = 1 << 7
    return flex_protocols & MLX5_FLEX_PARSER_VXLAN_GPE_ENABLED


def dr_matcher_supp_flex_parser_geneve(flex_protocols):
    MLX5_FLEX_PARSER_GENEVE_ENABLED = 1 << 3
    return flex_protocols & MLX5_FLEX_PARSER_GENEVE_ENABLED


def dr_matcher_supp_flex_parser_icmp_v4(flex_protocols):
    MLX5_FLEX_PARSER_ICMP_V4_ENABLED = 1 << 8
    return flex_protocols & MLX5_FLEX_PARSER_ICMP_V4_ENABLED


def dr_matcher_supp_flex_parser_icmp_v6(flex_protocols):
    MLX5_FLEX_PARSER_ICMP_V6_ENABLED = 1 << 9
    return flex_protocols & MLX5_FLEX_PARSER_ICMP_V6_ENABLED


def felx_parser_dump_string(flex_protocols):
    dump = ""
    if dr_matcher_supp_flex_parser_vxlan_gpe(flex_protocols):
        dump += "tnl_vxlan_gpe, "

    if dr_matcher_supp_flex_parser_geneve(flex_protocols):
        dump += "tnl_geneve, "

    if dr_matcher_supp_flex_parser_icmp_v4(flex_protocols):
        dump += "icmp_v4 -> flex_parser_1, "

    if dr_matcher_supp_flex_parser_icmp_v6(flex_protocols):
        dump += "icmp_v6 -> flex_parser_1, "

    if dump != "":
        return "supports " + dump
