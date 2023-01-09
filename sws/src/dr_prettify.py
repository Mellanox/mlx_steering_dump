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
import socket
import struct


def pretty_ip(ip):
    if len(ip) < 34:
        # IPv4
        ip_str = socket.inet_ntop(socket.AF_INET,
                                  struct.Struct('!I').pack(int(ip, 16)))
    else:
        # IPv6
        ip_bytes = struct.Struct('!QQ').pack(int(ip, 16) >> 64,
                                             int(ip, 16) & 0xffffffffffffffff)
        ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return ip_str


def pretty_mac(mac):
    mac_addr = "%s:%s:%s:%s:%s:%s" % (mac[2:4], mac[4:6], mac[6:8],
                                      mac[8:10], mac[10:12], mac[12:14])
    return mac_addr


def pretty_ip_protocol(p):
    switch = {0x06: "TCP",
              0x11: "UDP",
              0x2f: "GRE",
              0x33: "IPSEC",
              }

    protcol = int(p, 16)
    if protcol in switch.keys():
        return switch[protcol]
    else:
        return p


def prettify_fields(dic):
    for j in dic.keys():
        if "ip_protocol" in j:
            dic[j] = pretty_ip_protocol(dic[j])
            continue
        if "ip" in j and ("dst" in j or "src" in j):
            dic[j] = pretty_ip(dic[j])

        if "smac" in j or "dmac" in j:
            dic[j] = pretty_mac(dic[j])


def prettify_tag(tag):
    clean_tag = dict(filter(lambda elem: eval(elem[1]) != 0, tag.items()))
    prettify_fields(clean_tag)
    return clean_tag


def prettify_mask(mask):
    clean_mask = dict(filter(lambda elem: eval(elem[1]) != 0, mask.items()))
    return clean_mask


def lu_type_conv(hex_lu):
    switch = {
        "0x00": "terminate",
        "0x01": "port_ib_l2",
        "0x02": "ib_l3",
        "0x03": "ib_l3_ext",
        "0x04": "ib_l4",
        "0x05": "source_gvmi_qp",
        "0x06": "port_eth_l2_first",
        "0x07": "port_eth_l2_second",
        "0x08": "port_eth_l2_source_first",
        "0x09": "port_eth_l2_source_second",
        "0x0A": "eth_l2_tunneling",
        "0x0B": "eth_l2_config_headers_first",
        "0x0C": "eth_l2_config_headers_second",
        "0x0D": "eth_l3_ipv6_des_first",
        "0x0E": "eth_l3_ipv6_des_second",
        "0x0F": "eth_l3_ipv6_src_first",
        "0x10": "eth_l3_ipv6_src_second",
        "0x11": "eth_l3_ipv4_5_tuple_first",
        "0x12": "eth_l3_ipv4_5_tuple_second",
        "0x13": "eth_l4_first",
        "0x14": "eth_l4_second",
        "0x15": "mpls_first",
        "0x16": "gre",
        "0x17": "random_number",
        "0x18": "general_purpose_lookup_field",
        "0x19": "flex_parser_tunneling_header",
        "0x1a": "eoib_header",
        "0x1b": "port_eth_l2_by_decap",
        "0x1c": "port_eth_l2_source_by_decap",
        "0x1d": "eth_l2_config_headers_by_decap",
        "0x1e": "eth_l3_ipv6_des_by_decap",
        "0x1f": "eth_l3_ipv6_src_by_decap",
        "0x20": "eth_l3_ipv4_5_tuple_by_decap",
        "0x21": "eth_l4_by_decap",
        "0x22": "flex_parser_0",
        "0x23": "flex_parser_1",
        "0x24": "mpls_second",
        "0x25": "mpls_by_decup",
        "0x26": "mpls_extended",
        "0x27": "mpls_extended_second",
        "0x28": "mpls_extended_by_decap",
        "0x29": "eth_l3_ipv4_misc",
        "0x2a": "eth_l3_ipv4_misc_second",
        "0x2b": "eth_l3_ipv4_misc_by_decap",
        "0x2c": "eth_l4_misc",
        "0x2d": "eth_l4_misc_second",
        "0x2e": "eth_l4_misc_by_decap",
        "0x2f": "steering_registers_0",
        "0x30": "steering_registers_1",
        "0x31": "ipsec",
        "0x32": "ipsec_second",
        "0x33": "ipsec_by_decap",
        "0x34": "tunnel_header",
        "0x35": "ib_l3_source",
        "0x36": "eth_l2_src_dst",
        "0x37": "eth_l2_src_dst_second",
        "0x38": "eth_l2_src_dst_by_decap",
        "0x39": "dc_headers_0",
        "0x3a": "dc_headers_1",
        "0x3b": "dc_headers_2",
    }

    if hex_lu in switch.keys():
        return switch[hex_lu]
    else:
        return "Uknown lookup type"
