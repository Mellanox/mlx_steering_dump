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

from src.dr_utilities import _srd, dr_obj, print_dr
from src.dr_constants import DR_DUMP_REC_TYPE_ACTION_OBJS
from src.dr_prettify import pretty_ip,pretty_mac
from src.dr_utilities import _val
from src.parsers.mlx5_ifc_parser import mlx5_ifc_encap_decap, mlx5_ifc_modify_hdr
from src.dr_utilities import dr_dump_ctx

simple_output=True

def dr_rec_type_is_action(rec_type):
    if rec_type.startswith(DR_DUMP_REC_TYPE_ACTION_OBJS):
        return True
    return False


class dr_dump_action_unsupported(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "UNSUPPORTED_ACTION"


class dr_dump_action_drop(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DROP"


class dr_dump_action_ft(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "table_devx_id", "dest_ft"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "FlowTable index %s, dest_ft %s" % (
                _srd(self.data, "table_devx_id"),
                _srd(self.data, "dest_ft"))
        else:
            return "JUMP to Next Table %s" % (
                _srd(self.data, "dest_ft"))

class dr_dump_action_qp(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "qp_num"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "QP num %s" % (_srd(self.data, "qp_num"))


class dr_dump_action_devx_tir(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DEVX_TIR, ICM addr %s" % (_srd(self.data, "icm_addr"))


class dr_dump_action_ctr(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "ctr_index"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        if ( (_srd(self.data, "id")) in self.dump_ctx.counter.keys()):
            out_str = self.dump_ctx.counter[(_srd(self.data, "id"))]
        else:
            out_str = "counter"
        if not simple_output:
            return "counter(%s), index %s" % (out_str, _srd(self.data, "ctr_index"))
        else:
            return "counter(%s)" % (out_str)


class dr_dump_action_tag(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "tag"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "TAG, value %s" % (_srd(self.data, "tag"))


class dr_dump_action_modify_header(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index", "single_action_opt"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        if simple_output:
            if ( (_srd(self.data, "id")) in self.dump_ctx.modify_hdr.keys()):
                out_str = self.dump_ctx.modify_hdr[(_srd(self.data, "id"))].lstrip(',')
                return "MODIFY_HDR(hdr(%s))" % (out_str)
            else:
                return "MODIFY_HDR"

        if self.data["single_action_opt"]:
            if int(self.data["single_action_opt"], 16) == 1:
                return "MODIFY_HDR, single modify action optimized"

        if ( (_srd(self.data, "id")) in self.dump_ctx.modify_hdr.keys()):
            out_str = self.dump_ctx.modify_hdr[(_srd(self.data, "id"))].lstrip(',')
            return "MODIFY_HDR(hdr(%s)), rewrite index %s" % (out_str, (_srd(self.data, "rewrite_index")))
        else:
            return "MODIFY_HDR, rewrite index %s" % (_srd(self.data, "rewrite_index"))

class dr_dump_action_vport(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "vport_num"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        vport = int(_srd(self.data, "vport_num"), 16)
        #return "VPORT, num %s" % (_srd(self.data, "vport_num"))
        if vport == 0xffff:
            output = "pf"
        elif vport == 0xfffe:
            output = "ecpf"
        elif vport >= 0x8000:
            output = ("sf%s" % (vport - 0x8000))
        else:
            output = ("vf%s" % vport)
        return "output(%s)" % output


class dr_dump_action_decap_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DECAP"


class dr_dump_action_decap_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "DECAP_L3, rewrite index %s" % (_srd(self.data, "rewrite_index"))
        else:
            return "DECAP_L3"

class dr_dump_action_encap_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_obj_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        if ( (_srd(self.data, "id")) in self.dump_ctx.encap_decap.keys()):
           out_str = self.dump_ctx.encap_decap[(_srd(self.data, "id"))]
        else:
           out_str = "parse vxlan en/decap error!"
        if not simple_output:
            return "ENCAP(%s), index %s" % (out_str, _srd(self.data, "devx_obj_id"))
        else:
            return "ENCAP(%s)" % (out_str)


class dr_dump_action_encap_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_obj_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        if ( (_srd(self.data, "id")) in self.dump_ctx.encap_decap.keys()):
            out_str = self.dump_ctx.encap_decap[(_srd(self.data, "id"))]
        else:
            out_str = "parse vxlan en/decap error!"
        if not simple_output:
            return "ENCAP_L3(%s), index %s" % (out_str, _srd(self.data, "devx_obj_id"))
        else:
            return "ENCAP_L3(%s)" % (out_str)


class dr_dump_action_pop_vlan(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "POP_VLAN"


class dr_dump_action_push_vlan(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "vlan_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "PUSH_VLAN, vlan id %s" % (_srd(self.data, "vlan_id"))


class dr_dump_action_meter(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "next_ft", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "METER, next flow table %s, index %s, rx_icm_addr %s rx_icm_addr %s" % (
                _srd(self.data, "next_ft"),
                _srd(self.data, "devx_id"),
                _srd(self.data, "rx_icm_addr"),
                _srd(self.data, "tx_icm_addr"))
        else:
            return "LEGACY METER"

class dr_dump_action_sampler(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "next_ft", "sample_tbl_devx_id", "devx_id", "rx_icm_addr",
                "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "SAMPLER, next flow table %s, sample table index %s, sampler index %s, rx_icm_addr %s " \
                "rx_icm_addr %s" % (
                _srd(self.data, "next_ft"),
                _srd(self.data, "sample_tbl_devx_id"),
                _srd(self.data, "devx_id"),
                _srd(self.data, "rx_icm_addr"),
                _srd(self.data, "tx_icm_addr"))
        else:
            return "SAMPLER"

class dr_dump_action_dest_array(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "DEST_ARRAY, index %s, rx_icm_addr %s rx_icm_addr %s" % (
                _srd(self.data, "devx_id"),
                _srd(self.data, "rx_icm_addr"),
                _srd(self.data, "tx_icm_addr"))
        else:
            return "MIRROR"

class dr_dump_action_aso_flow_hit(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "flow_hit_aso"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "ASO, flow_hit_aso %s" % (
                _srd(self.data, "flow_hit_aso"))
        else:
            return "AGE"

class dr_dump_action_aso_flow_meter(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "flow_meter_aso"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        if not simple_output:
            return "ASO, flow_meter_aso %s" % (
                _srd(self.data, "flow_meter_aso"))
        else:
            return "METER"

class dr_dump_action_default_miss(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DEFAULT MISS"


class dr_dump_action_aso_ct(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "ASO CT devx_id %s" % (_srd(self.data, "devx_id"))


class dr_dump_counter(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type","id", "hits", "bytes"]
        self.data = dict(zip(keys, data))
        self.hits = str(self.data["hits"])
        self.bytes = str(self.data["bytes"])
        counter_str = "hits(%s), bytes(%s)" % (self.hits, self.bytes)

        self.data.pop("hits")
        self.data.pop("bytes")
        self.id = str(self.data["id"])
        self.data = counter_str

    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        return "counter"


class dr_dump_encap_decap(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "buf"]
        self.data = dict(zip(keys, data))
        str = mlx5_ifc_encap_decap(self.data["buf"])
        self.data.pop("buf")
        self.id = self.data["id"]
        self.data = str

    def dump_str(self):
       return "encap_decap"


class dr_dump_modify_hdr(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id",  "num", "buf"]
        self.data = dict(zip(keys, data))
        hdr_str = mlx5_ifc_modify_hdr(self.data["num"], self.data["buf"])
        self.data.pop("buf")
        self.data.pop("num")
        self.id = str(self.data["id"])
        self.data = hdr_str

    def dump_str(self):
        return "modify_hdr"
