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
from src.parsers.dr_ptrn_and_args_parser import dr_ptrn_and_args_parser
from src.dr_utilities import dr_dump_ctx

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
        return "FT devx id %s, dest_ft %s" % (
            _srd(self.data, "table_devx_id"),
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
        return "CTR(%s), index %s" % (out_str, _srd(self.data, "ctr_index"))


class dr_dump_action_tag(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "tag"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "TAG, value %s" % (_srd(self.data, "tag"))


class dr_dump_action_modify_header(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index", "single_action_opt",
                "num_of_ptrn_actions", "ptrn_idx", "arg_idx"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.ptrn_and_args_arr = []
        if self.data.get("num_of_ptrn_actions") != None:
            num_of_ptrn_actions = int(self.data.get("num_of_ptrn_actions"), 16)
            if num_of_ptrn_actions > 0:
                self.ptrn_and_args_arr = data[-num_of_ptrn_actions:]


    def add_dump_ctx(self, dump_ctx):
        self.dump_ctx = dump_ctx

    def dump_str(self):
        if self.data["single_action_opt"]:
            if int(self.data["single_action_opt"], 16) == 1:
                return "MODIFY_HDR, single modify action optimized"

        if len(self.ptrn_and_args_arr) > 0:
            out_str = dr_ptrn_and_args_parser(self.ptrn_and_args_arr)
            ptrn_idx = self.data.get("ptrn_idx")
            arg_idx = self.data.get("arg_idx")
            num_of_actions = self.data.get("num_of_ptrn_actions")
            return "MODIFY_HDR, num of actions: %s, ptrn_idx: %s, arg_idx: %s%s"\
                % (num_of_actions, ptrn_idx, arg_idx, out_str)

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
        return "VPORT, num %s" % (_srd(self.data, "vport_num"))


class dr_dump_action_decap_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DECAP_L2 "


class dr_dump_action_decap_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DECAP_L3, rewrite index %s" % (_srd(self.data, "rewrite_index"))


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
        return "ENCAP_L2(%s), devx obj id %s" % (out_str, _srd(self.data, "devx_obj_id"))


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
        return "ENCAP_L3(%s), devx obj id %s" % (out_str, _srd(self.data, "devx_obj_id"))

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
        return "METER, next flow table %s, devx obj id %s, rx_icm_addr %s rx_icm_addr %s" % (
            _srd(self.data, "next_ft"),
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))


class dr_dump_action_sampler(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "next_ft", "sample_tbl_devx_id", "devx_id", "rx_icm_addr",
                "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "SAMPLER, next flow table %s, sample table devx obj id %s, sampler devx obj id %s, rx_icm_addr %s " \
               "rx_icm_addr %s" % (
            _srd(self.data, "next_ft"),
            _srd(self.data, "sample_tbl_devx_id"),
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))


class dr_dump_action_dest_array(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "DEST_ARRAY, devx obj id %s, rx_icm_addr %s rx_icm_addr %s" % (
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))


class dr_dump_action_aso_flow_hit(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "flow_hit_aso"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "ASO, flow_hit_aso %s" % (
            _srd(self.data, "flow_hit_aso"))


class dr_dump_action_aso_flow_meter(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "flow_meter_aso"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "ASO, flow_meter_aso %s" % (
            _srd(self.data, "flow_meter_aso"))


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

class dr_dump_action_root_ft(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "ft_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "ROOT FT ID=%s" % (_srd(self.data, "ft_id"))


class dr_dump_action_match_range(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id",
                "hit_table_devx_id", "hit_ft",
                "miss_table_devx_id", "miss_ft", "definer_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self):
        return "Hit FT devx id %s, hit_ft %s, Miss FT devx id %s, miss_ft %s, definer id %s" % (
            _srd(self.data, "hit_table_devx_id"),
            _srd(self.data, "hit_ft"),
            _srd(self.data, "miss_table_devx_id"),
            _srd(self.data, "miss_ft"),
            _srd(self.data, "definer_id"))

