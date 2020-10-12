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
from src.dr_constants import DR_DUMP_REC_TYPE_ACTIONS

def dr_rec_type_is_action(rec_type):
    if rec_type.startswith(DR_DUMP_REC_TYPE_ACTIONS):
        return True
    return False


class dr_dump_action_drop(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "DROP"


class dr_dump_action_ft(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "table_devx_id", "dest_ft"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "FT devx id %s, dest_ft %s" % (
            _srd(self.data, "table_devx_id"),
            _srd(self.data, "dest_ft"))


class dr_dump_action_qp(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "qp_num"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "QP num %s" % (_srd(self.data, "qp_num"))


class dr_dump_action_devx_tir(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "icm_addr"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "DEVX_TIR, ICM addr %s" % (_srd(self.data, "icm_addr"))


class dr_dump_action_ctr(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "ctr_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "CTR, index %s" % (_srd(self.data, "ctr_index"))


class dr_dump_action_tag(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "tag"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "TAG, value %s" % (_srd(self.data, "tag"))


class dr_dump_action_modify_header(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "MODIFY_HDR, rewrite index %s" % (_srd(self.data, "rewrite_index"))


class dr_dump_action_vport(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "vport_num"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "VPORT, num %s" % (_srd(self.data, "vport_num"))


class dr_dump_action_decap_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "DECAP_L2 "


class dr_dump_action_decap_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "DECAP_L3, rewrite index %s" % (_srd(self.data, "rewrite_index"))


class dr_dump_action_encap_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_obj_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "ENCAP_L2, devx obj id %s" % (_srd(self.data, "devx_obj_id"))


class dr_dump_action_encap_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_obj_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "ENCAP_L3, devx obj id %s" % (_srd(self.data, "devx_obj_id"))


class dr_dump_action_pop_vlan(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "POP_VLAN"


class dr_dump_action_push_vlan(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "vlan_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "PUSH_VLAN, vlan id %s" % (_srd(self.data, "vlan_id"))


class dr_dump_action_meter(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "next_ft", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "METER, next flow table %s, devx obj id %s, rx_icm_addr %s rx_icm_addr %s" %(
            _srd(self.data, "next_ft"),
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))

class dr_dump_action_sampler(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "next_ft", "sample_tbl_devx_id", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "SAMPLER, next flow table %s, sample table devx obj id %s, sampler devx obj id %s, rx_icm_addr %s rx_icm_addr %s" %(
            _srd(self.data, "next_ft"),
            _srd(self.data, "sample_tbl_devx_id"),
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))

class dr_dump_action_dest_array(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        return "DEST_ARRAY, devx obj id %s, rx_icm_addr %s rx_icm_addr %s" %(
            _srd(self.data, "devx_id"),
            _srd(self.data, "rx_icm_addr"),
            _srd(self.data, "tx_icm_addr"))
