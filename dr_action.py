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

from dr_utilities import _srd, dr_obj, dr_dump_rec_type, print_dr


class dr_dump_action_drop(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + " "

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_ft(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "table_devx_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + " table devx id %s" % (_srd(self.data, "table_devx_id"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_qp(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "qp_num"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "qp num %s" % (_srd(self.data, "qp_num"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_devx_tir(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "icm_addr"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "ICM addr %s" % (_srd(self.data, "icm_addr"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_ctr(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "ctr_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "counter index %s" % (_srd(self.data, "ctr_index"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_tag(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "tag"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "mark/tag %s" % (_srd(self.data, "tag"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_modify_header(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "rewrite index %s" % (_srd(self.data, "rewrite_index"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_vport(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "vport_num"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "vport num %s" % (_srd(self.data, "vport_num"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_decup_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + " "

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_decup_l3(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "rewrite_index"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "rewrite index %s" % (_srd(self.data, "rewrite_index"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())


class dr_dump_action_encup_l2(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "rule_id", "devx_obj_id"]
        self.data = dict(zip(keys, data))

    def dump_str(self):
        action_type_str = dr_dump_rec_type.find_name(self.data["dr_dump_rec_type"])
        i = action_type_str.find("ACTION") + len("ACTION") + 1
        return action_type_str[i:] + "devx obj id %s" % (_srd(self.data, "devx_obj_id"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())

    def print_rule_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())
