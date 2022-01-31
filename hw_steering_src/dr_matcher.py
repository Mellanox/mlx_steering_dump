#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *


class dr_parse_matcher():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "tbl_id", "num_of_mt",
                "end_ft_id", "col_matcher_id", "rtc_0_id", "ste_0_id",
                "rtc_1_id", "ste_1_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.nic_rx = None
        self.nic_tx = None
        self.attr = None
        self.template = None

    def dump_str(self, verbosity):
        if verbosity == 0:
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "tbl_id"],
                                self.data)

        if verbosity == 1:
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "tbl_id",
                                 "num_of_mt"], self.data)

        return dump_obj_str(["mlx5dr_debug_res_type", "id", "tbl_id",
                             "num_of_mt", "end_ft_id", "col_matcher_id"],
                             self.data)

    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        _str = _str + tabs + self.attr.dump_str(verbosity)
        if self.nic_rx != None and verbosity > 0:
            _str = _str + tabs + self.nic_rx.dump_str(verbosity)
        if self.nic_tx != None and verbosity > 0:
            _str = _str + tabs + self.nic_tx.dump_str(verbosity)
        if self.template != None:
            _str = _str + tabs + self.template.dump_str(verbosity)

        return _str

    def add_attr(self, attr):
        self.attr = attr

    def add_nic_rx(self, nic_rx):
        self.nic_rx = nic_rx

    def add_nic_tx(self, nic_tx):
        self.nic_tx = nic_tx

    def add_template(self, template):
        self.template = template


class dr_parse_matcher_attr():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "matcher_id", "priority",
                "mode", "sz_row_log", "sz_col_log"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.fix_data()

    def dump_str(self, verbosity):
        if verbosity > 0:
            return dump_obj_str(["mlx5dr_debug_res_type",
                                 "priority", "mode", "sz_row_log",
                                 "sz_col_log"], self.data)

        return dump_obj_str(["mlx5dr_debug_res_type",
                             "priority", "mode"], self.data)

    def fix_data(self):
        self.data["mode"] = "RULE" if self.data["mode"] == "0" else "HTABLE"


class dr_parse_matcher_nic():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "matcher_id", "rtc_id", "ste_obj_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self, verbosity):
        if verbosity == 1:
            return dump_obj_str(["mlx5dr_debug_res_type", "matcher_id",
                                 "rtc_id"], self.data)
        elif verbosity > 1:
            return dump_obj_str(["mlx5dr_debug_res_type", "matcher_id",
                                 "rtc_id", "ste_obj_id"], self.data)

        return ""


class dr_parse_matcher_template():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "matcher_id", "fc_sz", "flags"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.definer = None

    def dump_str(self, verbosity):
        _str = ":"
        if self.definer != None:
            definer_str = str(self.definer.dump_fields())
            if len(definer_str) != 0:
                _str = ": " + self.definer.dump_fields() + ", "
        if verbosity > 0:
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "flags",
                                 "fc_sz"], self.data).replace(":", _str)

        return dump_obj_str(["mlx5dr_debug_res_type", "id",
                             "flags"], self.data).replace(":", _str)

    def add_definer(self, definer):
        self.definer = definer
