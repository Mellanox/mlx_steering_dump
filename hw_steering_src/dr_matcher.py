#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *
from hw_steering_src.dr_db import _fw_ste_indexes_arr, _matchers, _tbl_type_db,\
                                _config_args, _tbl_level_db, _col_matchers
from hw_steering_src.dr_rule import dr_parse_rules


class dr_parse_matcher():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "tbl_id", "num_of_mt",
                "end_ft_id", "col_matcher_id", "match_rtc_0_id", "match_ste_0_id",
                "match_rtc_1_id", "match_ste_1_id", "action_rtc_0_id", "action_ste_0_id",
                "action_rtc_1_id", "action_ste_1_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.id = self.data.get("id")
        self.nic_rx = None
        self.nic_tx = None
        self.attr = None
        self.match_template = None
        self.action_templates = []
        self.col_matcher_id = self.data.get("col_matcher_id")
        self.match_ste_0_id = None
        self.match_ste_1_id = None
        self.action_ste_0_id = None
        self.action_ste_1_id = None
        self.fix_data()
        self.save_to_db()


    def fix_data(self):
        tbl_level = _tbl_level_db.get(self.data.get("tbl_id"))
        if tbl_level == DR_ROOT_TBL_LEVEL:
            return

        ste_id = self.data.get("match_ste_0_id")
        if ste_id != '-1':
            self.match_ste_0_id = ste_id

        ste_id = self.data.get("match_ste_1_id")
        if ste_id != '-1':
            self.match_ste_1_id = ste_id

        ste_id = self.data.get("action_ste_0_id")
        if ste_id != '-1':
            self.action_ste_0_id = ste_id

        ste_id = self.data.get("action_ste_1_id")
        if ste_id != '-1':
            self.action_ste_1_id = ste_id


    def __eq__(self, other):
        return self.attr.priority == other.attr.priority


    def __lt__(self, other):
        return self.attr.priority < other.attr.priority


    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "id"]

        if verbosity > 1:
            _keys.extend(["end_ft_id"])
        if verbosity > 2:
            _keys.extend(["col_matcher_id", "num_of_mt"])

        return dump_obj_str(_keys, self.data)


    def dump_matcher_resources(self, verbosity, tabs):
        _keys = ["match_rtc_0_id", "match_ste_0_id"]

        if self.match_ste_1_id != None:
            _keys.extend(["match_rtc_1_id", "match_ste_1_id"])

        if self.action_ste_0_id != None:
            _keys.extend(["action_rtc_0_id", "action_ste_0_id"])

        if self.action_ste_1_id != None:
            _keys.extend(["action_rtc_1_id", "action_ste_1_id"])

        _str = tabs + "Resources: " + dump_obj_str(_keys, self.data)

        if self.col_matcher_id != "0x0":
            col_matcher = _matchers.get(self.col_matcher_id)
            _str += tabs +"Resources (C): " + dump_obj_str(_keys, col_matcher.data)

        return _str

    def tree_print(self, verbosity, tabs):
        if self.id in _col_matchers:
            return ''
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB
        tbl_level = _tbl_level_db.get(self.data.get("tbl_id"))
        col_matcher = _matchers.get(self.col_matcher_id)

        _str = _str + tabs + self.attr.dump_str(verbosity)
        if col_matcher:
            _str = _str + tabs + col_matcher.attr.dump_str(verbosity).replace(':', ' (C):')
        if verbosity > 2:
            _str = _str + self.dump_matcher_resources(verbosity, tabs)

        if tbl_level != DR_ROOT_TBL_LEVEL:
            if self.match_template != None:
                _str = _str + tabs + self.match_template.dump_str(tabs, verbosity)
            for at in self.action_templates:
                _str = _str + tabs + at.dump_str(tabs, verbosity)

        if _config_args.get("parse_hw_resources") and (tbl_level != DR_ROOT_TBL_LEVEL):
            _str = _str + dr_parse_rules(self, verbosity, tabs)
            if col_matcher:
                _str = _str + dr_parse_rules(col_matcher, verbosity, tabs)

        return _str

    def add_attr(self, attr):
        self.attr = attr

    def add_nic_rx(self, nic_rx):
        self.nic_rx = nic_rx

    def add_nic_tx(self, nic_tx):
        self.nic_tx = nic_tx

    def add_match_template(self, template):
        self.match_template = template

    def add_action_template(self, template):
        self.action_templates.append(template)

    def save_to_db(self):
        if self.match_ste_0_id != None:
            _fw_ste_indexes_arr.append(self.match_ste_0_id)

        if self.match_ste_1_id != None:
             _fw_ste_indexes_arr.append(self.match_ste_1_id)

        if self.action_ste_0_id != None:
            _fw_ste_indexes_arr.append(self.action_ste_0_id)

        if self.action_ste_1_id != None:
            _fw_ste_indexes_arr.append(self.action_ste_1_id)

        _matchers[self.id] = self

        if self.col_matcher_id != "0x0":
            _col_matchers.append(self.col_matcher_id)


    def get_fw_ste_0_index(self):
        return self.match_ste_0_id

    def get_fw_ste_1_index(self):
        return self.match_ste_1_id


class dr_parse_matcher_attr():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "matcher_id", "priority",
                "mode", "sz_row_log", "sz_col_log"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.priority = self.data.get("priority")
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


class dr_parse_matcher_match_template():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "matcher_id", "fc_sz", "flags"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.definer = None

    def dump_str(self, tabs, verbosity):
        _tabs = tabs + TAB
        _str = ':'
        if self.definer != None:
            definer_str = self.definer.dump_fields()
            if len(definer_str) != 0:
                _str = ':\n' + _tabs + definer_str
                if verbosity > 2:
                    _str += ", "
                _str = _str.replace(', ', '\n' + _tabs)

        if verbosity > 2:
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "flags",
                                 "fc_sz"], self.data).replace(":", _str)

        return dump_obj_str(["mlx5dr_debug_res_type", "id"],
                             self.data).replace(":", _str)

    def add_definer(self, definer):
        self.definer = definer


class dr_parse_matcher_action_template():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "matcher_id", "only_term",
                "num_of_action_stes", "num_of_actions"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.num_actions = int(self.data.get("num_of_actions"))
        if self.num_actions > 0:
            self.data["action_combinations"] = data[6]#Actions combinations start index is 6
            for ac in data[7:]:#Actions combinations start index is 6, 7 for the second
                self.data["action_combinations"] += ', ' + ac

    def dump_str(self, tabs, verbosity):
        _keys = ["mlx5dr_debug_res_type", "id"]
        if verbosity > 2:
            _keys.extend(["num_of_actions", "only_term", "num_of_action_stes"])

        _tabs = tabs + TAB
        _str = dump_obj_str(_keys, self.data)

        if self.num_actions > 0:
            _str += _tabs + 'Action combinations: ' + self.data.get("action_combinations") + '\n'

        return _str
