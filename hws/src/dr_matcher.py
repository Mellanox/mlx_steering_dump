#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_rule import dr_parse_rules


def get_fw_ste_distribution_statistics(fw_ste_id, row_log_sz, col_log_sz):
    tbl_size = 1 << row_log_sz
    arr = [0] * (1 << col_log_sz)
    _str = str(arr)
    base_addr = _db._stes_range_db.get(fw_ste_id)
    if base_addr == None:
        return _str

    base_addr = int(base_addr[0], 16)
    ste_addr_db = _db._fw_ste_db.get(fw_ste_id)
    if ste_addr_db == None:
        return _str

    for addr in ste_addr_db:
        _addr = int(addr, 16)
        i = (_addr - base_addr) // tbl_size
        arr[i] += 1

    _str = str(arr)

    return _str

class dr_parse_matcher():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "tbl_id", "num_of_mt",
                "end_ft_id", "col_matcher_id", "match_rtc_0_id", "match_ste_0_id",
                "match_rtc_1_id", "match_ste_1_id", "action_rtc_0_id", "action_ste_0_id",
                "action_rtc_1_id", "action_ste_1_id", "aliased_rtc_0_id",
                "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.id = self.data.get("id")
        self.nic_rx = None
        self.nic_tx = None
        self.attr = None
        self.match_template = []
        self.action_templates = []
        self.col_matcher_id = self.data.get("col_matcher_id")
        self.match_ste_0_id = None
        self.match_ste_1_id = None
        self.action_ste_0_id = None
        self.action_ste_1_id = None
        self.aliased_rtc_0_id = None
        self.hash_definer = None
        self.fix_data()
        self.save_to_db()


    def fix_data(self):
        tbl_level = _db._tbl_level_db.get(self.data.get("tbl_id"))
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

        aliased_rtc_0_id = self.data.get("aliased_rtc_0_id")
        if aliased_rtc_0_id != None and aliased_rtc_0_id != '0':
            self.aliased_rtc_0_id = aliased_rtc_0_id

        rx_icm_addr = self.data.get("rx_icm_addr")
        if rx_icm_addr == None:
            rx_icm_addr = "0x0"

        tx_icm_addr = self.data.get("tx_icm_addr")
        if tx_icm_addr == None:
            tx_icm_addr = "0x0"

        _tbl_type = _db._tbl_type_db.get(self.data.get("tbl_id"))
        if _tbl_type == DR_TBL_TYPE_NIC_TX:
            tx_icm_addr = rx_icm_addr
            rx_icm_addr = "0x0"

        self.data["rx_icm_addr"] = rx_icm_addr
        self.data["tx_icm_addr"] = tx_icm_addr

        self.data["end_ft_id"] = hex(int(self.data.get("end_ft_id")))


    def __eq__(self, other):
        return self.attr.priority == other.attr.priority


    def __lt__(self, other):
        return self.attr.priority < other.attr.priority


    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "id"]

        if verbosity > 1:
            _keys.extend(["end_ft_id"])
            if self.data.get("rx_icm_addr") != "0x0":
                _keys.extend(["rx_icm_addr"])
            if self.data.get("tx_icm_addr") != "0x0":
                _keys.extend(["tx_icm_addr"])

        if verbosity > 2:
            _keys.extend(["col_matcher_id", "num_of_mt"])

        return dump_obj_str(_keys, self.data)


    def dump_matcher_statistcs(self):
        row_log_sz = self.attr.get_row_log_sz()
        col_log_sz = self.attr.get_col_log_sz()
        _str = "Statistics: distribution: "
        if self.match_ste_1_id != None:
            _str += "RX: "
        _str += get_fw_ste_distribution_statistics(self.match_ste_0_id, row_log_sz, col_log_sz)
        if self.match_ste_1_id != None:
            _str += ", TX: " + get_fw_ste_distribution_statistics(self.match_ste_1_id, row_log_sz, col_log_sz)
        _str += "\n"

        return _str


    def dump_matcher_resources(self, verbosity, tabs):
        _keys = ["match_rtc_0_id", "match_ste_0_id"]

        if self.aliased_rtc_0_id != None:
            _keys.append("aliased_rtc_0_id")
        if self.match_ste_1_id != None:
            _keys.extend(["match_rtc_1_id", "match_ste_1_id"])

        if self.action_ste_0_id != None:
            _keys.extend(["action_rtc_0_id", "action_ste_0_id"])

        if self.action_ste_1_id != None:
            _keys.extend(["action_rtc_1_id", "action_ste_1_id"])

        _str = tabs + "Resources: " + dump_obj_str(_keys, self.data)

        if self.col_matcher_id != "0x0":
            col_matcher = _db._matchers.get(self.col_matcher_id)
            _str += tabs +"Resources (C): " + dump_obj_str(_keys, col_matcher.data)

        if _config_args.get("statistics") == True:
            _str += tabs + self.dump_matcher_statistcs()

            if self.col_matcher_id != "0x0":
                _str += tabs + col_matcher.dump_matcher_statistcs().replace("Statistics:", "Statistics (C):")

        return _str

    def tree_print(self, verbosity, tabs):
        if self.id in _db._col_matchers:
            return ''
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB
        tbl_level = _db._tbl_level_db.get(self.data.get("tbl_id"))
        col_matcher = _db._matchers.get(self.col_matcher_id)

        _str = _str + tabs + self.attr.dump_str(verbosity)

        if tbl_level != DR_ROOT_TBL_LEVEL:
            if col_matcher and verbosity > 0:
                _str = _str + tabs + col_matcher.attr.dump_str(verbosity).replace(':', ' (C):')
            if verbosity > 0:
                _str = _str + self.dump_matcher_resources(verbosity, tabs)
            if self.hash_definer != None:
                definer_str = self.hash_definer.dump_fields()
                if len(definer_str) != 0:
                    definer_str = definer_str.replace(', ', '\n' + TAB + tabs)
                    _str += tabs + 'Hash fields:\n' + tabs + TAB + definer_str + '\n'
            for mt in self.match_template:
                _str = _str + tabs + mt.dump_str(tabs, verbosity)
            for at in self.action_templates:
                _str = _str + tabs + at.dump_str(tabs, verbosity)

        if _config_args.get("parse_hw_resources") and (tbl_level != DR_ROOT_TBL_LEVEL):
            _str += tabs + 'Rules:\n'
            _rules_str = dr_parse_rules(self, verbosity, tabs)
            if col_matcher:
                _rules_str += dr_parse_rules(col_matcher, verbosity, tabs)
            if _rules_str != "":
                _str += _rules_str
            else:
                _str += tabs + TAB + "No rules\n"

        return _str

    def add_attr(self, attr):
        self.attr = attr

    def add_nic_rx(self, nic_rx):
        self.nic_rx = nic_rx

    def add_nic_tx(self, nic_tx):
        self.nic_tx = nic_tx

    def add_match_template(self, template):
        self.match_template.append(template)

    def add_action_template(self, template):
        self.action_templates.append(template)

    def add_hash_definer(self, definer):
        self.hash_definer = definer

    def save_to_db(self):
        if self.match_ste_0_id != None:
            _db._fw_ste_indexes_arr.append(self.match_ste_0_id)

        if self.match_ste_1_id != None:
             _db._fw_ste_indexes_arr.append(self.match_ste_1_id)

        if self.action_ste_0_id != None:
            _db._fw_ste_indexes_arr.append(self.action_ste_0_id)

        if self.action_ste_1_id != None:
            _db._fw_ste_indexes_arr.append(self.action_ste_1_id)

        _db._matchers[self.id] = self

        if self.col_matcher_id != "0x0":
            _db._col_matchers.append(self.col_matcher_id)

        if self.data.get("rx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("rx_icm_addr")] = {"type": "FT", "id": self.data.get("end_ft_id")}
        if self.data.get("tx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("tx_icm_addr")] = {"type": "FT", "id": self.data.get("end_ft_id")}


    def get_fw_ste_0_index(self):
        return self.match_ste_0_id

    def get_fw_ste_1_index(self):
        return self.match_ste_1_id


class dr_parse_matcher_attr():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "matcher_id", "priority",
                "mode", "sz_row_log", "sz_col_log", "use_rule_idx",
                "flow_src", "insertion", "distribution"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        if self.data["flow_src"] == "1":
            self.data["flow_src"]  = "FDB ingress"
        elif self.data["flow_src"] == "2":
            self.data["flow_src"]  = "FDB egress"
        else:
            self.data["flow_src"]  = "default"
        self.priority = int(self.data.get("priority")) & 0xffffffff
        self.fix_data()

    def get_row_log_sz(self):
        return int(self.data.get("sz_row_log"))

    def get_col_log_sz(self):
        return int(self.data.get("sz_col_log"))

    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "priority", "log_sz"]
        if verbosity > 1:
            _keys.extend(["mode", "flow_src"])
        if verbosity > 2:
            _keys.extend(["insertion", "distribution"])

        return dump_obj_str(_keys, self.data)


    def fix_data(self):
        self.data["mode"] = "RULE" if self.data["mode"] == "0" else "HTABLE"
        self.data["insertion"] = "INDEX" if self.data.get("insertion") == "1" else "HASH"
        self.data["distribution"] = "LINEAR" if self.data.get("distribution") == "1" else "HASH"
        self.data["log_sz"] = "%sX%s" % (self.data.get("sz_row_log"), self.data.get("sz_col_log"))
        self.data["priority"] = hex(self.priority)


class dr_parse_matcher_match_template():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "matcher_id", "fc_sz", "flags", "fcr_sz"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.match_definer = None
        self.range_definer = None
        self.fix_data()

    def fix_data(self):
        if self.data.get("fcr_sz") == None:
            self.data["fcr_sz"] = "0"

    def dump_str(self, tabs, verbosity):
        _tabs = tabs + TAB
        __tabs = _tabs + TAB
        _str = ':'
        if self.match_definer != None:
            definer_str = self.match_definer.dump_fields()
            if len(definer_str) != 0:
                _str = ':\n' + _tabs + 'Match fields:\n' + __tabs + definer_str
                _str = _str.replace(', ', '\n' + __tabs)

            range_definer_str = ''
            if self.range_definer != None:
                range_definer_str = self.range_definer.dump_fields()
            if len(range_definer_str) != 0:
                _str += '\n' + _tabs + 'Range fields:\n' + __tabs + range_definer_str
                _str = _str.replace(', ', '\n' + __tabs)

        if verbosity > 2:
            if _str != ':':
                _str += '\n' + _tabs
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "flags",
                                 "fc_sz", "fcr_sz"], self.data).replace(":", _str)

        return dump_obj_str(["mlx5dr_debug_res_type", "id"],
                             self.data).replace(":", _str)

    def add_match_definer(self, definer):
        self.match_definer = definer

    def add_range_definer(self, definer):
        self.range_definer = definer


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
