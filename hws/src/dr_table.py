#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args


class dr_parse_table():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "ctx_id", "ft_id", "type",
                "fw_ft_type", "level", "local_ft_id", "rx_icm_addr",
                "tx_icm_addr", "local_rx_icm_addr", "local_tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.id = self.data.get("id")
        self.level = int(self.data.get("level"))
        self.fix_data()
        self.matchers = []
        self.col_matcher_ids = {}
        self.save_to_db()

    def __eq__(self, other):
        return self.level == other.level

    def __lt__(self, other):
        return self.level < other.level

    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "id", "type", "level"]
        if verbosity < 2:
            return dump_obj_str(_keys, self.data)

        if _config_args.get("shared_device") != None:
            _keys.extend(["local_ft_id"])
            if self.data.get("local_rx_icm_addr") != "0x0":
                _keys.extend(["local_rx_icm_addr"])
            if self.data.get("local_tx_icm_addr") != "0x0":
                _keys.extend(["local_tx_icm_addr"])

        _keys.extend(["ft_id"])
        if self.data.get("rx_icm_addr") != "0x0":
            _keys.extend(["rx_icm_addr"])
        if self.data.get("tx_icm_addr") != "0x0":
            _keys.extend(["tx_icm_addr"])

        return dump_obj_str(_keys, self.data)

    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        for m in sorted(self.matchers):
            if verbosity < 2 and m.data["id"] in self.col_matcher_ids:
                continue
            _str = _str + m.tree_print(verbosity, tabs)
            if verbosity < 2 and m.data["col_matcher_id"] != "0x0":
                self.col_matcher_ids[m.data["col_matcher_id"]] = ""

        return _str

    def fix_data(self):
        rx_icm_addr = self.data.get("rx_icm_addr")
        if rx_icm_addr == None:
            rx_icm_addr = "0x0"
        tx_icm_addr = self.data.get("tx_icm_addr")
        if tx_icm_addr == None:
            tx_icm_addr = "0x0"
        local_rx_icm_addr = self.data.get("local_rx_icm_addr")
        if local_rx_icm_addr == None:
            local_rx_icm_addr = "0x0"
        local_tx_icm_addr = self.data.get("local_tx_icm_addr")
        if local_tx_icm_addr == None:
            local_tx_icm_addr = "0x0"

        self.data["type"] = dr_table_type[int(self.data["type"])]
        self.data["ft_id"] = hex(int(self.data.get("ft_id"))) if self.data.get("ft_id") != None else "0x0"
        self.data["local_ft_id"] = hex(int(self.data.get("local_ft_id"))) if self.data.get("local_ft_id") != None else "0x0"

        if self.data.get("type") == DR_TBL_TYPE_NIC_TX:
            tx_icm_addr = rx_icm_addr
            rx_icm_addr = "0x0"
            if _config_args.get("shared_device") != None:
                local_tx_icm_addr = local_rx_icm_addr
                local_rx_icm_addr = "0x0"

        self.data["rx_icm_addr"] = rx_icm_addr
        self.data["tx_icm_addr"] = tx_icm_addr
        self.data["local_rx_icm_addr"] = local_rx_icm_addr
        self.data["local_tx_icm_addr"] = local_tx_icm_addr

    def add_matcher(self, matcher):
        self.matchers.append(matcher)

    def save_to_db(self):
        _db._tbl_type_db[self.id] = self.data.get("type")
        _db._tbl_level_db[self.id] = self.level
        if self.data.get("rx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("rx_icm_addr")] = {"type": "FT", "id": self.data.get("ft_id")}
        if self.data.get("tx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("tx_icm_addr")] = {"type": "FT", "id": self.data.get("ft_id")}
        if self.data.get("local_rx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("local_rx_icm_addr")] = {"type": "FT", "id": self.data.get("local_ft_id")}
        if self.data.get("local_tx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("local_tx_icm_addr")] = {"type": "FT", "id": self.data.get("local_ft_id")}
