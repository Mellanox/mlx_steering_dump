# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _tbl_type_db, _tbl_level_db


class dr_parse_table:
    def __init__(self, data):
        keys = [
            "mlx5dr_debug_res_type",
            "id",
            "ctx_id",
            "ft_id",
            "type",
            "fw_ft_type",
            "level",
            "local_ft_id",
        ]
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
        if verbosity == 0:
            return dump_obj_str(
                ["mlx5dr_debug_res_type", "id", "ctx_id", "type", "level"], self.data
            )

        return dump_obj_str(
            [
                "mlx5dr_debug_res_type",
                "id",
                "ctx_id",
                "type",
                "level",
                "ft_id",
                "local_ft_id",
            ],
            self.data,
        )

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
        self.data["type"] = dr_table_type[int(self.data["type"])]

    def add_matcher(self, matcher):
        self.matchers.append(matcher)

    def save_to_db(self):
        _tbl_type_db[self.id] = self.data.get("type")
        _tbl_level_db[self.id] = self.level
