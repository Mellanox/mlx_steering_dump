#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *



class dr_parse_table():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "ctx_id", "ft_id", "type", "fw_ft_type", "level"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.matchers = []


    def dump_str(self, verbosity):
        if verbosity == 0:
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "ctx_id", "type", "level"], self.data)

        return dump_obj_str(["mlx5dr_debug_res_type", "id", "ctx_id", "type", "level", "fw_ft_type", "ft_id"], self.data)


    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + "\t"

        for m in self.matchers:
            _str = _str + m.tree_print(verbosity, tabs)

        return _str


    def add_matcher(self, matcher):
        self.matchers.append(matcher)
