#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *
from hw_steering_src.dr_db import _fw_ste_indexes_arr

class dr_parse_fw_ste():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.ste_dic = {}

    def dump_str(self, verbosity):
        return dump_obj_str(["mlx5dr_debug_res_type", "id"],
                            self.data)

    def add_ste(self, ste):
        self.ste_dic[ste.get_addr()] = ste
