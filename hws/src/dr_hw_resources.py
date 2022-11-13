#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _fw_ste_indexes_arr, _fw_ste_db, _stes_range_db, _term_dest_db, _stc_indexes_arr
from src.dr_ste import ste_hit_addr_calc


class dr_parse_fw_ste():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.ste_dic = {}

    def dump_str(self, verbosity):
        return dump_obj_str(["mlx5dr_debug_res_type", "id"],
                            self.data)

    def get_id(self):
        return self.data.get("id")

    def add_ste(self, ste):
        self.ste_dic[ste.get_addr()] = ste

    def init_fw_ste_db(self):
        _fw_ste_db[self.data.get("id")] = {}

    def add_stes_range(self, min_ste_addr, max_ste_addr):
        _stes_range_db[self.get_id()] = (min_ste_addr, max_ste_addr)


class dr_parse_address():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "address", "type", "id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_addr(self):
        return self.data.get('address')

    def get_type(self):
        return self.data.get('type')

    def get_id(self):
        return self.data.get('id')

    def load_to_db(self):
        _term_dest_db[self.get_addr()] = {'type': self.get_type(), 'id': int(self.get_id(), 16)}

class dr_parse_stc():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "type", "id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_id(self):
        return self.data.get("id")

    def load_to_db(self):
        _stc_indexes_arr.append(self.get_id())


#This dictionary holds action objects id location
#according to stc obj param
stc_param_id_loc_dic = {
    STC_ACTION_JUMP_TO_TIR: {'type': 'TIR', 'loc': (2,8)},
    STC_ACTION_JUMP_TO_FLOW_TABLE: {'type': 'FT', 'loc': (2,8)},
    STC_ACTION_JUMP_TO_VPORT: {'type': 'VPORT', 'loc': (4,8)},
}


def dr_parse_fw_stc_action_get_obj_id(raw):
    stc_param = raw[2:22]
    action_type = raw[40:42]

    obj = stc_param_id_loc_dic.get(action_type)
    if obj != None:
        id_loc = obj.get("loc")
        return {"type": obj.get("type"), "id": hex(int(stc_param[id_loc[0]:id_loc[1]], 16))}

    return None


def dr_parse_fw_stc_get_addr(raw):
    raw = hex_to_bin_str(raw, STE_SIZE_IN_BITS)
    next_table_base_63_48 = int(raw[96 : 112], 2)
    next_table_base_39_32 = int(raw[120 : 128], 2)
    next_table_base_31_5 = int(raw[128 : 155], 2)

    return hex(ste_hit_addr_calc(next_table_base_63_48, next_table_base_39_32, next_table_base_31_5))
