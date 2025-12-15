#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args
from src.dr_common_functions import *


class dr_parse_ft_anchor():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "ft_id", "rx_icm_addr", "tx_icm_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def load_to_db(self):
        ft_id = self.data.get("ft_id")
        rx_icm_addr = self.data.get("rx_icm_addr")
        tx_icm_addr = self.data.get("tx_icm_addr")
        _db._ft_idx_dic[ft_id] = (rx_icm_addr, tx_icm_addr)
        if rx_icm_addr != "0x0":
            _db._term_dest_db[rx_icm_addr] = {"type": "FT", "id": ft_id}
        if tx_icm_addr != "0x0":
            _db._term_dest_db[tx_icm_addr] = {"type": "FT", "id": ft_id}

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
        _db._fw_ste_db[self.data.get("id")] = {}

    def add_stes_range(self, min_ste_addr, max_ste_addr):
        _db._stes_range_db[self.get_id()] = (min_ste_addr, max_ste_addr)


class dr_parse_fw_ste_stats():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "fw_ste_id", "min_addr", "max_addr"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_min_addr(self):
        return self.data.get("min_addr")

    def get_max_addr(self):
        return self.data.get("max_addr")


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
        if self.get_type() == 'FW_STE_TABLE':
            _id = str(int(self.get_id(), 16))
            if _id not in _db._fw_ste_indexes_arr:
                _db._fw_ste_indexes_arr.append(_id)
        else:
            _db._term_dest_db[self.get_addr()] = {'type': self.get_type(), 'id': self.get_id()}


class dr_parse_stc():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "type", "idx", "ib_port"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_idx(self):
        return self.data.get("idx")

    def load_to_db(self):
        _db._stc_indexes_arr.append(self.get_idx())


#This dictionary holds action objects id location
#according to stc obj param
stc_param_id_loc_dic = {
    STC_ACTION_HEADER_MODIFY_LIST: {'type': 'MODIFY_LIST', 'loc': (8, 16)},
    STC_ACTION_JUMP_TO_STE_TABLE: {'type': 'FW_STE_TABLE', 'loc': (0, 8)},
    STC_ACTION_JUMP_TO_TIR: {'type': 'TIR', 'loc': (2, 8)},
    STC_ACTION_JUMP_TO_FLOW_TABLE: {'type': 'FT', 'loc': (2, 8)},
    STC_ACTION_JUMP_TO_VPORT: {'type': 'VPORT', 'loc': (4, 8)},
    STC_ACTION_JUMP_TO_UPLINK: {'type': 'UPLINK'},
    STC_ACTION_JUMP_TO_DROP: {'type': 'DROP'},
    STC_ACTION_TYPE_ALLOW: {'type': 'ALLOW'},
    STC_ACTION_TYPE_FLOW_COUNTER: {'type': 'FLOW_COUNTER', 'loc': (0,8)},
    STC_ACTION_JUMP_TO_QP: {'type': 'DEST_RDMA_RESP'},
}


def dr_parse_fw_stc_action_get_obj_id(raw):
    stc_param = raw[2:22]
    stc_action_type_shift = _config_args.get("stc_action_type_shift")
    action_type = raw[(40 + stc_action_type_shift):(42 + stc_action_type_shift)]

    obj = stc_param_id_loc_dic.get(action_type)

    if obj != None:
        if (action_type == STC_ACTION_JUMP_TO_UPLINK) or \
           (action_type == STC_ACTION_JUMP_TO_DROP) or \
           (action_type == STC_ACTION_TYPE_ALLOW) or \
           (action_type == STC_ACTION_JUMP_TO_QP):
            return {"type": obj.get("type"), "id": ''}

        id_loc = obj.get("loc")
        return {"type": obj.get("type"), "id": hex(int(stc_param[id_loc[0]:id_loc[1]], 16))}

    return None


def dr_parse_fw_stc_get_addr(raw):
    raw = hex_to_bin_str(raw, STE_SIZE_IN_BITS)
    next_table_base_63_48 = int(raw[96 : 112], 2)
    next_table_base_39_32 = int(raw[120 : 128], 2)
    next_table_base_31_5 = int(raw[128 : 155], 2)

    return hex(hit_location_calc(next_table_base_63_48, next_table_base_39_32, next_table_base_31_5).index)


class dr_parse_pattern():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "index"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.patterns_arr = data[2:] if (len(data) > 2) else []
        self.fix_data()

    def fix_data(self):
        parsed_patterns = []
        for e in self.patterns_arr:
            tmp = e.split("-")
            parsed_patterns.append({"raw": tmp[0], "type": int(tmp[1], 16), "text": tmp[2]})

        self.patterns_arr = parsed_patterns

    def get_index(self):
        return self.data.get("index")

    def load_to_db(self):
        _db._pattern_db[self.get_index()] = self.patterns_arr


class dr_parse_argument():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "arg_index", "index", "data"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_index(self):
        return self.data.get("index")

    def load_to_db(self):
        _db._argument_db[self.get_index()] = self.data.get("data")


class dr_parse_res_counter():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "counter_index", "index", "packets", "octets"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_index(self):
        return self.data.get("index")

    def load_to_db(self):
        _db._counters_db[self.get_index()] = {"packets": self.data.get("packets"), "octets": self.data.get("octets")}


def dr_parse_fw_modify_argument_set(raw):
    raw = raw[8:16]
    text = "data: %s" % hex(int(raw, 16))
    return {"text": text, "raw": raw}


def dr_parse_modify_pattern_set(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_set_action(_raw[0:32], _raw[32:64], False)

    return {"type": 0x1, "text": action_pretiffy(action, False), "raw": raw[0:8]}


def dr_parse_fw_modify_argument_add(raw):
    raw = raw[8:16]
    text = "data: %s" % hex(int(raw, 16))
    return {"text": text, "raw": raw}


def dr_parse_modify_pattern_add(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_add_action(_raw[0:32], _raw[32:64], False)

    return {"type": 0x2, "text": action_pretiffy(action, False), "raw": raw[0:8]}


def dr_parse_modify_pattern_copy(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_copy_action(_raw[0:32], _raw[32:64])

    return {"type": 0x3, "text": action_pretiffy(action, False), "raw": raw}


def dr_parse_fw_modify_argument_insert(raw):
    raw = raw[8:16]
    text = "insert_argument: %s" % hex(int(raw, 16))
    return {"text": text, "raw": raw}


def dr_parse_modify_pattern_insert_inline(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_insert_inline_action(_raw[0:32], _raw[32:64], False)

    return {"type": 0x4, "text": action_pretiffy(action, False), "raw": raw[0:8]}

def dr_parse_modify_pattern_insert_pointer(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_insert_by_pointer_action(_raw[0:32], _raw[32:64])

    return {"type": 0x4, "text": action_pretiffy(action, False), "raw": raw}


def dr_parse_modify_pattern_remove(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_remove_header2header_action(_raw[0:32], _raw[32:64])

    return {"type": 0x5, "text": action_pretiffy(action, False), "raw": raw}


def dr_parse_modify_pattern_nop(raw):
    return {"type":0x6, "text": "", "raw": raw}


def dr_parse_modify_pattern_remove_words(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_remove_by_size_action(_raw[0:32], _raw[32:64])

    return {"type": 0x7, "text": action_pretiffy(action, False), "raw": raw}

def dr_parse_modify_pattern_add_field(raw):
    _raw = hex_to_bin_str(raw, 64)
    action = dr_parse_add_field_action(_raw[0:32], _raw[32:64])

    return {"type": 0x8, "text": action_pretiffy(action, False), "raw": raw}

dr_parse_fw_modify_pattern_dic = {
    0x0: dr_parse_modify_pattern_nop,
    0x5: dr_parse_modify_pattern_copy,
    0x6: dr_parse_modify_pattern_set,
    0x7: dr_parse_modify_pattern_add,
    0x8: dr_parse_modify_pattern_remove_words,
    0x9: dr_parse_modify_pattern_remove,
    0xa: dr_parse_modify_pattern_insert_inline,
    0xb: dr_parse_modify_pattern_insert_pointer,
    0x1b: dr_parse_modify_pattern_add_field,
}

dr_parse_fw_modify_arguments_dic = {
    0x1: dr_parse_fw_modify_argument_set,
    0x2: dr_parse_fw_modify_argument_add,
    0x4: dr_parse_fw_modify_argument_insert,
}

def dr_parse_fw_modify_pattern(raw):
    action_type = int(raw[0:2], 16)
    return dr_parse_fw_modify_pattern_dic.get(action_type)(raw)

def parse_fw_modify_pattern_rd_bin_output(pattern_index, load_to_db, file, num_of_pat):
    arr = []
    read_sz = num_of_pat * MODIFY_PATTERN_BYTES_SZ
    file_str = "%s,%s" % (MLX5DR_DEBUG_RES_TYPE_PATTERN, pattern_index)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")

    #There are 36B of prefix data before first pattern dump
    data = bin_file.read(36)
    #Segment prefix till pattern data
    data = bin_file.read(16)
    data = hex(int.from_bytes(data, byteorder='big'))
    data_type = data[2:8]
    if data_type == RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_PAT_BIN:
        while read_sz:
            data = bin_file.read(MODIFY_PATTERN_BYTES_SZ)
            if data:
                data = hex(int.from_bytes(data, byteorder='big'))[2:]
                len_data = len(data)
                if(len_data < 2 * MODIFY_PATTERN_BYTES_SZ):
                    data = (((2 * MODIFY_PATTERN_BYTES_SZ) - len_data) * '0') + data
                pat_dic = dr_parse_fw_modify_pattern(data)
                arr.append(pat_dic)
                file_str += ",%s-%s-%s" % (pat_dic.get("raw") ,hex(pat_dic.get("type")), pat_dic.get("text").replace(',', ''))
            read_sz -= MODIFY_PATTERN_BYTES_SZ

    file.write("%s\n" % file_str)

    if load_to_db:
        _db._pattern_db[pattern_index] = arr

    return arr

