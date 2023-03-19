#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args


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
        _db._term_dest_db[self.get_addr()] = {'type': self.get_type(), 'id': self.get_id()}

class dr_parse_stc():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "type", "id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def get_id(self):
        return self.data.get("id")

    def load_to_db(self):
        _db._stc_indexes_arr.append(self.get_id())


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
    next_table_base_39_32 = int(raw[120 : 128], 2)
    next_table_base_31_5 = int(raw[128 : 155], 2)

    return hex(hit_addr_calc(next_table_base_39_32, next_table_base_31_5))


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
            parsed_patterns.append({"type": int(tmp[0], 16), "text": tmp[1]})

        self.patterns_arr = parsed_patterns

    def get_index(self):
        return self.data.get("index")

    def load_to_db(self):
        _db._pattern_db[self.get_index()] = self.patterns_arr


class dr_parse_argument():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "index"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.args_arr = data[2:] if (len(data) > 2) else []

    def get_index(self):
        return self.data.get("index")

    def load_to_db(self):
        _db._argument_db[self.get_index()] = self.args_arr


def dr_parse_fw_modify_argument_set(raw):
    return "data: %s" % hex(int(raw[8:16], 16))


def dr_parse_fw_modify_pattern_set(raw):
    field = modify_pattern_field_dic.get(int(raw[1:4], 16))
    offset = hex(int(raw[4:6], 16) & 0x1f)
    length = int(raw[6:8], 16) & 0x1f
    length = "0x20" if length == 0 else hex(length)
    text = "SET: field: %s offset: %s length: %s" %\
            (field, offset, length)

    return {"type": 0x1, "text": text}


def dr_parse_fw_modify_argument_add(raw):
    return "data: %s" % hex(int(raw[8:16], 16))


def dr_parse_fw_modify_pattern_add(raw):
    field = modify_pattern_field_dic.get(int(raw[1:4], 16))
    text =  "ADD: field: %s" % field

    return {"type": 0x2, "text": text}


def dr_parse_fw_modify_pattern_copy(raw):
    src_field = modify_pattern_field_dic.get(int(raw[1:4], 16))
    src_offset = hex(int(raw[4:6], 16) & 0x1f)
    length = int(raw[6:8]) & 0x1f
    length = "0x20" if length == 0 else hex(length)
    dst_field = modify_pattern_field_dic.get(int(raw[9:12], 16))
    dst_offset = hex(int(raw[12:14], 16) & 0x1f)
    text = "COPY: field: %s src_offset: %s src_length: %s dst_field: %s dst_offset: %s" %\
            (src_field, src_offset, length, dst_field, dst_offset)

    return {"type": 0x3, "text": text}


def dr_parse_fw_modify_argument_insert(raw):
    return "insert_argument: %s" % hex(int(raw[8:16], 16))


def dr_parse_fw_modify_pattern_insert(raw):
    encap = hex(int(raw[1:2], 16) & 0x8)
    inline_data = hex(int(raw[1:2], 16) & 0x4)
    insert_anchor = modify_pattern_anchor_dic.get(int(raw[2:4]) & 0x3f)
    insert_offset = hex(int(raw[4:6], 16) & 0x7f)
    insert_size = hex(int(raw[6:8], 16) & 0x7f)
    insert_argument = "0x%s" % raw[8:16]
    text = "INSERT: encap: %s inline_data: %s insert_anchor: %s insert_offset: %s insert_size: %s insert_argument: %s" %\
            (encap, inline_data, insert_anchor, insert_offset, insert_size, insert_argument)

    return {"type": 0x4, "text": text}


def dr_parse_fw_modify_pattern_remove(raw):
    decap = hex(int(raw[1:2], 16) & 0x8)
    start_anchor = modify_pattern_anchor_dic.get(int(raw[2:4], 16) & 0x3f)
    end_anchor = modify_pattern_anchor_dic.get(int(raw[4:6], 16) & 0x3f)
    text = "REMOVE: decap: %s start_anchor: %s end_anchor: %s" %\
            (decap, start_anchor, end_anchor)

    return {"type": 0x5, "text": text}


def dr_parse_fw_modify_pattern_nop(raw):
    return {"type":0x6, "text": ""}


def dr_parse_fw_modify_pattern_remove_words(raw):
    start_anchor = modify_pattern_anchor_dic.get(int(raw[2:4], 16) & 0x3f)
    remove_size = hex(int(raw[6:8], 16) & 0x3f)
    text = "REMOVE WORDS: start_anchor: %s remove_size: %s" %\
            (start_anchor, remove_size)

    return {"type": 0x7, "text": text}


dr_parse_fw_modify_pattern_dic = {
    0x1: dr_parse_fw_modify_pattern_set,
    0x2: dr_parse_fw_modify_pattern_add,
    0x3: dr_parse_fw_modify_pattern_copy,
    0x4: dr_parse_fw_modify_pattern_insert,
    0x5: dr_parse_fw_modify_pattern_remove,
    0x6: dr_parse_fw_modify_pattern_nop,
    0x7: dr_parse_fw_modify_pattern_remove_words,
}

dr_parse_fw_modify_arguments_dic = {
    0x1: dr_parse_fw_modify_argument_set,
    0x2: dr_parse_fw_modify_argument_add,
    0x4: dr_parse_fw_modify_argument_insert,
}

def dr_parse_fw_modify_pattern(raw):
    action_type = int(raw[0:1], 16)
    return dr_parse_fw_modify_pattern_dic.get(action_type)(raw)


def parse_fw_modify_pattern_rd_bin_output(pattern_index, load_to_db, file):
    arr = []
    file_str = "%s,%s" % (MLX5DR_DEBUG_RES_TYPE_PATTERN, pattern_index)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")

    #There are 68B of prefix data before first pattern dump
    data = bin_file.read(68)
    #Segment prefix till pattern data
    data = bin_file.read(48)
    data = hex(int.from_bytes(data, byteorder='big'))
    data_type = data[2:8]
    if data_type == RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_PAT_BIN:
        read_sz = int(data[64:66], 16) * MODIFY_PATTERN_BYTES_SZ
        while read_sz:
            data = bin_file.read(MODIFY_PATTERN_BYTES_SZ)
            if data:
                data = hex(int.from_bytes(data, byteorder='big'))
                pat_dic = dr_parse_fw_modify_pattern(data[2:])
                arr.append(pat_dic)
                file_str += ",%s-%s" % (hex(pat_dic.get("type")), pat_dic.get("text"))
            read_sz -= MODIFY_PATTERN_BYTES_SZ

    file.write("%s\n" % file_str)

    if load_to_db:
        _db._pattern_db[pattern_index] = arr

    return arr


def parse_fw_modify_argument_rd_bin_output(arg_index,  load_to_db, file, len):
    arr = []
    file_str = "%s,%s" % (MLX5DR_DEBUG_RES_TYPE_ARGUMENT, arg_index)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")

    #There are 68B of prefix data before first pattern dump
    data = bin_file.read(68)
    #Segment prefix till pattern data
    data = bin_file.read(16)
    data = hex(int.from_bytes(data, byteorder='big'))
    data_type = data[2:8]
    if data_type == RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_ARG_BIN:
        read_sz = len * MODIFY_ARGUMENT_BYTES_SZ
        while read_sz:
            data = bin_file.read(MODIFY_ARGUMENT_BYTES_SZ)
            if data:
                data = hex(int.from_bytes(data, byteorder='big'))[2:]
                arr.append(data)
                file_str += ",%s" % data
            read_sz -= MODIFY_ARGUMENT_BYTES_SZ

    file.write("%s\n" % file_str)

    if load_to_db:
        _db._argument_db[arg_index] = arr

    return arr
