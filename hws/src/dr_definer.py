#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_hl import *
from src.dr_db import _db
from src.dr_ste import fields_handler

def byte_mask_builder(hl_byte_offset):
    return lambda byte_tag : ((hl_byte_offset * BYTE_SZ) * "0") + byte_tag + (((3 - hl_byte_offset) * BYTE_SZ) * "0")

class dr_parse_definer():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "mt_id", "definer_obj_id",
                "definer_type", "dw_selectors", "byte_selectors",
                "mask_tag"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.dw_fields = None
        self.byte_fields = None
        self.range_dw_fields = None
        self.range_byte_fields = None
        self.fields_arr = None
        self.byte_mask_tag_functions = {}
        self.fix_data()
        self.parse_data()
        self.save_to_db()

    def fix_data(self):
        self.data["definer_obj_id"] = int(self.data["definer_obj_id"])

    def get_definer_obj_id(self):
        return self.data["definer_obj_id"]

    def save_to_db(self):
        _db._definers[self.get_definer_obj_id()] = self

    def get_definer_matching_fields(self):
        return self.fields_arr

    def dump_str(self, verbosity):
            return dump_obj_str(["mlx5dr_debug_res_type", "id", "mt_id",
                                 "definer_obj_id", "dw_selector_0", "dw_selector_1",
                                 "dw_selector_2", "dw_selector_3", "dw_selector_4",
                                 "dw_selector_5", "byte_selector_0", "byte_selector_1",
                                 "byte_selector_2", "byte_selector_3", "byte_selector_4",
                                 "byte_selector_5", "byte_selector_6", "byte_selector_7"],
                                 self.data)

    def dump_fields(self):
        _str = ""
        tmp_arr = []
        fields = {}
        if self.data.get("mlx5dr_debug_res_type") == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_RANGE_DEFINER:
            _dw_fields = self.range_dw_fields
            _byte_fields = self.range_byte_fields
        else:
            _dw_fields = self.dw_fields
            _byte_fields = self.byte_fields

        for arr in list(_dw_fields.values()):
            tmp_arr.extend(arr)

        for arr in list(_byte_fields.values()):
            tmp_arr.extend(arr)

        for e in tmp_arr:
            _key = e[0]
            _data = int(e[1], 2)
            if _data == 0:
                continue

            if _key in fields:
                fields[_key] |= _data
            else:
                fields[_key] = _data

        return fields_handler(fields)

    def definer_dws_parser(self):
        fields_dic = {}

        for i in range(DW_SELECTORS):
            dw_selector = "dw_selector_" + str(i)
            hl_index = int(self.data[dw_selector], 16)
            mask = hex_to_bin_str(self.data["dw_mask_tag_" + str(i)], DW_SZ)

            if int(mask, 2) == 0:
                fields_dic[dw_selector] = []
            else:
                fields_dic[dw_selector] = dr_hl_dw_parser(hl_index, mask)

        return fields_dic

    def definer_bytes_parser(self):
        fields_dic = {}

        for i in range(BYTE_SELECTORS):
            byte_selector = "byte_selector_" + str(i)
            #Check byte mask tag if zero then continue assigning empty array
            byte_mask_tag = hex_to_bin_str(self.data["byte_mask_tag_" + str(i)], BYTE_SZ)
            if int(byte_mask_tag, 2) == 0:
                self.byte_mask_tag_functions[byte_selector] = lambda byte_tag : 32 * "0"
                fields_dic[byte_selector] = []
                continue
            hl_byte_index = int(self.data[byte_selector], 16)
            hl_dw_index = int(hl_byte_index / DW_SZ_IN_BYTES)
            hl_byte_offset = hl_byte_index % DW_SZ_IN_BYTES
            #Define Lambda function which creates the mask tag
            mask_func = byte_mask_builder(hl_byte_offset)
            self.byte_mask_tag_functions[byte_selector] = mask_func
            #create mask tag
            mask = mask_func(byte_mask_tag)
            fields_dic[byte_selector] = dr_hl_dw_parser(hl_dw_index, mask)

        return fields_dic

    def parse_selectors_and_mask(self):
        dw_selector_arr = self.data["dw_selectors"].split("-")
        byte_selector_arr = self.data["byte_selectors"].split("-")
        count = 0
        _len = len(dw_selector_arr)
        for i in range(_len):
            self.data["dw_selector_" + str(_len - (i + 1))] = dw_selector_arr[-(i + 1)]
            self.data["dw_mask_tag_" + str(_len - (i + 1))] = "0x" + self.data["mask_tag"][count: count + 8]
            #8 chars represents a 32 bit in hex
            count += 8

        _len = len(byte_selector_arr)
        for i in range(_len):
            self.data["byte_selector_" + str(_len - (i + 1))] = byte_selector_arr[-(i + 1)]
            self.data["byte_mask_tag_" + str(_len - (i + 1))] = "0x" + self.data["mask_tag"][count: count + 2]
            #2 chars represents byte in hex
            count += 2

    def parse_data(self):
        self.parse_selectors_and_mask()
        self.dw_fields = self.definer_dws_parser()
        self.byte_fields = self.definer_bytes_parser()
        if self.data.get("mlx5dr_debug_res_type") == MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_RANGE_DEFINER:
            _dw_fields = {}
            _byte_fields = {}
            _dw_fields["dw_selector_0_min"] = dr_hl_fields_arr_add_prefix("min_", self.dw_fields["dw_selector_0"])
            _dw_fields["dw_selector_0_max"] = dr_hl_fields_arr_add_prefix("max_", self.dw_fields["dw_selector_0"])
            _dw_fields["dw_selector_1_min"] = dr_hl_fields_arr_add_prefix("min_", self.dw_fields["dw_selector_1"])
            _dw_fields["dw_selector_1_max"] = dr_hl_fields_arr_add_prefix("max_", self.dw_fields["dw_selector_1"])
            self.range_dw_fields = self.dw_fields
            self.dw_fields = _dw_fields
            _byte_fields["byte_selector_0_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_0"])
            _byte_fields["byte_selector_0_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_0"])
            _byte_fields["byte_selector_1_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_1"])
            _byte_fields["byte_selector_1_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_1"])
            _byte_fields["byte_selector_2_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_2"])
            _byte_fields["byte_selector_2_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_2"])
            _byte_fields["byte_selector_3_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_3"])
            _byte_fields["byte_selector_3_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_3"])
            _byte_fields["byte_selector_4_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_4"])
            _byte_fields["byte_selector_4_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_4"])
            _byte_fields["byte_selector_5_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_5"])
            _byte_fields["byte_selector_5_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_5"])
            _byte_fields["byte_selector_6_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_6"])
            _byte_fields["byte_selector_6_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_6"])
            _byte_fields["byte_selector_7_min"] = dr_hl_fields_arr_add_prefix("min_", self.byte_fields["byte_selector_7"])
            _byte_fields["byte_selector_7_max"] = dr_hl_fields_arr_add_prefix("max_", self.byte_fields["byte_selector_7"])
            self.range_byte_fields = self.byte_fields
            self.byte_fields = _byte_fields

        self.fields_arr = dict(self.dw_fields)
        self.fields_arr.update(self.byte_fields)
