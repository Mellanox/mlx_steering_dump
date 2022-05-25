#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *
from hw_steering_src.dr_hl import *
from hw_steering_src.dr_db import _definers
from hw_steering_src.dr_ste import fields_handler


class dr_parse_definer():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "mt_id", "definer_obj_id",
                "definer_type", "dw_selectors", "byte_selectors",
                "mask_tag"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.dw_fields = None
        self.byte_fields = None
        self.fix_data()
        self.parse_data()
        self.save_to_db()

    def fix_data(self):
        self.data["definer_obj_id"] = int(self.data["definer_obj_id"])

    def get_definer_obj_id(self):
        return self.data["definer_obj_id"]

    def save_to_db(self):
        _definers[self.get_definer_obj_id()] = self

    def get_definer_matching_fields(self):
        fields_arr = dict(self.dw_fields)
        fields_arr.update(self.byte_fields)
        return fields_arr

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
        for arr in list(self.dw_fields.values()):
            tmp_arr.extend(arr)

        for arr in list(self.byte_fields.values()):
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

            fields_dic[dw_selector] = dr_hl_dw_parser(hl_index, mask)

        return fields_dic

    def definer_bytes_parser(self):
        fields_dic = {}

        for i in range(BYTE_SELECTORS):
            byte_selector = "byte_selector_" + str(i)
            hl_byte_index = int(self.data[byte_selector], 16)
            hl_dw_index = int(hl_byte_index / DW_SZ_IN_BYTES)
            hl_byte_offset = hl_byte_index % DW_SZ_IN_BYTES
            mask = (hl_byte_offset * BYTE_SZ) * "0" #Add prefix zeros for the mask
            mask += hex_to_bin_str(self.data["byte_mask_tag_" + str(i)], BYTE_SZ)
            mask += ((3 - hl_byte_offset) * BYTE_SZ) * "0" #Add suffix zeros for the mask

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
            count += 8 #8 chars represents a 32 bit in hex

        _len = len(byte_selector_arr)
        for i in range(_len):
            self.data["byte_selector_" + str(_len - (i + 1))] = byte_selector_arr[-(i + 1)]
            self.data["byte_mask_tag_" + str(_len - (i + 1))] = "0x" + self.data["mask_tag"][count: count + 2]
            count += 2 #2 chars represents byte in hex

    def parse_data(self):
        self.parse_selectors_and_mask()
        self.dw_fields = self.definer_dws_parser()
        self.byte_fields = self.definer_bytes_parser()
