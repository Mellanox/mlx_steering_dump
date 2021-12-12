#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *
from hw_steering_src.dr_hl import *


DEFINERS = {}


class dr_parse_definer():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "mt_id", "definer_obj_id",
                "dw_selector_0", "dw_selector_1", "dw_selector_2",
                "dw_selector_3", "dw_selector_4", "dw_selector_5",
                "byte_selector_0", "byte_selector_1", "byte_selector_2",
                "byte_selector_3", "byte_selector_4", "byte_selector_5",
                "byte_selector_6", "byte_selector_7", "mask_tag_0", "mask_tag_1",
                "mask_tag_2", "mask_tag_3", "mask_tag_4", "mask_tag_5",
                "mask_tag_6", "mask_tag_7", "mask_tag_8", "mask_tag_9",
                "mask_tag_10", "mask_tag_11", "mask_tag_12", "mask_tag_13",
                "mask_tag_14", "mask_tag_15", "mask_tag_16", "mask_tag_17",
                "mask_tag_18", "mask_tag_19", "mask_tag_20", "mask_tag_21",
                "mask_tag_22", "mask_tag_23", "mask_tag_24", "mask_tag_25",
                "mask_tag_26", "mask_tag_27", "mask_tag_28", "mask_tag_29",
                "mask_tag_30", "mask_tag_31"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.dw_fields = None
        self.byte_fields = None
        self.parse_data()

    def get_definer_obj_id(self):
        return self.data["definer_obj_id"]

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
        union_fields = {"smac_47_16": 0, "smac_15_0": 0, "dmac_47_16": 0,
                        "dmac_15_0": 0, "ipv6_address_127_96": 0,
                        "ipv6_address_95_64": 0, "ipv6_address_63_32": 0,
                        "ipv6_address_31_0": 0}
        tmp_arr = []
        fields = {}
        for arr in list(self.dw_fields.values()):
            tmp_arr.extend(arr)

        for arr in list(self.byte_fields.values()):
            tmp_arr.extend(arr)

        for e in tmp_arr:
            _key = e[0]
            _data = e[1]
            if int(_data, 2) == 0:
                continue

            if _key in union_fields:
                union_fields[_key] = union_fields[_key] | int(_data, 2)
            else:
                fields[_key] = int(_data, 2)

        if union_fields["smac_47_16"] != 0 or union_fields["smac_15_0"] != 0:
            fields["smac"] = (union_fields["smac_47_16"] << 16) | union_fields["smac_15_0"]

        if union_fields["dmac_47_16"] != 0 or union_fields["dmac_15_0"] != 0:
            fields["dmac"] = (union_fields["dmac_47_16"] << 16) | union_fields["dmac_15_0"]

        if (union_fields["ipv6_address_127_96"] != 0 or
            union_fields["ipv6_address_95_64"] != 0 or
            union_fields["ipv6_address_63_32"] != 0 or
            union_fields["ipv6_address_31_0"] != 0):
            fields["ipv6_address"] = union_fields["ipv6_address_127_96"] << 96
            fields["ipv6_address"] |= union_fields["ipv6_address_95_64"] << 64
            fields["ipv6_address"] |= union_fields["ipv6_address_63_32"] << 32
            fields["ipv6_address"] |= union_fields["ipv6_address_31_0"]

        for _key in fields:
            if _str != "":
                _str += ", "
            _str += _key + ": " + str(hex(fields[_key]))

        return _str

    def definer_dws_parser(self):
        fields_dic = {}

        for i in range(6):
            dw_selector = "dw_selector_" + str(i)
            hl_index = int(self.data[dw_selector], 16)
            tag_index = 8 + (4 * i)
            mask = hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 3)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 2)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index + 1)])
            mask += hex_to_bin_str(self.data["mask_tag_" + str(tag_index)])

            fields_dic[dw_selector] = dr_hl_dw_parser(hl_index, mask)

        return fields_dic

    def definer_bytes_parser(self):
        fields_dic = {}

        for i in range(8):
            byte_selector = "byte_selector_" + str(i)
            hl_byte_index = int(self.data[byte_selector], 16)
            hl_dw_index = hl_byte_index / 4
            hl_byte_offset = hl_byte_index % 4
            mask = ((3 - hl_byte_offset) * 8) * "0"
            mask += hex_to_bin_str(self.data["mask_tag_" + str(i)])
            mask += (hl_byte_offset * 8) * "0"

            fields_dic[byte_selector] = dr_hl_dw_parser(hl_dw_index, mask)

        return fields_dic


    def parse_data(self):
        self.dw_fields = self.definer_dws_parser()
        self.byte_fields = self.definer_bytes_parser()
