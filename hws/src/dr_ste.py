#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _definers,_fw_ste_db
from src.dr_hl import _fields_text_values
from src.dr_action import action_pretiffy

def dr_ste_parse_ste_actions_arr(action_arr):
    index = 0
    result = []
    while index < 3:
        action_dw_0 = action_arr[index]
        action_type = int(action_dw_0[0 : 8], 2)
        if action_type == 0x0:
            action = {"type" : "NOPE"}
            result.append(action)
        elif action_type == 0x5:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "Copy"}
            action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
            action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
            action["destination_length"] = int(action_dw_0[24 : 32], 2)
            action["source_dw_offset"] = int(action_dw_1[8 : 16], 2)
            action["source_right_shifter"] = int(action_dw_1[18 : 24], 2)
            result.append(action)
        elif action_type == 0x6:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "Set"}
            action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
            action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
            action["destination_length"] = int(action_dw_0[24 : 32], 2)
            action["inline_data"] = int(action_dw_1, 2)
            result.append(action)
        elif action_type == 0x7:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "Add"}
            action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
            action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
            action["destination_length"] = int(action_dw_0[24 : 32], 2)
            action["add_value"] = int(action_dw_1, 2)
            result.append(action)
        elif action_type == 0x8:
            action = {"type" : "Remove by size"}
            action["start_anchor"] = int(action_dw_0[10 : 16], 2)
            action["outer_l4_removed"] = int(action_dw_0[16 : 17], 2)
            action["start_offset"] = int(action_dw_0[18 : 25], 2)
            action["size"] = int(action_dw_0[26 : 32], 2)
            result.append(action)
        elif action_type == 0x9:
            action = {"type" : "remove header2header"}
            action["start_anchor"] = int(action_dw_0[10 : 16], 2)
            action["end_anchor"] = int(action_dw_0[18 : 24], 2)
            action["decap"] = int(action_dw_0[28 : 29], 2)
            action["vni_to_cqe"] = int(action_dw_0[29 : 30], 2)
            action["qos_profile "] = int(action_dw_0[30 : 32], 2)
            result.append(action)
        elif action_type == 0xa:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "insert with inline"}
            action["start_anchor"] = int(action_dw_0[10 : 16], 2)
            action["end_anchor"] = int(action_dw_0[18 : 24], 2)
            action["insert_data_inline"] = int(action_dw_1[0 : 32], 2)
            result.append(action)
        elif action_type == 0xb:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "insert with pointer"}
            action["start_anchor"] = int(action_dw_0[10 : 16], 2)
            action["end_anchor"] = int(action_dw_0[18 : 24], 2)
            action["size"] = int(action_dw_0[24 : 29], 2)
            action["attributes"] = int(action_dw_0[29 : 32], 2)
            action["pointer"] = int(action_dw_1[0 : 32], 2)
            result.append(action)
        elif action_type == 0xc:
            action = {"type" : "flow tag"}
            action["flow_tag"] = int(action_dw_0[8 : 32], 2)
            result.append(action)
        elif action_type == 0xe:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "accelerated modify action list"}
            action["modify_actions_pattern_pointer"] = int(action_dw_0[8 : 32], 2)
            action["number_of_modify_actions"] =  int(action_dw_1[0 : 8], 2)
            action["modify_actions_argument_pointer"] = int(action_dw_1[8 : 32], 2)
            result.append(action)
        elif action_type == 0x12:
            index += 1
            action_dw_1 = action_arr[index]
            action = {"type" : "ASO"}
            action["aso_context_number"] = int(action_dw_0[8 : 32], 2)
            action["dest_reg_id"] = int(action_dw_1[0 : 2], 2)
            action["aso_context_type"] = int(action_dw_1[4 : 8], 2)
            action["aso_fields"] = int(action_dw_1[16 : 32], 2)
            result.append(action)

        index += 1

    return result

def fields_handler(_fields, show_field_val=False):
    _str = ""
    fields = {}
    union_fields = {"smac_47_16_o": 0, "smac_15_0_o": 0, "dmac_47_16_o": 0,
                    "dmac_15_0_o": 0, "ipv6_address_127_96_o": 0,
                    "ipv6_address_95_64_o": 0, "ipv6_address_63_32_o": 0,
                    "ipv6_address_31_0_o": 0, "smac_47_16_i": 0,
                    "smac_15_0_i": 0, "dmac_47_16_i": 0, "dmac_15_0_i": 0,
                    "ipv6_address_127_96_i": 0, "ipv6_address_95_64_i": 0,
                    "ipv6_address_63_32_i": 0, "ipv6_address_31_0_i": 0}

    for field in _fields:
        _data = _fields.get(field)
        if _data == 0:
            continue

        if field in union_fields:
            union_fields[field] |= _data
        elif field in fields:
            fields[field] |= _data
        else:
            fields[field] = _data

    if union_fields["smac_47_16_o"] != 0 or union_fields["smac_15_0_o"] != 0:
        fields["smac_o"] = (union_fields["smac_47_16_o"] << 16) | union_fields["smac_15_0_o"]

    if union_fields["smac_47_16_i"] != 0 or union_fields["smac_15_0_i"] != 0:
        fields["smac_i"] = (union_fields["smac_47_16_i"] << 16) | union_fields["smac_15_0_i"]

    if union_fields["dmac_47_16_o"] != 0 or union_fields["dmac_15_0_o"] != 0:
        fields["dmac_o"] = (union_fields["dmac_47_16_o"] << 16) | union_fields["dmac_15_0_o"]

    if union_fields["dmac_47_16_i"] != 0 or union_fields["dmac_15_0_i"] != 0:
        fields["dmac_i"] = (union_fields["dmac_47_16_i"] << 16) | union_fields["dmac_15_0_i"]

    if (union_fields["ipv6_address_127_96_o"] != 0 or
        union_fields["ipv6_address_95_64_o"] != 0 or
        union_fields["ipv6_address_63_32_o"] != 0 or
        union_fields["ipv6_address_31_0_o"] != 0):
        fields["ipv6_addr_o"] = union_fields["ipv6_address_127_96_o"] << 96
        fields["ipv6_addr_o"] |= union_fields["ipv6_address_95_64_o"] << 64
        fields["ipv6_addr_o"] |= union_fields["ipv6_address_63_32_o"] << 32
        fields["ipv6_addr_o"] |= union_fields["ipv6_address_31_0_o"]

    if (union_fields["ipv6_address_127_96_i"] != 0 or
        union_fields["ipv6_address_95_64_i"] != 0 or
        union_fields["ipv6_address_63_32_i"] != 0 or
        union_fields["ipv6_address_31_0_i"] != 0):
        fields["ipv6_addr_i"] = union_fields["ipv6_address_127_96_i"] << 96
        fields["ipv6_addr_i"] |= union_fields["ipv6_address_95_64_i"] << 64
        fields["ipv6_addr_i"] |= union_fields["ipv6_address_63_32_i"] << 32
        fields["ipv6_addr_i"] |= union_fields["ipv6_address_31_0_i"]

    for field in fields:
        if _str != "":
            _str += ", "

        value = fields.get(field)

        if show_field_val:
            tv_field = _fields_text_values.get(field)
            if tv_field != None:
                _str += field + ": " + hex(value) + ' (' + tv_field.get(value) + ')'
            else:
                _str += field + ": " + hex(value)
        else:
            _str += field + ": " + hex(value)

    return _str

def ste_hit_addr_calc(next_table_base_63_48, next_table_base_39_32, next_table_base_31_5):
    hit_addr = next_table_base_39_32 << 32
    hit_addr |= next_table_base_31_5
    hit_addr = (hit_addr >> 6) & 0xffffffff

    return hit_addr

#This function input is raw STE data in hexa, and
#extracts the matching data.
def raw_ste_parser(raw_ste):
    #Convert STE to binary
    ste = {}
    raw_ste = hex_to_bin_str(raw_ste, STE_SIZE_IN_BITS)
    
    ste["entry_format"] = int(raw_ste[0 : 8], 2)
    ste["counter_id"] = int(raw_ste[8 : 32], 2)
    miss_address_63_48 = int(raw_ste[32 : 48], 2)
    ste["match_definer_context_index"] = int(raw_ste[48 : 56], 2)
    miss_address_39_32 = int(raw_ste[56 : 64], 2)
    miss_address_31_6 = int(raw_ste[64 : 90], 2)
    ste["miss_addr"] = (miss_address_63_48 << 64) | (miss_address_39_32 << 32) | (miss_address_31_6 << 6)
    next_table_base_63_48 = int(raw_ste[96 : 112], 2)
    ste["hash_definer_context_index"] = int(raw_ste[112 : 120], 2)
    next_table_base_39_32 = int(raw_ste[120 : 128], 2)
    next_table_base_31_5 = int(raw_ste[128 : 155], 2)
    ste["hit_addr"] = hex(ste_hit_addr_calc(next_table_base_63_48, next_table_base_39_32, next_table_base_31_5))

    dw_selector_8 = raw_ste[160 : 192]
    dw_selector_7 = raw_ste[192 : 224]
    dw_selector_6 = raw_ste[224 : 256]
    dw_selector_5 = raw_ste[256 : 288]
    dw_selector_4 = raw_ste[288 : 320]
    dw_selector_3 = raw_ste[320 : 352]
    dw_selector_2 = raw_ste[352 : 384]
    dw_selector_1 = raw_ste[384 : 416]
    dw_selector_0 = raw_ste[416 : 448]

    tags = {"dw_selector_0" : dw_selector_0, "dw_selector_1" : dw_selector_1, "dw_selector_2" : dw_selector_2, "dw_selector_3" : dw_selector_3, "dw_selector_4" : dw_selector_4, "dw_selector_5" : dw_selector_5}

    if (ste["entry_format"] == STE_ENTRY_TYPE_MATCH):
        ste["actions"] = dr_ste_parse_ste_actions_arr([dw_selector_8, dw_selector_7, dw_selector_6])
    else:
        extra_tags = {"dw_selector_6" : dw_selector_6, "dw_selector_7" : dw_selector_7, "dw_selector_8" : dw_selector_8}

    if (ste["entry_format"] == STE_ENTRY_TYPE_JUMBO_MATCH):
        tags.update(extra_tags)

    #Get definer
    definer = _definers.get(ste["match_definer_context_index"])
    if definer == None:
        ste["parsed_tag"] = {}
        return ste

    definer_fields = definer.get_definer_matching_fields()

    #Add prefix and suffix zeros for the mask of bytes to complete to DW
    tags["byte_selector_7"] = raw_ste[448 : 456] + (24 * '0')
    tags["byte_selector_6"] = (8 * '0') + raw_ste[456 : 464] + (16 * '0')
    tags["byte_selector_5"] = (16 * '0') + raw_ste[464 : 472] + (8 * '0')
    tags["byte_selector_4"] = (24 * '0') + raw_ste[472 : 480]
    tags["byte_selector_3"] = raw_ste[480 : 488] + (24 * '0')
    tags["byte_selector_2"] = (8 * '0') + raw_ste[488 : 496] + (16 * '0')
    tags["byte_selector_1"] = (16 * '0') + raw_ste[496 : 504] + (8 * '0')
    tags["byte_selector_0"] = (24 * '0') + raw_ste[504 : 512]

    parsed_tag = {}

    for selector in definer_fields:
        selector_arr = definer_fields[selector]
        count = 0
        tag = tags.get(selector)
        for field in selector_arr:
            if (field != None):
                tag_value = int(field[1], 2) & int(tag[count : count + len(field[1])], 2)
                if tag_value != 0:
                    parsed_tag[field[0]] = tag_value
                count += len(field[1])

    ste["parsed_tag"] = parsed_tag

    return ste


class dr_parse_ste():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "fw_ste_id", "raw_ste"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        parsed_ste = raw_ste_parser(self.data.get("raw_ste"))
        self.hit_addr = parsed_ste["hit_addr"]
        self.miss_addr = parsed_ste["miss_addr"]
        self.fields_dic = parsed_ste.get("parsed_tag")
        self.action_arr = parsed_ste.get("actions")

    def dump_str(self, verbosity, prefix='STE '):
        _str = prefix + self.data.get("id") + ':\n'
        return _str

    def dump_actions(self, verbosity, tabs):
        _str = tabs + 'Actions:\n'
        _tabs = tabs + TAB
        flag = False

        for action in self.action_arr:
            action_str = action_pretiffy(action)
            if action_str != '':
                _str += _tabs + action_pretiffy(action)
                flag = True

        if flag:
            return _str
        else:
            return ''

    def dump_fields(self, verbosity, tabs):
        _str = tabs + 'Tag:\n'
        tabs = tabs + TAB
        fields_handler_str = fields_handler(self.fields_dic, True)
        if fields_handler_str == '':
            _str += tabs + 'Empty Tag\n'
        else:
            _str += tabs + fields_handler_str + '\n'

        return _str

    def dump_raw_ste(self, verbosity, tabs):
        _str = tabs + 'Raw STE:\n'
        tabs = tabs + TAB
        raw_ste = self.data.get("raw_ste")[2:]
        _str += tabs + raw_ste[0:8] + ' ' + raw_ste[8:16] + ' '
        _str += raw_ste[16:24] + ' ' + raw_ste[24:32] + '\n'
        _str += tabs + raw_ste[32:40] + ' ' + raw_ste[40:48] + ' '
        _str += raw_ste[48:56] + ' ' + raw_ste[56:64] + '\n'
        _str += tabs + raw_ste[64:72] + ' ' + raw_ste[72:80] + ' '
        _str += raw_ste[80:88] + ' ' + raw_ste[88:96] + '\n'
        _str += tabs + raw_ste[96:104] + ' ' + raw_ste[104:112] + ' '
        _str += raw_ste[112:120] + ' ' + raw_ste[120:128] + '\n'

        return _str

    def tree_print(self, verbosity, tabs, prefix=None):
        _str = tabs + self.dump_str(verbosity, prefix)
        tabs = tabs + TAB

        _str += self.dump_fields(verbosity, tabs)
        _str += self.dump_actions(verbosity, tabs)

        if verbosity > 2:
            _str += self.dump_raw_ste(verbosity, tabs)

        return _str

    def get_addr(self):
        return self.data.get("id")

    def get_hit_addr(self):
        return self.hit_addr

    def get_miss_addr(self):
        return self.miss_addr

    def load_to_db(self):
        _fw_ste_db[self.data.get("fw_ste_id")][self.data.get("id")] = self