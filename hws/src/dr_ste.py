#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args
from src.dr_hl import _fields_text_values
from src.dr_action import action_pretiffy,dr_ste_parse_ste_actions_arr


def fields_handler(_fields, verbosity=0, show_field_val=False):
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
        if type(value) == str:
            _str += field + ": " + value
            continue

        if show_field_val:
            tv_field = _fields_text_values.get(field)
            if tv_field != None:
                _str += field + ": " + tv_field.get(value)
                if verbosity > 2:
                    _str += ' (' + hex(value) + ')'
            else:
                _str += field + ": " + hex(value)
        else:
            _str += field + ": " + hex(value)

    return _str

def compare_ste_op_translate(op, inverse):
    _str = ""
    if inverse == 1:
        if op == 2:
            _str = "NE(!=)"
        elif op == 1:
            _str = "GT(>)"
        else:
            _str = "LT(<)"
    else:
        if op == 2:
            _str = "EQ(=)"
        elif op == 1:
            _str = "LE(<=)"
        else:
            _str = "GE(>=)"

    return _str

#This function input is raw STE data in hexa, and
#extracts the matching data.
def raw_ste_parser(raw_ste):
    #Convert STE to binary
    ste = {}
    ste["actions"] = []
    raw_ste = hex_to_bin_str(raw_ste, STE_SIZE_IN_BITS)

    ste["entry_format"] = int(raw_ste[0 : 8], 2)
    ste["counter_id"] = int(raw_ste[8 : 32], 2)
    miss_address_63_48 = int(raw_ste[32 : 48], 2)
    ste["match_definer_context_index"] = int(raw_ste[48 : 56], 2)
    miss_address_39_32 = int(raw_ste[56 : 64], 2)
    miss_address_31_6 = int(raw_ste[64 : 90], 2)
    ste["miss_loc"] = miss_location_calc(miss_address_63_48, miss_address_39_32, miss_address_31_6)
    next_table_base_63_48 = int(raw_ste[96 : 112], 2)
    ste["hash_definer_context_index"] = int(raw_ste[112 : 120], 2)
    next_table_base_39_32 = int(raw_ste[120 : 128], 2)
    next_table_base_31_5 = int(raw_ste[128 : 155], 2)
    ste["hit_loc"] = hit_location_calc(next_table_base_63_48, next_table_base_39_32, next_table_base_31_5)

    dw_selector_8 = raw_ste[160 : 192]
    dw_selector_7 = raw_ste[192 : 224]
    dw_selector_6 = raw_ste[224 : 256]
    dw_selector_5 = raw_ste[256 : 288]
    dw_selector_4 = raw_ste[288 : 320]
    dw_selector_3 = raw_ste[320 : 352]
    dw_selector_2 = raw_ste[352 : 384]
    dw_selector_1 = raw_ste[384 : 416]
    dw_selector_0 = raw_ste[416 : 448]

    if ste["entry_format"] == STE_ENTRY_TYPE_RANGE_MATCH:
        tags = {"dw_selector_0_min": dw_selector_0, "dw_selector_0_max": dw_selector_1}
    elif ste["entry_format"] == STE_ENTRY_TYPE_4DW_RANGE_MATCH:
        tags = {"dw_selector_arg_0": dw_selector_4, "dw_selector_arg_1": dw_selector_5, "dw_selector_base_0": dw_selector_2, "dw_selector_base_1": dw_selector_3}
    else:
        tags = {"dw_selector_0" : dw_selector_0, "dw_selector_1" : dw_selector_1, "dw_selector_2" : dw_selector_2, "dw_selector_3" : dw_selector_3, "dw_selector_4" : dw_selector_4, "dw_selector_5" : dw_selector_5}

    if (ste["entry_format"] != STE_ENTRY_TYPE_JUMBO_MATCH):
        ste["actions"] = dr_ste_parse_ste_actions_arr([dw_selector_8, dw_selector_7, dw_selector_6])
    else:
        tags.update({"dw_selector_6" : dw_selector_6, "dw_selector_7" : dw_selector_7, "dw_selector_8" : dw_selector_8})

    #Get definer
    definer = _db._definers.get(ste["match_definer_context_index"])
    if definer == None:
        ste["parsed_tag"] = {}
        return ste

    definer_fields = definer.get_definer_matching_fields()

    #Build the mask tag according to definer byte_mask_tag_functions lambda functions to get the correct fields
    if ste["entry_format"] == STE_ENTRY_TYPE_RANGE_MATCH:
        tags["dw_selector_1_min"] = raw_ste[480 : 512]
        tags["dw_selector_1_max"] = raw_ste[448 : 480]
        tags["byte_selector_0_min"] = definer.byte_mask_tag_functions.get("byte_selector_0")(dw_selector_4[24 : 32])
        tags["byte_selector_0_max"] = definer.byte_mask_tag_functions.get("byte_selector_0")(dw_selector_5[24 : 32])
        tags["byte_selector_1_min"] = definer.byte_mask_tag_functions.get("byte_selector_1")(dw_selector_4[16 : 24])
        tags["byte_selector_1_max"] = definer.byte_mask_tag_functions.get("byte_selector_1")(dw_selector_5[16 : 24])
        tags["byte_selector_2_min"] = definer.byte_mask_tag_functions.get("byte_selector_2")(dw_selector_4[8 : 16])
        tags["byte_selector_2_max"] = definer.byte_mask_tag_functions.get("byte_selector_2")(dw_selector_5[8 : 16])
        tags["byte_selector_3_min"] = definer.byte_mask_tag_functions.get("byte_selector_3")(dw_selector_4[0 : 8])
        tags["byte_selector_3_max"] = definer.byte_mask_tag_functions.get("byte_selector_3")(dw_selector_5[0 : 8])
        tags["byte_selector_4_min"] = definer.byte_mask_tag_functions.get("byte_selector_4")(dw_selector_2[24 : 32])
        tags["byte_selector_4_max"] = definer.byte_mask_tag_functions.get("byte_selector_4")(dw_selector_3[24 : 32])
        tags["byte_selector_5_min"] = definer.byte_mask_tag_functions.get("byte_selector_5")(dw_selector_2[16 : 24])
        tags["byte_selector_5_max"] = definer.byte_mask_tag_functions.get("byte_selector_5")(dw_selector_3[16 : 24])
        tags["byte_selector_6_min"] = definer.byte_mask_tag_functions.get("byte_selector_6")(dw_selector_2[7 : 16])
        tags["byte_selector_6_max"] = definer.byte_mask_tag_functions.get("byte_selector_6")(dw_selector_3[8 : 16])
        tags["byte_selector_7_min"] = definer.byte_mask_tag_functions.get("byte_selector_7")(dw_selector_2[0 : 8])
        tags["byte_selector_7_max"] = definer.byte_mask_tag_functions.get("byte_selector_7")(dw_selector_3[0 : 8])
    elif ste["entry_format"] != STE_ENTRY_TYPE_4DW_RANGE_MATCH:
        tags["byte_selector_7"] = definer.byte_mask_tag_functions.get("byte_selector_7")(raw_ste[448 : 456])
        tags["byte_selector_6"] = definer.byte_mask_tag_functions.get("byte_selector_6")(raw_ste[456 : 464])
        tags["byte_selector_5"] = definer.byte_mask_tag_functions.get("byte_selector_5")(raw_ste[464 : 472])
        tags["byte_selector_4"] = definer.byte_mask_tag_functions.get("byte_selector_4")(raw_ste[472 : 480])
        tags["byte_selector_3"] = definer.byte_mask_tag_functions.get("byte_selector_3")(raw_ste[480 : 488])
        tags["byte_selector_2"] = definer.byte_mask_tag_functions.get("byte_selector_2")(raw_ste[488 : 496])
        tags["byte_selector_1"] = definer.byte_mask_tag_functions.get("byte_selector_1")(raw_ste[496 : 504])
        tags["byte_selector_0"] = definer.byte_mask_tag_functions.get("byte_selector_0")(raw_ste[504 : 512])

    parsed_tag = {}

    if ste["entry_format"] == STE_ENTRY_TYPE_4DW_RANGE_MATCH:
        arg_1 = tags.get("dw_selector_arg_1")
        match = int(arg_1[0 : 1], 2)
        base_1_src = int(arg_1[3 : 4], 2)
        inverse_1 = int(arg_1[4 : 5], 2)
        operator_1 = int(arg_1[6 : 8], 2)
        base_0_src = int(arg_1[11 : 12], 2)
        inverse_0 = int(arg_1[12 : 13], 2)
        operator_0 = int(arg_1[14 : 16], 2)
        parsed_tag["operator_0"] = compare_ste_op_translate(operator_0, inverse_0)
        if base_0_src == 0x1:
            parsed_tag["base_0_src"] = "inline base"
            parsed_tag["base_0"] = int(tags.get("dw_selector_base_0"), 2)

        ste["parsed_tag"] = parsed_tag
        return ste

    for selector in definer_fields:
        selector_arr = definer_fields[selector]
        count = 0
        tag = tags.get(selector)
        for field in selector_arr:
            if (field != None):
                tag_value = int(field[1], 2) & int(tag[count : count + len(field[1])], 2)
                if tag_value != 0:
                    pre_tag = parsed_tag.get(field[0])
                    if pre_tag != None:
                        parsed_tag[field[0]] = pre_tag | tag_value
                    else:
                        parsed_tag[field[0]] = tag_value
                count += len(field[1])

    ste["parsed_tag"] = parsed_tag

    return ste


class dr_parse_ste():
    def __init__(self, data, parse=False):
        keys = ["mlx5dr_debug_res_type", "id", "fw_ste_id", "raw_ste"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.hit_loc = None
        self.miss_loc = None
        self.fields_dic = None
        self.action_arr = None
        self.parsed = False
        self.counter_id = 0;
        if parse:
            self.parse()

    def parse(self):
        parsed_ste = raw_ste_parser(self.data.get("raw_ste"))
        self.hit_loc = parsed_ste["hit_loc"]
        self.miss_loc = parsed_ste["miss_loc"]
        self.fields_dic = parsed_ste.get("parsed_tag")
        self.action_arr = parsed_ste.get("actions")
        self.counter_id = parsed_ste.get("counter_id")
        self.parsed = True

    def dump_str(self, verbosity, prefix='STE '):
        _str = prefix + self.data.get("id") + ':\n'
        return _str

    def dump_actions(self, verbosity, tabs, is_last):
        if not(self.parsed):
            self.parse()

        _str = tabs + 'Actions:\n'
        _tabs = tabs + TAB
        flag = False

        if self.counter_id != 0:
            _str += _tabs + 'Counter: ' + hex(self.counter_id) + '\n'
            flag = True

        for action in self.action_arr:
            if action != '':
                _str += _tabs + action
                flag = True

        if is_last or verbosity > 3:
            _str += _tabs + 'Go To:'
            if self.hit_loc.gvmi_str == _config_args.get("vhca_id"):
                obj = _db._term_dest_db.get(hex(self.hit_loc.index))
            else:
                obj = None
            if obj != None:
                _str += ' ' + obj.get("type") + ' ' + obj.get("id")
                if verbosity > 2:
                    _str += ' (' + str(self.hit_loc) + ')'
            else:
                _str += ' ' + str(self.hit_loc)
            _str += '\n'
            flag = True

        if flag:
            return _str
        else:
            return ''

    def dump_fields(self, verbosity, tabs):
        if not(self.parsed):
            self.parse()

        _str = tabs + 'Tag:\n'
        tabs = tabs + TAB
        fields_handler_str = fields_handler(self.fields_dic, verbosity, True)
        if fields_handler_str == '':
            _str += tabs + 'Empty Tag\n'
        else:
            _str += tabs + fields_handler_str + '\n'

        return _str

    def dump_miss(self, verbosity, tabs):
        if not len(self.fields_dic):
            return ''

        return tabs + 'Miss address: ' + str(self.miss_loc) + '\n'

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

    def tree_print(self, verbosity, tabs, prefix, is_last):
        _str = tabs + self.dump_str(verbosity, prefix)
        tabs = tabs + TAB

        _str += self.dump_fields(verbosity, tabs)

        if verbosity > 3:
            _str += self.dump_miss(verbosity, tabs)

        _str += self.dump_actions(verbosity, tabs, is_last)

        if verbosity > 2:
            _str += self.dump_raw_ste(verbosity, tabs)

        return _str

    def get_addr(self):
        return self.data.get("id")

    def get_hit_location(self):
        if not(self.parsed):
            self.parse()

        return self.hit_loc

    def get_miss_location(self):
        if not(self.parsed):
            self.parse()

        return self.miss_loc

    def load_to_db(self):
        _db._fw_ste_db[self.data.get("fw_ste_id")][self.data.get("id")] = self
