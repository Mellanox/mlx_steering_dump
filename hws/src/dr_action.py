#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _pattern_db, _argument_db
from src.dr_hw_resources import parse_fw_modify_pattern_rd_bin_output, parse_fw_modify_argument_rd_bin_output, dr_parse_fw_modify_arguments_dic

def dr_action_nope_parser(action_arr, index):
    return (1, [''])

def dr_action_copy_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "Copy"}
    action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
    action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
    action["destination_length"] = int(action_dw_0[24 : 32], 2)
    action["source_dw_offset"] = int(action_dw_1[8 : 16], 2)
    action["source_right_shifter"] = int(action_dw_1[18 : 24], 2)

    return (2, [action_pretiffy(action)])

def dr_action_set_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "Set"}
    action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
    action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
    action["destination_length"] = int(action_dw_0[24 : 32], 2)
    action["inline_data"] = int(action_dw_1, 2)

    return (2, [action_pretiffy(action)])

def dr_action_add_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "Add"}
    action["destination_dw_offset"] = int(action_dw_0[8 : 16], 2)
    action["destination_left_shifter"] = int(action_dw_0[18 : 24], 2)
    action["destination_length"] = int(action_dw_0[24 : 32], 2)
    action["add_value"] = int(action_dw_1, 2)

    return (2, [action_pretiffy(action)])

def dr_action_remove_by_size_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "Remove by size"}
    action["start_anchor"] = int(action_dw_0[10 : 16], 2)
    action["outer_l4_removed"] = int(action_dw_0[16 : 17], 2)
    action["start_offset"] = int(action_dw_0[18 : 25], 2)
    action["size"] = int(action_dw_0[26 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_remove_header2header_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "remove header2header"}
    action["start_anchor"] = int(action_dw_0[10 : 16], 2)
    action["end_anchor"] = int(action_dw_0[18 : 24], 2)
    action["decap"] = int(action_dw_0[28 : 29], 2)
    action["vni_to_cqe"] = int(action_dw_0[29 : 30], 2)
    action["qos_profile "] = int(action_dw_0[30 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_insert_inline_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "insert with inline"}
    action["start_anchor"] = int(action_dw_0[10 : 16], 2)
    action["end_anchor"] = int(action_dw_0[18 : 24], 2)
    action["insert_data_inline"] = int(action_dw_1[0 : 32], 2)

    return (2, [action_pretiffy(action)])

def dr_action_insert_pointer_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "insert with pointer"}
    action["start_anchor"] = int(action_dw_0[10 : 16], 2)
    action["end_anchor"] = int(action_dw_0[18 : 24], 2)
    action["size"] = int(action_dw_0[24 : 29], 2)
    action["attributes"] = int(action_dw_0[29 : 32], 2)
    action["pointer"] = int(action_dw_1[0 : 32], 2)

    return (2, [action_pretiffy(action)])

def dr_action_accelerated_modify_list_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "accelerated modify action list"}
    modify_actions_pattern_pointer = int(action_dw_0[8 : 32], 2)
    number_of_modify_actions =  int(action_dw_1[0 : 8], 2)
    modify_actions_argument_pointer = int(action_dw_1[8 : 32], 2)
    action["modify_actions_pattern_pointer"] = modify_actions_pattern_pointer
    action["number_of_modify_actions"] = number_of_modify_actions
    action["modify_actions_argument_pointer"] = modify_actions_argument_pointer
    arr = [action_pretiffy(action)]
    dump_arg = _config_args.get("extra_hw_res_arg")
    dump_pat = _config_args.get("extra_hw_res_pat")

    _arr = []
    load_to_db = _config_args.get("load_hw_resources")
    dev = _config_args.get("_dev")
    dev_name = _config_args.get("_dev_name")
    file = _config_args.get("csv_file")
    num_of_pat = int((number_of_modify_actions + PAT_ARG_BULK_SIZE - 1) // PAT_ARG_BULK_SIZE)#Addition to ceiling division
    for i in range (0, num_of_pat):
        pat_index = hex(modify_actions_pattern_pointer + i)
        pat_arr = _pattern_db.get(pat_index)
        if pat_arr == None:
            if dump_pat == True:
                output = call_resource_dump(dev, dev_name, "MODIFY_PATTERN", pat_index, None, None, None)
                pat_arr = parse_fw_modify_pattern_rd_bin_output(pat_index,  load_to_db, file)

        arg_index = hex(modify_actions_argument_pointer + i)
        arg_arr = _argument_db.get(arg_index)
        if arg_arr == None:
            if dump_arg == True:
                output = call_resource_dump(dev, dev_name, "MODIFY_ARGUMENT", arg_index, None, "1", None)
                arg_arr = parse_fw_modify_argument_rd_bin_output(arg_index,  load_to_db, file, len(pat_arr))

        if arg_arr != None:
            for j in range(0, len(pat_arr)):
                _pat = pat_arr[j]
                _arg_handler = dr_parse_fw_modify_arguments_dic.get(_pat.get("type"))
                if _arg_handler != None:
                    _arg = _arg_handler(arg_arr[j])
                    _pat["text"] = "%s %s" % (_pat.get("text"), _arg)
                    pat_arr[j] = _pat

        if pat_arr != None:
            _arr.extend(pat_arr)

        for e in _arr:
            arr.append("%s%s\n" % (TAB, e.get("text")))

    return (2, arr)

def dr_action_counter_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "counter"}
    action["counter_id"] = int(action_dw_0[8 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_flow_tag_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "flow tag"}
    action["flow_tag"] = int(action_dw_0[8 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_aso_parser(action_arr, index):
    _str = ''
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    aso_context_number = int(action_dw_0[8 : 32], 2)
    dest_reg_id = int(action_dw_1[0 : 2], 2)
    aso_context_type = int(action_dw_1[4 : 8], 2)
    aso_fields = int(action_dw_1[16 : 32], 2)

    _str = 'ASO: aso_context_number: ' + hex(aso_context_number)
    _str += ', aso_context_type: '
    if aso_context_type > 0x5:
        _str += hex(aso_context_type)
    else:
        aso_context_type_arr = ["IPSec", "Connection Tracking", "Policers", "Race Avoidance", "First Hit", "MACSEC"]

    _str += aso_context_type_arr[aso_context_type] + ' (' + hex(aso_context_type) + ')'
    _str += ', dest_reg_id: ' + hex(dest_reg_id)

    _str += ', aso_fields: ' + hex(aso_fields)
    aso_init_colors = ["RED", "YELLOW", "GREEN", "UNDEFINED"]
    _str += ' [line_id: ' + hex(aso_fields & 0x1)
    init_color_val = (aso_fields & 0x6) >> 1
    _str += ', initial_color: ' + aso_init_colors[init_color_val] + '(' + hex(init_color_val) + ')]\n'

    return (2, [_str])

switch_actions_parser = {
    DR_ACTION_NOPE: dr_action_nope_parser,
    DR_ACTION_COPY: dr_action_copy_parser,
    DR_ACTION_SET: dr_action_set_parser,
    DR_ACTION_ADD: dr_action_add_parser,
    DR_ACTION_REMOVE_BY_SIZE: dr_action_remove_by_size_parser,
    DR_ACTION_REMOVE_HEADER2HEADER: dr_action_remove_header2header_parser,
    DR_ACTION_INSERT_INLINE: dr_action_insert_inline_parser,
    DR_ACTION_INSERT_POINTER: dr_action_insert_pointer_parser,
    DR_ACTION_ACCELERATED_MODIFY_LIST: dr_action_accelerated_modify_list_parser,
    DR_ACTION_COUNTER: dr_action_counter_parser,
    DR_ACTION_FLOW_TAG: dr_action_flow_tag_parser,
    DR_ACTION_ASO: dr_action_aso_parser,
}

def dr_ste_parse_ste_actions_arr(actions_arr):
    index = 0
    result = []
    while index < 3:
        action_dw_0 = actions_arr[index]
        action_type = int(action_dw_0[0 : 8], 2)
        parser = switch_actions_parser.get(action_type)
        if parser != None:
            res = parser(actions_arr, index)
            index += res[0]
            result.extend(res[1])
        else:
            index += 1

    return result

def action_pretiffy(action):
    action_type = action.get("type")
    _str = action_type
    first = True
    for field in action:
        if field != "type":
            if first:
                _str += ': '
                first = False
            else:
                _str += ', '
            _str += field + ': ' + hex(action.get(field))
    _str += '\n'

    return _str
