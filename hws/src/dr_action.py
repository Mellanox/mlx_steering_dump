#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_hw_resources import parse_fw_modify_pattern_rd_bin_output, dr_parse_fw_modify_arguments_dic
from src.dr_common_functions import *


def dr_action_nope_parser(action_arr, index):
    return (1, [''])

def dr_action_copy_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_copy_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

def dr_action_set_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_set_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

def dr_action_add_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_add_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

def dr_action_remove_by_size_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_remove_by_size_action(action_dw_0, action_dw_1)

    return (1, [action_pretiffy(action)])

def dr_action_remove_header2header_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_remove_header2header_action(action_dw_0, action_dw_1)

    return (1, [action_pretiffy(action)])

def dr_action_insert_inline_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_insert_inline_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

def dr_action_insert_pointer_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_insert_by_pointer_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

def dr_action_accelerated_modify_list_parser(action_arr, index):
    verbose = _config_args.get("verbose")
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = {"type" : "Modify action list"}
    modify_actions_pattern_pointer = int(action_dw_0[8 : 32], 2)
    number_of_modify_actions =  int(action_dw_1[0 : 8], 2)
    modify_actions_argument_pointer = int(action_dw_1[8 : 32], 2)
    action["pat_idx"] = modify_actions_pattern_pointer
    action["num_of_actions"] = number_of_modify_actions
    action["arg_idx"] = modify_actions_argument_pointer
    output_arr = [action_pretiffy(action)]
    dump_arg = _config_args.get("extra_hw_res_arg")
    dump_pat = _config_args.get("extra_hw_res_pat")

    load_to_db = _config_args.get("load_hw_resources")
    dev = _config_args.get("_dev")
    dev_name = _config_args.get("_dev_name")
    file = _config_args.get("csv_file")
    num_of_pat = int((number_of_modify_actions + PAT_ARG_BULK_SIZE - 1) // PAT_ARG_BULK_SIZE)#Addition to ceiling division
    for i in range (0, num_of_pat):
        pat_index = hex(modify_actions_pattern_pointer + i)
        pat_arr = _db._pattern_db.get(pat_index)
        if pat_arr == None:
            if dump_pat == True:
                output = call_resource_dump(dev, dev_name, "HW_MODIFY_PATT", pat_index, None, None, None)
                pat_sz = PAT_ARG_BULK_SIZE if (i != num_of_pat - 1) else (number_of_modify_actions % PAT_ARG_BULK_SIZE)
                pat_arr = parse_fw_modify_pattern_rd_bin_output(pat_index,  load_to_db, file, pat_sz)

        if pat_arr == None:
            continue

        arg_index = hex(modify_actions_argument_pointer + i)
        arg_str = _db._argument_db.get(arg_index)

        if arg_str != None:
            for j in range(0, len(pat_arr)):
                _pat = pat_arr[j]
                raw_data = ''
                _arg_handler = dr_parse_fw_modify_arguments_dic.get(_pat.get("type"))
                #each arg is MODIFY_ARGUMENT_BYTES_SZ bytes & each byte = 2 chars
                start_substring = 2 * j * MODIFY_ARGUMENT_BYTES_SZ
                if _arg_handler != None:
                    _arg = _arg_handler(arg_str[start_substring : start_substring + (2 * MODIFY_ARGUMENT_BYTES_SZ)])
                    if verbose > 2:
                        raw_data = " (%s %s)" % (_pat.get("raw"), _arg.get("raw"))

                    output_arr.append("%s%s, %s%s\n" % (TAB, _pat.get("text"), _arg.get("text"), raw_data))
                else:
                    if verbose > 2:
                        raw_data = " (%s)" % _pat.get("raw")
                    output_arr.append("%s%s%s\n" % (TAB, _pat.get("text"), raw_data))
        else:
            for j in range(0, len(pat_arr)):
                _pat = pat_arr[j]
                raw_data = ''
                if verbose > 2:
                    raw_data = " (%s)" % _pat.get("raw")

                output_arr.append("%s%s%s\n" % (TAB, _pat.get("text"), raw_data))

    return (2, output_arr)

def dr_action_counter_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "Counter"}
    action["counter_id"] = int(action_dw_0[8 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_flow_tag_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "Flow tag"}
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

    _str = 'ASO: ctx_idx: ' + hex(aso_context_number)
    _str += ', type: '
    if aso_context_type > 0x5:
        _str += hex(aso_context_type)
    else:
        aso_context_type_arr = ["IPSec", "Connection Tracking", "Policers", "Race Avoidance", "First Hit", "MACSEC"]
        _str += aso_context_type_arr[aso_context_type] + ' (' + hex(aso_context_type) + ')'

    _str += ', dest_reg_id: ' + hex(dest_reg_id)

    if aso_context_type != 0x0:
        _str += ', fields: ' + hex(aso_fields)
    if aso_context_type == 0x2:
        aso_init_colors = ["RED", "YELLOW", "GREEN", "UNDEFINED"]
        _str += ' [line_id: ' + hex(aso_fields & 0x1)
        init_color_val = (aso_fields & 0x6) >> 1
        _str += ', initial_color: ' + aso_init_colors[init_color_val] + '(' + hex(init_color_val) + ')]'

    _str += '\n'

    return (2, [_str])

def dr_action_ipsec_enc_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "IPsec encryption"}
    action["sadb_ctx_idx"] = int(action_dw_0[8 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_ipsec_dec_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action = {"type" : "IPsec decryption"}
    action["sadb_ctx_idx"] = int(action_dw_0[8 : 32], 2)

    return (1, [action_pretiffy(action)])

def dr_action_trailer_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    _str = 'Trailer: command: '
    command = int(action_dw_0[8 : 12], 2)
    if command == 0x0:
        _str += 'Insert (0x0)'
    elif command == 0x1:
        _str += 'Remove (0x1)'
    else:
        _str += hex(command)

    _type = int(action_dw_0[14 : 16], 2)
    _str += ' type: '
    if _type == 0x0:
        _str += 'IPSEC (0x0)'
    elif _type == 0x1:
        _str += 'MACEC (0x1)'
    elif _type == 0x2:
        _str += 'PSP (0x2)'
    else:
        _str += hex(_type)

    size = int(action_dw_0[26 : 32], 2)
    _str += ' size: %s\n' % hex(size)

    return (1, [_str])

def dr_action_add_field_parser(action_arr, index):
    action_dw_0 = action_arr[index]
    action_dw_1 = action_arr[index + 1]
    action = dr_parse_add_field_action(action_dw_0, action_dw_1)

    return (2, [action_pretiffy(action)])

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
    DR_ACTION_IPSEC_ENC: dr_action_ipsec_enc_parser,
    DR_ACTION_IPSEC_DEC: dr_action_ipsec_dec_parser,
    DR_ACTION_TRAILER: dr_action_trailer_parser,
    DR_ACTION_ADD_FIELD : dr_action_add_field_parser,
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

