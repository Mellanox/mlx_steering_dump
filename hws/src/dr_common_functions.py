from src.dr_common import *
from src.dr_db import _config_args
from src.dr_hl import dr_hl_dw_parser


def action_pretiffy(action, line_break=True):
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
            _str += field + ': '
            val = action.get(field)
            if type(val) is str:
                _str += val
            else:
                _str += hex(val)

    if line_break:
        _str += '\n'

    return _str


def get_field(dw_offset, mask):
    fw_version_major = _config_args.get("fw_version_major")
    if fw_version_major < FW_VERSION_MAJOR_CX7:
        if dw_offset > FLEX_PARSER_0_HL_OFFSET:
            dw_offset += V1_TO_V2_HL_OFFSET_DIFF

    arr = dr_hl_dw_parser(dw_offset, mask)

    if arr != None and len(arr) > 0:
        for f in arr:
            if int(f[1], 2) != 0:
                return f[0]

    return None


def dr_parse_nope_action(action_dw_0, action_dw_1):
    return {}


def dr_parse_set_action(action_dw_0, action_dw_1, parse_value=True):
    action = {"type" : "Set"}
    dw_offset = int(action_dw_0[8 : 16], 2)
    left_shifter = int(action_dw_0[18 : 24], 2)
    if left_shifter >= 32:
        left_shifter -= 32

    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    mask = hex_to_bin_str(hex(int(length * "1", 2) << left_shifter), 32)
    res = get_field(dw_offset, mask)

    if res != None:
        action["field"] = "%s (%s)" % (res, hex(dw_offset))
    else:
        action["dw_offset"] = dw_offset

    action["length"] = length
    action["left_shifter"] = left_shifter
    if parse_value:
        action["inline_data"] = int(action_dw_1, 2)

    return action

def dr_parse_copy_action(action_dw_0, action_dw_1):
    action = {"type" : "Copy"}
    dst_dw_offset = int(action_dw_0[8 : 16], 2)
    dst_left_shifter = int(action_dw_0[18 : 24], 2)
    if dst_left_shifter >= 32:
        dst_left_shifter -= 32

    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    mask = hex_to_bin_str(hex(int(length * "1", 2) << dst_left_shifter), 32)
    res = get_field(dst_dw_offset, mask)

    if res != None:
        action["dst_field"] = "%s (%s)" % (res, hex(dst_dw_offset))
    else:
        action["dst_dw_offset"] = dst_dw_offset

    action["dst_left_shifter"] = dst_left_shifter
    action["length"] = length

    src_dw_offset = int(action_dw_1[8 : 16], 2)
    src_right_shifter = int(action_dw_1[18 : 24], 2)
    if src_right_shifter >= 32:
        src_right_shifter -= 32

    mask = hex_to_bin_str(hex(int(length * "1", 2) << src_right_shifter), 32)
    res = get_field(src_dw_offset, mask)

    if res != None:
        action["src_field"] = "%s (%s)" % (res, hex(src_dw_offset))
    else:
        action["src_dw_offset"] = src_dw_offset

    action["src_right_shifter"] = src_right_shifter

    return action


def dr_parse_add_action(action_dw_0, action_dw_1, parse_value=True):
    action = {"type" : "Add"}
    dw_offset = int(action_dw_0[8 : 16], 2)
    left_shifter = int(action_dw_0[18 : 24], 2)
    if left_shifter >= 32:
        left_shifter -= 32

    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    mask = hex_to_bin_str(hex(int(length * "1", 2) << left_shifter), 32)
    res = get_field(dw_offset, mask)

    if res != None:
        action["field"] = "%s (%s)" % (res, hex(dw_offset))
    else:
        action["dw_offset"] = dw_offset

    action["length"] = length
    action["left_shifter"] = left_shifter

    if parse_value:
        action["value"] = int(action_dw_1, 2)

    return action


def dr_parse_remove_by_size_action(action_dw_0, action_dw_1):
    action = {"type" : "Remove by size"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = modify_pattern_anchor_dic.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    action["outer_l4_removed"] = int(action_dw_0[16 : 17], 2)
    action["start_offset"] = int(action_dw_0[18 : 25], 2)
    action["size"] = int(action_dw_0[26 : 32], 2)

    return action


def dr_parse_remove_header2header_action(action_dw_0, action_dw_1):
    action = {"type" : "Remove header2header"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    end_anchor = int(action_dw_0[18 : 24], 2)
    field = modify_pattern_anchor_dic.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    field = modify_pattern_anchor_dic.get(end_anchor)
    action["end_anchor"] = field if field != None else end_anchor
    action["decap"] = int(action_dw_0[28 : 29], 2)
    action["vni_to_cqe"] = int(action_dw_0[29 : 30], 2)
    action["qos_profile "] = int(action_dw_0[30 : 32], 2)

    return action


def dr_parse_insert_inline_action(action_dw_0, action_dw_1, parse_value=True):
    action = {"type" : "Insert inline"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = modify_pattern_anchor_dic.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    #Offset in words granularity
    action["start_offset"] = '%s Bytes' % hex(int(action_dw_0[18 : 23], 2) * 2)

    if parse_value:
        action["insert_data_inline"] = int(action_dw_1[0 : 32], 2)

    return action


def dr_parse_insert_by_pointer_action(action_dw_0, action_dw_1):
    action = {"type" : "Insert pointer"}
    start_anchor = int(action_dw_0[10 : 16], 2)
    field = modify_pattern_anchor_dic.get(start_anchor)
    action["start_anchor"] = field if field != None else start_anchor
    #Offset in words granularity
    action["start_offset"] = '%s Bytes' % hex(int(action_dw_0[18 : 23], 2) * 2)
    #Size in words granularity
    action["size"] = '%s Bytes' % hex(int(action_dw_0[23 : 29], 2) * 2)
    action["attributes"] = int(action_dw_0[29 : 32], 2)
    action["pointer"] = int(action_dw_1[0 : 32], 2)

    return action

def dr_parse_add_field_action(action_dw_0, action_dw_1):
    action = {"type" : "Add Field"}
    dst_dw_offset = int(action_dw_0[8 : 16], 2)
    dst_left_shifter = int(action_dw_0[18 : 24], 2)
    if dst_left_shifter >= 32:
        dst_left_shifter -= 32

    length = int(action_dw_0[24 : 32], 2)
    length = 32 if length == 0 else length
    mask = hex_to_bin_str(hex(int(length * "1", 2) << dst_left_shifter), 32)
    res = get_field(dst_dw_offset, mask)

    if res != None:
        action["dst_field"] = "%s (%s)" % (res, hex(dst_dw_offset))
    else:
        action["dst_dw_offset"] = dst_dw_offset

    action["dst_left_shifter"] = dst_left_shifter
    action["length"] = length

    src_dw_offset = int(action_dw_1[8 : 16], 2)
    src_right_shifter = int(action_dw_1[18 : 24], 2)
    if src_right_shifter >= 32:
        src_right_shifter -= 32

    mask = hex_to_bin_str(hex(int(length * "1", 2) << src_right_shifter), 32)
    res = get_field(src_dw_offset, mask)

    if res != None:
        action["src_field"] = "%s (%s)" % (res, hex(src_dw_offset))
    else:
        action["src_dw_offset"] = src_dw_offset

    action["src_right_shifter"] = src_right_shifter

    return action
