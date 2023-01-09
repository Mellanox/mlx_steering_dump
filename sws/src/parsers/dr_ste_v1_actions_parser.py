# Copyright (c) 2020 Mellanox Technologies, Inc.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def mlx5_ifc_ste_v1_action_bits_parser(actions):
    if int(actions[0], 16) & 0xff000000 == 0x05000000:
        return mlx5_ifc_ste_v1_action_single_modify_copy_parser([actions[0], actions[1]])
    elif int(actions[0], 16) & 0xff000000 == 0x05000000 and len(actions) > 2:
        return mlx5_ifc_ste_v1_action_single_modify_copy_parser([actions[1], actions[2]])
    elif int(actions[0], 16) & 0xff000000 == 0x06000000:
        return mlx5_ifc_ste_v1_action_single_modify_set_parser([actions[0], actions[1]])
    elif int(actions[0], 16) & 0xff000000 == 0x06000000 and len(actions) > 2:
        return mlx5_ifc_ste_v1_action_single_modify_set_parser([actions[1], actions[2]])
    elif int(actions[0], 16) & 0xff000000 == 0x07000000:
        return mlx5_ifc_ste_v1_action_single_modify_add_parser([actions[0], actions[1]])
    elif int(actions[0], 16) & 0xff000000 == 0x07000000 and len(actions) > 2:
        return mlx5_ifc_ste_v1_action_single_modify_add_parser([actions[1], actions[2]])
    elif int(actions[0], 16) & 0xff000000 == 0x12000000:
        return mlx5_ifc_ste_v1_action_aso_parser([actions[0], actions[1]])
    elif int(actions[1], 16) & 0xff000000 == 0x12000000 and len(actions) > 2:
        return mlx5_ifc_ste_v1_action_aso_parser([actions[1], actions[2]])
    return {}


def mlx5_ifc_ste_v1_action_aso_parser(actions):
    result = {}

    result["action_id"] = 0x12
    result["ctx_num"] = int(actions[0], 16) & 0x00ffffff
    result["dest_reg_id"] = ((int(actions[1], 16) & 0b11000000000000000000000000000000) >> 30) * 2 + 1
    result["ctx_type"] = (int(actions[1], 16) & 0x0f000000) >> 24
    if result["ctx_type"] == 0x1:
        result["direction"] = int(actions[1], 16) & 0b00000000000000000000000000000001
    if result["ctx_type"] == 0x2:
        result["initial_color"] = (int(actions[1], 16) & 0b00000000000000000000000000000110) >> 1
        result["line_id"] = int(actions[1], 16) & 0b00000000000000000000000000000001
    if result["ctx_type"] == 0x4:
        result["_set"] = (int(actions[1], 16) & 0b00000000000000000000001000000000) >> 9
        result["line_id"] = int(actions[1], 16) & 0b00000000000000000000000111111111

    return result


def mlx5_ifc_ste_v1_action_single_modify_copy_parser(actions):
    result = {}

    result["action_id"] = 0x5
    result["destination_dw_offset"] = (int(actions[0], 16) & 0x00ff0000) >> 16
    result["destination_left_shifter"] = (int(actions[0], 16) & 0b00000000000000000011111100000000) >> 8
    result["destination_length"] = int(actions[0], 16) & 0b00000000000000000000000000111111
    result["source_dw_offset"] = (int(actions[1], 16) & 0x00ff0000) >> 16
    result["source_right_shifter"] = (int(actions[1], 16) & 0b00000000000000000011111100000000) >> 8


def mlx5_ifc_ste_v1_action_single_modify_set_parser(actions):
    result = {}

    result["action_id"] = 0x6
    result["destination_dw_offset"] = (int(actions[0], 16) & 0x00ff0000) >> 16
    result["destination_left_shifter"] = (int(actions[0], 16) & 0b00000000000000000011111100000000) >> 8
    result["destination_length"] = int(actions[0], 16) & 0b00000000000000000000000000111111
    result["inline_data"] = int(actions[1], 16) & 0xffffffff

    return result


def mlx5_ifc_ste_v1_action_single_modify_add_parser(actions):
    result = {}

    result["action_id"] = 0x7
    result["destination_dw_offset"] = (int(actions[0], 16) & 0x00ff0000) >> 16
    result["destination_left_shifter"] = (int(actions[0], 16) & 0b00000000000000000011111100000000) >> 8
    result["destination_length"] = int(actions[0], 16) & 0b00000000000000000000000000111111
    result["add_value"] = int(actions[1], 16) & 0xffffffff

    return result
