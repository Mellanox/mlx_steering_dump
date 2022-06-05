#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *


def action_pretiffy(action):
    _str = ''
    action_type = action.get("type")

    if action_type == "NOPE":
        return ''
    elif action_type == "ASO":
        _str = 'ASO: aso_context_number: ' + hex(action.get("aso_context_number"))
        _str += ', aso_context_type: '
        value = action.get("aso_context_type")
        if value > 0x5:
            _str += hex(value)
        else:
            aso_context_type_arr = ["IPSec", "Connection Tracking", "Policers", "Race Avoidance", "First Hit", "MACSEC"]
            _str += aso_context_type_arr[value] + ' (' + hex(value) + ')'
        _str += ', dest_reg_id: ' + hex(action.get("dest_reg_id"))
        value = action.get("aso_fields")

        _str += ', aso_fields: ' + hex(value)
        aso_init_colors = ["RED", "YELLOW", "GREEN", "UNDEFINED"]
        _str += ' [line_id: ' + hex(value & 0x1)
        init_color_val = (value & 0x6) >> 1
        _str += ', initial_color: ' + aso_init_colors[init_color_val] + '(' + hex(init_color_val) + ')]\n'
    else:
        _str += action_type + ': '
        for field in action:
            if field != "type":
                _str += ', ' + field + ': ' + hex(action.get(field))
        _str += '\n'

    return _str
