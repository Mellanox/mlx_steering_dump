#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

def dump_obj_str(keys, data):
    _str = ""
    length = len(keys)
    for i in range(length):
        key = keys[i]
        if key == "id":
            continue

        if key == "mlx5dr_debug_res_type":
            _str = _str + class_name_arr[data[key]]
            if "id" in keys:
                _str = _str + " " + data["id"]
            _str = _str + ": "
            continue

        _str = _str + key + " "
        if data[key] == None:
            _str = _str + "NONE"
        else:
            _str = _str + data[key]
        if i < (length - 1):
            _str = _str + ", "
        else:
            _str = _str + "\n"

    return _str



MLX5DR_DEBUG_RES_TYPE_CONTEXT = "4000"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR = "4001"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS = "4002"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE = "4003"
MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING = "4004"

MLX5DR_DEBUG_RES_TYPE_TABLE = "4100"

MLX5DR_DEBUG_RES_TYPE_MATCHER = "4200"
MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR = "4201"
MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX = "4202"
MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX = "4203"
MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE = "4204"

class_name_arr = {
    MLX5DR_DEBUG_RES_TYPE_CONTEXT: "Context",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR: "Attr",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS: "Caps",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE: "Send_engine",
    MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING: "Send_ring",
    MLX5DR_DEBUG_RES_TYPE_TABLE: "Table",
    MLX5DR_DEBUG_RES_TYPE_MATCHER: "Matcher",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR: "Attr",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX: "Nic_RX",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX: "Nic_TX",
    MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE: "Template",
}
