#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

import subprocess as sp
from hw_steering_src.dr_common import *
from hw_steering_src.dr_db import _fw_ste_indexes_arr, _fw_ste_db, _stes_range_db, _config_args
from hw_steering_src.dr_ste import dr_parse_ste, raw_ste_parser


def parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file):
    min_addr = '0xffffffff'
    max_addr = '0x00000000'
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    data = bin_file.read(68)#There are 68B of prefix data before first STE dump
    ste_dic = {}
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))#Leading zeros will be ignored
        if data[2:8] == RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN:
            ste = '0x' + data[32:]
            hit_add = ste[32 : 41]
            if int(hit_add, 16) & STE_ALWAYS_HIT_ADDRESS != STE_ALWAYS_HIT_ADDRESS:
                ste_addr = '0x' + data[16:24]
                ste_prefix = MLX5DR_DEBUG_RES_TYPE_STE + ','
                ste_prefix += ste_addr + ','
                ste_prefix += fw_ste_index + ','
                file.write(ste_prefix + ste + '\n')
                if load_to_db:
                    ste = dr_parse_ste([MLX5DR_DEBUG_RES_TYPE_STE, ste_addr, fw_ste_index, ste])
                    ste_dic[ste_addr] = ste
                    if ste_addr < min_addr:
                        min_addr = ste_addr
                    if ste_addr > max_addr:
                        max_addr = ste_addr

        data = bin_file.read(80)#Each STE dump contain 64B(STE) + 16(STE prefix)

    bin_file.close()
    _config_args["tmp_file"] = None

    if load_to_db:
        _fw_ste_db[fw_ste_index] = ste_dic
        _stes_range_db[fw_ste_index] = (min_addr, max_addr)


def call_resource_dump(dev, segment, index1, num_of_obj1, num_of_obj2, depth):
    _input = 'resourcedump dump -d ' + dev
    _input += ' --segment ' + segment
    _input += ' --index1 ' + index1
    if num_of_obj1 != None:
        _input += ' --num-of-obj1 ' + num_of_obj1
    if num_of_obj2 != None:
        _input += ' --num-of-obj2 ' + num_of_obj2
    if depth != None:
        _input += ' --depth=' + depth
    if _config_args.get("resourcedump_mem_mode"):
        _input += ' --mem ' + _config_args.get("dev_name")
        _input += ' --bin ' + _config_args.get("tmp_file_path")

    output = sp.getoutput(_input)

    if (len(output) >= 10) and ('Error' in output[0:10]):
        print('MFT Error')
        exit()

    return output


def parse_fw_ste_rd_output(data, fw_ste_index, load_to_db, file):
    ste_dic = {}
    min_addr = '0xffffffff'
    max_addr = '0x00000000'
    data_arr = data.split('\n')
    file.write(MLX5DR_DEBUG_RES_TYPE_FW_STE + ',' + fw_ste_index + '\n')
    for count in range(0, len(data_arr)):
        if RESOURCE_DUMP_SEGMENT_TYPE_STE in data_arr[count][0:10]:
            ste_addr = (data_arr[count][22 : 32]).lower()
            ste = data_arr[count + 1] + data_arr[count + 2] + data_arr[count + 3] + data_arr[count + 4]
            ste = ste.replace(' 0x', '')
            hit_add = ste[32 : 41]
            if int(hit_add, 16) & STE_ALWAYS_HIT_ADDRESS != STE_ALWAYS_HIT_ADDRESS:
                ste_prefix = MLX5DR_DEBUG_RES_TYPE_STE + ','
                ste_prefix += ste_addr + ','
                ste_prefix += fw_ste_index + ','
                file.write(ste_prefix + ste + '\n')
                if load_to_db:
                    ste = dr_parse_ste([MLX5DR_DEBUG_RES_TYPE_STE, ste_addr, fw_ste_index, ste])
                    ste_dic[ste_addr] = ste
                    if ste_addr < min_addr:
                        min_addr = ste_addr
                    if ste_addr > max_addr:
                        max_addr = ste_addr

    if load_to_db:
        _fw_ste_db[fw_ste_index] = ste_dic
        _stes_range_db[fw_ste_index] = (min_addr, max_addr)


def dump_hw_resources(load_to_db, dev, file):
    #Dump FW STE's, and save the range into
    for fw_ste_index in _fw_ste_indexes_arr:
        output = call_resource_dump(dev, "FW_STE", fw_ste_index, None, 'all', None)
        if _config_args.get("resourcedump_mem_mode"):
            parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file)
        else:
            parse_fw_ste_rd_output(output, fw_ste_index, load_to_db, file)


def dr_hw_data_engine(obj, file):
    if _config_args.get("dump_hw_resources"):
        load_to_db = _config_args.get("load_hw_resources")
        device = _config_args.get("device")
        if device == None:
            print('Unknown MST device')
            exit()

        file.write(MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START + '\n')
        dump_hw_resources(load_to_db, device, file)
        file.write(MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_END + '\n')
