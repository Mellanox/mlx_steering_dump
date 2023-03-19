#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args
from src.dr_ste import dr_parse_ste
from src.dr_hw_resources import dr_parse_fw_stc_action_get_obj_id, dr_parse_fw_stc_get_addr, dr_parse_fw_modify_pattern
from src.dr_visual import interactive_progress_bar


def parse_fw_stc_rd_bin_output(stc_index, load_to_db, file):
    _dests = {}
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    stc = ''

    #There are 68B of prefix data before first STC dump
    data = bin_file.read(68)
    while data:
        #Leading zeros will be ignored
        data = hex(int.from_bytes(data, byteorder='big'))
        data_type = data[2:8]
        if data_type == RESOURCE_DUMP_SEGMENT_TYPE_STC_BIN:
            stc = '0x' + data[32:]
            data = bin_file.read(48)
            continue
        elif data_type[:-1] == RESOURCE_DUMP_SEGMENT_TYPE_ACTION_STC_BIN:
            stc_action = '0x' + data[31:]
            obj = dr_parse_fw_stc_action_get_obj_id(stc_action)
            if obj != None:
                addr = dr_parse_fw_stc_get_addr(stc)
                write_line = '%s,%s,%s,%s\n' % (MLX5DR_DEBUG_RES_TYPE_ADDRESS, addr, obj.get("type"), obj.get("id"))
                file.write(write_line)
                _dests[addr] = obj

        data = bin_file.read(80)

    bin_file.close()
    _config_args["tmp_file"] = None

    if load_to_db:
        _db._term_dest_db.update(_dests)


def parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file):
    min_addr = '0xffffffff'
    max_addr = '0x00000000'
    first_ste = True
    ste_dic = {}
    count = 0

    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")

    file.write(MLX5DR_DEBUG_RES_TYPE_FW_STE + ',' + fw_ste_index + '\n')

    #First read DW(4B) each time till reaching first STE
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[2:8] == RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN:
            #Seek to the first STE location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Each STE dump contain 64B(STE) + 16(STE prefix)
    data = bin_file.read(80)

    while data:
        #Leading zeros will be ignored
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[2:8] == RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN:
            ste = '0x' + data[32:]
            hit_add = ste[32 : 41]
            if first_ste:
                ste_addr = '0x' + data[16:24]
                if ste_addr < min_addr:
                    min_addr = ste_addr
                first_ste = False
            if int(hit_add, 16) & STE_ALWAYS_HIT_ADDRESS != STE_ALWAYS_HIT_ADDRESS:
                ste_addr = '0x' + data[16:24]
                ste_prefix = MLX5DR_DEBUG_RES_TYPE_STE + ','
                ste_prefix += ste_addr + ','
                ste_prefix += fw_ste_index + ','
                file.write(ste_prefix + ste + '\n')
                if load_to_db:
                    ste = dr_parse_ste([MLX5DR_DEBUG_RES_TYPE_STE, ste_addr, fw_ste_index, ste])
                    ste_dic[ste_addr] = ste
                    if ste_addr > max_addr:
                        max_addr = ste_addr

        #Each STE dump contain 64B(STE) + 16(STE prefix)
        data = bin_file.read(80)

    bin_file.close()
    _config_args["tmp_file"] = None

    if load_to_db:
        _db._fw_ste_db[fw_ste_index] = ste_dic
        _db._stes_range_db[fw_ste_index] = (min_addr, max_addr)

    file.write("%s,%s,%s,%s\n" % (MLX5DR_DEBUG_RES_TYPE_FW_STE_STATS, fw_ste_index, min_addr, max_addr))


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
                    ste = dr_parse_ste([MLX5DR_DEBUG_RES_TYPE_STE, ste_addr, fw_ste_index, ste], True)
                    ste_dic[ste_addr] = ste
                    if ste_addr < min_addr:
                        min_addr = ste_addr
                    if ste_addr > max_addr:
                        max_addr = ste_addr

    if load_to_db:
        #Save the STE's to FW STE DB
        _db._fw_ste_db[fw_ste_index] = ste_dic
        #Save the STE's range for this FW STE
        _db._stes_range_db[fw_ste_index] = (min_addr, max_addr)


def dump_hw_resources(load_to_db, dev, dev_name, file):
    total_resources = _config_args.get("total_resources")
    interactive_progress_bar(0, total_resources, DUMPING_HW_RESOURCES)
    i = 0
    for stc_index in _db._stc_indexes_arr:
        output = call_resource_dump(dev, dev_name, "STC", stc_index, None, 'all', None)
        parse_fw_stc_rd_bin_output(stc_index, load_to_db, file)
        i += 1
        interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)

    #Dump FW STE's
    for fw_ste_index in _db._fw_ste_indexes_arr:
        output = call_resource_dump(dev, dev_name, "FW_STE", fw_ste_index, None, 'all', None)
        if _config_args.get("resourcedump_mem_mode"):
            parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file)
        else:
            parse_fw_ste_rd_output(output, fw_ste_index, load_to_db, file)

        i += 1
        interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)


def dr_hw_data_engine(obj, file):
    if _config_args.get("dump_hw_resources"):
        load_to_db = _config_args.get("load_hw_resources")
        dev = _config_args.get("shared_device")
        if dev == None:
            dev = _config_args.get("device")
            if dev == None:
                print('Unknown MST device')
                exit()
            dev_name = _config_args.get("dev_name")
            _vhca_id = _config_args.get("vhca_id")
        else:
            dev_name = _config_args.get("shared_dev_name")
            _vhca_id = _config_args.get("shared_vhca_id")

        file.write(MLX5DR_DEBUG_RES_TYPE_HW_RRESOURCES_DUMP_START + '\n')
        _config_args["hw_resources_dump_started"] = True
        _config_args["_dev"] = dev
        _config_args["_dev_name"] = dev_name
        _config_args["_vhca_id"] = _vhca_id
        dump_hw_resources(load_to_db, dev, dev_name, file)
