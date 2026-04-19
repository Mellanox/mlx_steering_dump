#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from pathlib import Path
import os
import multiprocessing as mp
import queue
import subprocess as sp
from src.dr_common import *
from src.dr_db import _db, _config_args
from src.dr_ste import dr_parse_ste
from src.dr_hw_resources import dr_parse_fw_stc_action_get_obj_id, dr_parse_fw_stc_get_addr, dr_parse_fw_modify_pattern
from src.dr_visual import interactive_progress_bar

def dr_dump_send_queue(sqn, queue_size, entry_num):
    dev = _config_args.get("device")
    dev_name = _config_args.get("dev_name")

    # Phase 1: Get pi value from first command
    cmd1 = f"fwqd {dev} {sqn} sq --num 1"
    #print(f"Phase 1 - Executing command: {cmd1}")
    try:
        status, output = sp.getstatusoutput(cmd1)
        if status != 0:
            print(f"Phase 1 command failed with return code: {status}")
            print(f"Output: {output}")
            return (output if output else "Phase 1 command failed with no error message", None)

        # Extract pi value from the output
        pi = None
        for line in output.split('\n'):
            if 'pi' in line:
                # Look for pattern like "pi 0x140" or "pi: 0x140"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part in ['pi', 'pi:'] and i + 1 < len(parts):
                        pi_value = parts[i + 1]
                        # Convert hex string to integer if it starts with 0x
                        if pi_value.startswith('0x'):
                            pi = int(pi_value, 16)
                        else:
                            pi = int(pi_value)
                        break
                if pi is not None:
                    break

        if pi is None:
            print("Warning: Could not extract pi value from phase 1 output, using default 200")
            return ("Warning: Could not extract pi value from phase 1 output, using default 200", None)
        # Phase 2: Run command with queue size value
        # Take min of pi and queue_size
        processed_pi = min(pi, queue_size)
        if entry_num > 0:
            processed_pi = min(processed_pi, entry_num)
        start_entry = 0 if pi < queue_size else pi - queue_size
        cmd2 = f"fwqd {dev} {sqn} sq --num {processed_pi} --fi {start_entry}"
        #print(f"Phase 2 - Executing command: {cmd2}")
        status, output = sp.getstatusoutput(cmd2)
        if status != 0:
            print(f"Phase 2 command failed with return code: {status}")
            print(f"Output: {output}")
            return (output if output else "Phase 2 command failed with no error message", None)
        return (output, processed_pi)

    except sp.TimeoutExpired as e:
        print(f"Command timed out after 30 seconds")
        return ("Command timed out", None)
    except Exception as e:
        print(f"Exception occurred: {type(e).__name__}: {str(e)}")
        return (f"Exception: {str(e)}", None)

def query_and_parse_ft_meta_rd_bin_output(ft_id, load_to_db, dev, dev_name, file):
    output = call_resource_dump(dev, dev_name, "QUERY_FT_META", ft_id, None, None, None)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    count = 0

    #First read DW(4B) each time till reaching FT META
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[2:8] == RESOURCE_DUMP_SEGMENT_TYPE_FT_META_BIN:
            #Seek to FT META location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Read FT META
    data = bin_file.read(112)
    if len(data) == 112:
        data = hex(int.from_bytes(data, byteorder='big'))
        rx_icm_addr = "0x" + data[192:200]
        tx_icm_addr = "0x" + data[200:208]
        _db._ft_idx_dic[ft_id] = (rx_icm_addr, tx_icm_addr)
        write_line = '%s,%s,%s,%s\n' % (MLX5DR_DEBUG_RES_TYPE_FT_ANCHORS, ft_id, rx_icm_addr, tx_icm_addr)
        file.write(write_line)
        if load_to_db:
            if rx_icm_addr != "0x0":
                _db._term_dest_db[rx_icm_addr] = {"type": "FT", "id": ft_id}
            if tx_icm_addr != "0x0":
                _db._term_dest_db[tx_icm_addr] = {"type": "FT", "id": ft_id}

def parse_stc_rd_bin_output(stc_index, load_to_db, file):
    _dests = {}
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    count = 0
    stc_meta = ''
    stc_meta_segment_sz = _config_args.get("resource_dump_segment_action_stc_meta_bin_sz")
    stc_raw_segment_sz = _config_args.get("resource_dump_segment_action_stc_raw_bin_sz")
    stc_param_start_ofset = _config_args.get("stc_param_start_ofset")
    stc_param_end_ofset = _config_args.get("stc_param_end_ofset")
    stc_action_type_offset = _config_args.get("stc_action_type_offset")

    #First read DW(4B) each time till reaching first STC
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[4:8] == RESOURCE_DUMP_SEGMENT_TYPE_STC_INFO_META_BIN:
            #Seek to the first STC location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Read first STC INFO
    data = bin_file.read(stc_meta_segment_sz)

    while data:
        #Leading zeros will be ignored
        data = hex(int.from_bytes(data, byteorder='big'))
        data_type = data[4:8]
        if data_type == RESOURCE_DUMP_SEGMENT_TYPE_STC_INFO_META_BIN:
            stc_meta = '0x' + data[32:]
            data = bin_file.read(stc_raw_segment_sz)
            continue
        elif data_type == RESOURCE_DUMP_SEGMENT_TYPE_STC_INFO_RAW_BIN:
            stc_raw = '0x' + data[32:]
            obj = dr_parse_fw_stc_action_get_obj_id(stc_meta, stc_param_start_ofset,
                                                    stc_param_end_ofset, stc_action_type_offset)

            if obj != None:
                addr = dr_parse_fw_stc_get_addr(stc_raw)
                write_line = '%s,%s,%s,%s\n' % (MLX5DR_DEBUG_RES_TYPE_ADDRESS, addr, obj.get("type"), obj.get("id"))
                file.write(write_line)
                if obj.get("type") == 'FW_STE_TABLE':
                    _id = str(int(obj.get("id"), 16))
                    if _id not in _db._fw_ste_indexes_arr:
                        _db._fw_ste_indexes_arr.append(_id)

                elif obj.get("type") == 'MODIFY_LIST' or obj.get("type") == 'INSERT_HEADER':
                    _db._arg_obj_indexes_dic[obj.get("id")] = ''

                elif obj.get("type") == 'FLOW_COUNTER':
                    _db._flow_counter_indexes_dic[obj.get("id")] = ''

                else:
                    _dests[addr] = obj

        data = bin_file.read(stc_meta_segment_sz)

    bin_file.close()
    _config_args["tmp_file"] = None

    if load_to_db:
        _db._term_dest_db.update(_dests)

def parse_fw_stc_rd_bin_output(stc_index, load_to_db, file):
    _dests = {}
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    stc = ''
    count = 0
    action_stc_segment_sz = _config_args.get("resource_dump_segment_action_stc_bin_sz")
    stc_param_start_ofset = _config_args.get("stc_param_start_ofset")
    stc_param_end_ofset = _config_args.get("stc_param_end_ofset")
    stc_action_type_offset = _config_args.get("stc_action_type_offset")

    #First read DW(4B) each time till reaching first STC
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[4:8] == RESOURCE_DUMP_SEGMENT_TYPE_STC_BIN:
            #Seek to the first STC location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Read first STC
    data = bin_file.read(80)

    while data:
        #Leading zeros will be ignored
        data = hex(int.from_bytes(data, byteorder='big'))
        data_type = data[4:8]
        if data_type == RESOURCE_DUMP_SEGMENT_TYPE_STC_BIN:
            stc = '0x' + data[32:]
            data = bin_file.read(action_stc_segment_sz)
            continue
        elif RESOURCE_DUMP_SEGMENT_TYPE_ACTION_STC_BIN in data_type:
            stc_action = '0x' + data[31:]
            obj = dr_parse_fw_stc_action_get_obj_id(stc_action, stc_param_start_ofset,
                                                    stc_param_end_ofset, stc_action_type_offset)
            if obj != None:
                addr = dr_parse_fw_stc_get_addr(stc)
                write_line = '%s,%s,%s,%s\n' % (MLX5DR_DEBUG_RES_TYPE_ADDRESS, addr, obj.get("type"), obj.get("id"))
                file.write(write_line)
                if obj.get("type") == 'FW_STE_TABLE':
                    _id = str(int(obj.get("id"), 16))
                    if _id not in _db._fw_ste_indexes_arr:
                        _db._fw_ste_indexes_arr.append(_id)

                elif obj.get("type") == 'MODIFY_LIST' or obj.get("type") == 'INSERT_HEADER':
                    _db._arg_obj_indexes_dic[obj.get("id")] = ''

                elif obj.get("type") == 'FLOW_COUNTER':
                    _db._flow_counter_indexes_dic[obj.get("id")] = ''

                else:
                    _dests[addr] = obj

        data = bin_file.read(80)

    bin_file.close()
    _config_args["tmp_file"] = None

    if load_to_db:
        _db._term_dest_db.update(_dests)


def parse_fw_ste_rd_bin_output_chunk(f_path, f_seek, chunk_sz, fw_ste_index, load_to_db, segment_type):
    min_addr = '0xffffffff'
    max_addr = '0x00000000'
    ste_dic = {}
    count = 0
    _str = ''

    bin_file = open(f_path, 'rb')
    bin_file.seek(f_seek)

    #Each STE dump contain 64B(STE) + 16(STE prefix)
    data = bin_file.read(80)
    _data = hex(int.from_bytes(data, byteorder='big'))
    if _data[4:8] == segment_type:
        min_addr = f'0x{(int(_data[16:24], 16)):0{8}x}'

    while data and count < chunk_sz:
        count += 80
        #Leading zeros will be ignored
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[4:8] == segment_type:
            ste = f'0x{data[32:]}'
            hit_add = ste[32 : 41]
            if segment_type == RESOURCE_DUMP_SEGMENT_TYPE_STE_INFO_BIN:
                ste_addr = f'0x{(int(data[16:24], 16) + int(data[24:32], 16)):0{8}x}'
            else:
                ste_addr = '0x' + data[16:24]
            if ste_addr > max_addr:
                max_addr = ste_addr
            if int(hit_add, 16) & STE_ALWAYS_HIT_ADDRESS != STE_ALWAYS_HIT_ADDRESS:
                _str += f'{MLX5DR_DEBUG_RES_TYPE_STE},{ste_addr},{fw_ste_index},{ste}\n'
                if load_to_db:
                    ste = dr_parse_ste([MLX5DR_DEBUG_RES_TYPE_STE, ste_addr, fw_ste_index, ste])
                    ste_dic[ste_addr] = ste

        #Each STE dump contain 64B(STE) + 16(STE prefix)
        data = bin_file.read(80)

    bin_file.close()
    return _str, ste_dic, min_addr, max_addr

def parse_fw_ste_rd_bin_output_worker(req_q, resp_q):
    while True:
        try:
            work_item = req_q.get(timeout=1)
        except Exception as e:
            print(f'Failed to get work item: {type(e).__name__}: {e}', flush=True)
            return
        if work_item is None:
            return

        try:
            f_path, f_seek, chunk_sz, fw_ste_index, load_to_db, segment_type = work_item
            resp_q.put(parse_fw_ste_rd_bin_output_chunk(f_path, f_seek, chunk_sz,
                                                        fw_ste_index, load_to_db, segment_type))
        except Exception as e:
            print(f'Failed to parse binary output: {type(e).__name__}: {e}', flush=True)

def parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file, tmp_file_path):
    # Let's parse the tmp_file in separate processes, that we can parse every
    # 256K STE (16B + 64B * 256K = 20MB) of file data in a new process.
    num_workers = _config_args.get("max_cores")
    bin_file = open(tmp_file_path, 'rb')
    min_addr = '0xffffffff'
    max_addr = '0x00000000'
    resp_q = mp.Queue()
    req_q = mp.Queue()
    num_of_chunks = 0
    bin_file_sz = 0
    processes = []
    ste_dic = {}
    count = 0
    segment_type = RESOURCE_DUMP_SEGMENT_TYPE_STE_INFO_BIN

    if _config_args.get("legacy_rd"):
        segment_type = RESOURCE_DUMP_SEGMENT_TYPE_STE_BIN

    # Get the file size
    bin_file.seek(0, 2)
    bin_file_sz = bin_file.tell()
    # Seek to the beginning of the file
    bin_file.seek(0, 0)

    file.write(f'{MLX5DR_DEBUG_RES_TYPE_FW_STE},{fw_ste_index}\n')

    # First read DW(4B) each time till reaching first STE
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[4:8] == segment_type:
            break

        count += 4
        data = bin_file.read(4)

    bin_file.close()

    # Now we are at the first STE
    # Split the file into chunks and send to the workers
    # chunk_sz = 256K STEs ((16B + 64B) * 256K = 20MB)
    chunk_sz = 256 * 1024 * 80
    while count < bin_file_sz:
        req_q.put((tmp_file_path, count, chunk_sz, fw_ste_index, load_to_db, segment_type))
        # Split the read to chunk_sz STEs
        count += chunk_sz
        num_of_chunks += 1

    for i in range(min(num_workers, num_of_chunks)):
        req_q.put(None)
        p = mp.Process(target=parse_fw_ste_rd_bin_output_worker, args=(req_q, resp_q))
        processes.append(p)

    [p.start() for p in processes]

    num_of_results = 0
    while any([p.is_alive() for p in processes]) or not resp_q.empty():
        try:
            _str, _ste_dic, _min_addr, _max_addr = resp_q.get(timeout=1)
        except queue.Empty:
            continue
        file.write(_str)
        num_of_results += 1
        ste_dic.update(_ste_dic)
        if _min_addr < min_addr:
            min_addr = _min_addr
        if _max_addr > max_addr:
            max_addr = _max_addr

    [p.join() for p in processes]

    if num_of_results < num_of_chunks:
        print(f'Got only {num_of_results} results, expected {num_of_chunks}. '
              f'Results are incomplete.')

    if load_to_db:
        _db._fw_ste_db[fw_ste_index] = ste_dic
        _db._stes_range_db[fw_ste_index] = (min_addr, max_addr)

    file.write(f'{MLX5DR_DEBUG_RES_TYPE_FW_STE_STATS},{fw_ste_index},{min_addr},{max_addr}\n')


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


def parse_fw_modify_argument_rd_bin_output(arg_index,  load_to_db, file, segment_type):
    arg_dic = {}
    arr = []
    file_str = "%s,%s" % (MLX5DR_DEBUG_RES_TYPE_ARGUMENT, arg_index)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    count = 0

    #First read DW(4B) each time till reaching first argument
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[4:8] == segment_type:
            #Seek to the first argument location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Read first argument
    data = bin_file.read(80)

    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        data_type = data[4:8]
        if data_type == segment_type:
            index = hex(int(data[16:24], 16))
            file_str = "%s,%s,%s" % (MLX5DR_DEBUG_RES_TYPE_ARGUMENT, arg_index, index)
            arr = data[32:]
            file_str += ",%s" % arr
            file.write("%s\n" % file_str)
            if load_to_db:
                arg_dic[index] = arr

        #64B(Args data) + 16(Prefix)
        data = bin_file.read(80)

    if load_to_db:
        _db._argument_db.update(arg_dic)


def parse_fw_counter_rd_bin_output(counter_index,  load_to_db, file, segment_type):
    counters_dic = {}
    file_str = "%s,%s" % (MLX5DR_DEBUG_RES_TYPE_COUNTER, counter_index)
    _config_args["tmp_file"] = open(_config_args.get("tmp_file_path"), 'rb+')
    bin_file = _config_args.get("tmp_file")
    count = 0

    #First read DW(4B) each time till reaching first counter
    data = bin_file.read(4)
    while data:
        data = hex(int.from_bytes(data, byteorder='big'))
        if data[3:7] == segment_type:
            #Seek to the first counter location in the bin_file
            bin_file.seek(count)
            break

        count += 4
        data = bin_file.read(4)

    #Read first counter
    data = bin_file.read(32)

    while data:
        #Leading zeros will be ignored, add zero to keep alignment
        data = "0%s" % hex(int.from_bytes(data, byteorder='big'))
        data_type = data[4:8]
        if data_type == segment_type:
            index = hex(int(data[16:24], 16))
            file_str = "%s,%s,%s" % (MLX5DR_DEBUG_RES_TYPE_COUNTER, counter_index, index)
            packets = hex((int(data[32:40], 16) << 32) | int(data[40:48], 16))
            octets = hex((int(data[48:56], 16) << 32) | int(data[56:64], 16))
            file_str += ",%s" % packets
            file_str += ",%s" % octets
            file.write("%s\n" % file_str)
            if load_to_db:
                counters_dic[index] = {"packets": packets, "octets": octets}

        #16B(Args data) + 16(Prefix)
        data = bin_file.read(32)

    if load_to_db:
        _db._counters_db.update(counters_dic)

def dump_fw_ste_worker(req_q, resp_q, dev, dev_name):
    while True:
        try:
            fw_ste_index, tmp_file_path = req_q.get_nowait()
        except queue.Empty:
            return

        rd_segment_type = "FW_STE" if _config_args.get("legacy_rd") else "STE_INFO"
        all_or_active = "all" if _config_args.get("legacy_rd") else "active"
        resp = call_resource_dump(dev, dev_name, rd_segment_type, fw_ste_index, None,
                                  all_or_active, None, tmp_file_path)
        resp_q.put((fw_ste_index, tmp_file_path))

def dump_fw_ste(load_to_db, dev, dev_name, file, total_resources, load_bar_idx):
    tmp_file_path = _config_args.get("tmp_file_path")
    num_workers = _config_args.get("max_cores")
    resp_q = mp.Queue()
    req_q = mp.Queue()

    for fw_ste_index in _db._fw_ste_indexes_arr:
        _tmp_file_path = tmp_file_path.replace('.bin', f'_ste{fw_ste_index}.bin')
        Path(_tmp_file_path).touch()
        _config_args["tmp_file_arr"].append(_tmp_file_path)
        req_q.put((fw_ste_index, _tmp_file_path))

    # Init a differrent process to call resource dump for each FW STE in
    # parallel to parsing the output of the previous call.
    p = mp.Process(target=dump_fw_ste_worker, args=(req_q, resp_q, dev, dev_name))
    p.start()

    while p.is_alive() or not resp_q.empty():
        try:
            fw_ste_index, _tmp_file_path = resp_q.get(timeout=1)
        except Exception as e:
            continue
        parse_fw_ste_rd_bin_output(fw_ste_index, load_to_db, file, _tmp_file_path)

        if os.path.exists(_tmp_file_path):
            os.remove(_tmp_file_path)

        load_bar_idx += 1
        interactive_progress_bar(load_bar_idx, total_resources, DUMPING_HW_RESOURCES)

    p.join()

def dump_hw_resources(load_to_db, dev, dev_name, file):
    total_resources = _config_args.get("total_resources")
    dump_arg = _config_args.get("extra_hw_res_arg")
    dump_counter = _config_args.get("extra_hw_res_counter")
    interactive_progress_bar(0, total_resources, DUMPING_HW_RESOURCES)
    i = 0

    if _config_args.get("legacy_rd"):
        rd_segment_type = "STC"
    else:
        rd_segment_type = "STC_INFO"

    for stc_index in _db._stc_indexes_arr:
        output = call_resource_dump(dev, dev_name, rd_segment_type, stc_index, None, 'all', None)
        if _config_args.get("legacy_rd"):
            parse_fw_stc_rd_bin_output(stc_index, load_to_db, file)
        else:
            parse_stc_rd_bin_output(stc_index, load_to_db, file)
        i += 1

    # In this Phase we've the Args & Counters
    if dump_arg:
        total_resources += len(_db._arg_obj_indexes_dic)
    if dump_counter:
        total_resources += len(_db._flow_counter_indexes_dic)

    total_resources += len(_db._ft_idx_arr)

    _config_args["total_resources"] = total_resources
    interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)

    # Dump FT info
    for ft_id in _db._ft_idx_arr:
        query_and_parse_ft_meta_rd_bin_output(ft_id, load_to_db, dev, dev_name, file)
        i += 1
        interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)

    # Dump Arg's
    if dump_arg == True:
        if _config_args.get("legacy_rd"):
            segment_type = RESOURCE_DUMP_SEGMENT_TYPE_MODIFY_ARG_BIN
            rd_segment_type = "MODIFY_ARGUMENT"
        else:
            segment_type = RESOURCE_DUMP_SEGMENT_TYPE_MOD_ARG_BIN
            rd_segment_type = "HEADER_MOD_ARG"
        for arg_index in _db._arg_obj_indexes_dic:
            output = call_resource_dump(dev, dev_name, rd_segment_type, arg_index, None, 'all', None)
            parse_fw_modify_argument_rd_bin_output(arg_index,  load_to_db, file, segment_type)
            i += 1
            interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)

    # Dump Counters
    if dump_counter == True:
        if _config_args.get("legacy_rd"):
            segment_type = RESOURCE_DUMP_SEGMENT_TYPE_FLOW_COUNTER_BIN
            rd_segment_type = "FLOW_COUNTER"
        else:
            segment_type = RESOURCE_DUMP_SEGMENT_TYPE_FLOW_COUNT_BIN
            rd_segment_type = "FLOW_COUNT"
        for counter_idx in _db._flow_counter_indexes_dic:
            output = call_resource_dump(dev, dev_name, rd_segment_type, counter_idx, 'all', None, None)
            parse_fw_counter_rd_bin_output(counter_idx,  load_to_db, file, segment_type)
            i += 1
            interactive_progress_bar(i, total_resources, DUMPING_HW_RESOURCES)

    # Dump FW STE's
    if _config_args.get("resourcedump_mem_mode"):
        dump_fw_ste(load_to_db, dev, dev_name, file, total_resources, i)
    else:
        for fw_ste_index in _db._fw_ste_indexes_arr:
            output = call_resource_dump(dev, dev_name, "FW_STE", fw_ste_index, None, 'all', None)
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
