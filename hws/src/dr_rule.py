#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_ste import *
from src.dr_visual import interactive_progress_bar

import multiprocessing as mp
import queue
import gc


SLICE_SIZE = 64 * 1024


class dr_parse_rule():
    def __init__(self, tbl_type):
        self.ste_arr = []
        self.prefix = ''
        self.tbl_type = tbl_type
        self.fix_data(tbl_type)


    def fix_data(self, tbl_type):
        if tbl_type == DR_TBL_TYPE_NIC_RX:
            self.prefix = 'RX STE '
        elif tbl_type == DR_TBL_TYPE_NIC_TX:
            self.prefix = 'TX STE '
        else:
            self.prefix = 'STE '


    def dump_str(self, verbosity):
        return 'Rule:\n'


    def add_ste(self, ste):
        self.ste_arr.append(ste)


    def tree_print(self, verbosity, tabs, matcher):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        def tree_print_stes(stes, prefix):
            nonlocal _str
            last_i = len(stes) - 1
            for i, ste in enumerate(stes):
                is_last = i == last_i
                _str += ste.tree_print(verbosity, tabs, prefix, is_last)

        tree_print_stes(self.ste_arr, self.prefix)

        return _str


def dr_hw_get_ste_from_loc(loc, hint_loc=[], ignore_hint=False, curr_matcher_idx=None):
    if loc.gvmi_str != _config_args.get("vhca_id"):
        return None

    if ignore_hint:
        hint_loc = _db._stes_range_db

    addr = hex(loc.index)
    fw_ste_index = None
    for index in hint_loc:
        if index == None:
            continue
        _range = _db._stes_range_db.get(index)
        if addr >= _range[0] and addr <= _range[1]:
            fw_ste_index = index
            break

    matcher_range = _db._stes_range_db.get(curr_matcher_idx)
    if curr_matcher_idx:
        if matcher_range[0] <= addr <= matcher_range[1]:
            fw_ste_index = curr_matcher_idx

    if fw_ste_index == None:
        return None

    fw_ste_stes = _db._fw_ste_db.get(fw_ste_index)
    return fw_ste_stes.get(addr)


def dr_parse_stes(fw_ste_dic, tbl_type, match_ste_id, hint_loc, verbosity,
                  tabs, matcher):
    _str = ''
    for ste_addr, ste in fw_ste_dic.items():
        if ste.get_entry_format() == STE_ENTRY_TYPE_RANGE_MATCH or \
            ste.get_entry_format() == STE_ENTRY_TYPE_4DW_RANGE_MATCH:
                continue
        rule = dr_parse_rule(tbl_type)
        while ste != None:
            rule.add_ste(ste)
            hit_loc = ste.get_hit_location()
            ste = dr_hw_get_ste_from_loc(hit_loc, hint_loc + _db._action_ste_indexes_arr, False, match_ste_id)
        _str += rule.tree_print(verbosity, tabs, matcher)
    return _str


def worker_process(idx, ste_slices, tbl_type, match_ste_id, hint_loc, verbosity,
                   tabs, matcher, req_q, resp_q):
    while True:
        try:
            # The control process posts all of the work items before starting
            # the workers, and no other items are posted after that. So we don't
            # need to block.
            slice_idx = req_q.get_nowait()
        except queue.Empty:
            # No more work, we're done.
            return
        _str = dr_parse_stes(ste_slices[slice_idx], tbl_type, match_ste_id, hint_loc, verbosity,
                             tabs, matcher)
        resp_q.put((slice_idx, _str))


def split_dict(dic, slice_size):
    slices = []
    for i, (key, val) in enumerate(sorted(dic.items())):
        if i % slice_size == 0:
            slices.append({})
        slices[-1][key] = val
    return slices


def dr_parse_rules(matcher, verbosity, tabs):
    _str = ''
    _tabs = tabs + TAB
    progress_bar_i = _config_args.get("progress_bar_i")
    progress_bar_total = _db._total_matcher_match_fw_stes[0]
    if progress_bar_i == 0:
        interactive_progress_bar(progress_bar_i, progress_bar_total, PARSING_THE_RULES_STR)

    tbl_type_to_dumps = {
        DR_TBL_TYPE_NIC_RX: [
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
        ],
        DR_TBL_TYPE_NIC_TX: [
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
        ],
        DR_TBL_TYPE_FDB: [
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_1_index(), matcher.get_ste_arrays(ste_0=False)),
        ],
        DR_TBL_TYPE_FDB_RX: [
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_1_index(), matcher.get_ste_arrays(ste_0=False)),
        ],
        DR_TBL_TYPE_FDB_TX: [
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_1_index(), matcher.get_ste_arrays(ste_0=False)),
        ],
        DR_TBL_TYPE_FDB_UNIFIED: [
            (DR_TBL_TYPE_FDB_UNIFIED, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
        ],
        DR_TBL_TYPE_RDMA_TRANSPORT_RX: [
            (DR_TBL_TYPE_RDMA_TRANSPORT_RX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
        ],
        DR_TBL_TYPE_RDMA_TRANSPORT_TX: [
            (DR_TBL_TYPE_RDMA_TRANSPORT_TX, matcher.get_fw_ste_0_index(), matcher.get_ste_arrays(ste_1=False)),
        ],
    }
    tbl_type = _db._tbl_type_db.get(matcher.data.get("tbl_id"))
    dumps = tbl_type_to_dumps[tbl_type]

    for _tbl_type, match_ste_id, hint_loc in dumps:
        fw_ste_dic = _db._fw_ste_db.get(match_ste_id)
        if not fw_ste_dic:
            continue

        num_workers = _config_args["max_cores"]
        if num_workers == 0:
            num_workers = mp.cpu_count()

        fw_ste_slices = split_dict(fw_ste_dic, SLICE_SIZE)
        req_q = mp.Queue()
        resp_q = mp.Queue()
        # The STE dictioary can be quite huge and we don't want to send slices
        # of it through a request queue because that would involve pickling
        # them. Instead, we rely on the fact that workers are spawned using
        # 'fork' so they have access to all of the data on the main process, and
        # only post work in the form of slice indices.
        #
        # We are, however, not as fortunate when it comes to receiving data. The
        # STE slices are parsed into large strings which must be sent over the
        # queue. If these cause the machine to OOM, one easy future improvement
        # is to write the results of individual slices to files and then
        # concatenate them to the main file in the master process, but these
        # extra disk accesses would slow us down.
        for i in range(len(fw_ste_slices)):
            req_q.put(i)

        # Disable the garbage collector before starting new processes.
        # Otherwise, the periodic garbage collection in each individual process
        # causes a storm of CoW faults and dramatically increases memory usage.
        # The workers are short lived anyway, and we re-enable garbage
        # collection after they are done.
        gc.disable()
        processes = []
        results = {}

        for i in range(num_workers):
            p = mp.Process(target=worker_process,
                           args=(i, fw_ste_slices, _tbl_type, match_ste_id,
                                 hint_loc, verbosity, _tabs, matcher,
                                 req_q, resp_q))
            processes.append(p)

        [p.start() for p in processes]

        while len(results) < len(fw_ste_slices):
            slice_idx, result = resp_q.get()
            results[slice_idx] = result

        [p.join() for p in processes]
        gc.enable()

        for _, s in sorted(results.items()):
            _str += s

        progress_bar_i += 1
        interactive_progress_bar(progress_bar_i, progress_bar_total, PARSING_THE_RULES_STR)

    _config_args["progress_bar_i"] = progress_bar_i

    return _str
