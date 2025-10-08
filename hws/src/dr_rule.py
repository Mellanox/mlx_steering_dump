#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_ste import *
from src.dr_visual import interactive_progress_bar


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
        stes = self.ste_arr
        last_i = len(stes) - 1
        for i, ste in enumerate(stes):
            is_last = i == last_i
            _str += ste.tree_print(verbosity, tabs, self.prefix, is_last)

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
        if fw_ste_dic == None:
            continue

        for ste_addr in fw_ste_dic:
            ste = fw_ste_dic.get(ste_addr)
            if ste.get_entry_format() == STE_ENTRY_TYPE_RANGE_MATCH or \
                ste.get_entry_format() == STE_ENTRY_TYPE_4DW_RANGE_MATCH:
                    continue
            rule = dr_parse_rule(_tbl_type)
            while ste != None:
                rule.add_ste(ste)
                hit_loc = ste.get_hit_location()
                ste = dr_hw_get_ste_from_loc(hit_loc, hint_loc + _db._action_ste_indexes_arr, False, match_ste_id)
            _str += rule.tree_print(verbosity, _tabs, matcher)

        progress_bar_i += 1
        interactive_progress_bar(progress_bar_i, progress_bar_total, PARSING_THE_RULES_STR)

    _config_args["progress_bar_i"] = progress_bar_i

    return _str
