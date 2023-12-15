#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_ste import *
from src.dr_visual import interactive_progress_bar


class dr_parse_rule():
    def __init__(self):
        self.rx_ste_arr = []
        self.tx_ste_arr = []


    def dump_str(self, verbosity):
        return 'Rule:\n'


    def add_ste(self, ste, rx_tx):
        if rx_tx == DR_TBL_TYPE_NIC_RX:
            self.rx_ste_arr.append(ste)
        else:
            self.tx_ste_arr.append(ste)


    def tree_print(self, verbosity, tabs, matcher):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        def tree_print_stes(stes, prefix, expected_miss_index):
            nonlocal _str
            last_i = len(stes) - 1
            for i, ste in enumerate(stes):
                is_last = i == last_i
                _str += ste.tree_print(verbosity, tabs, prefix, expected_miss_index, is_last)
        tree_print_stes(self.rx_ste_arr, 'RX STE ', matcher.data["rx_icm_addr"])
        tree_print_stes(self.tx_ste_arr, 'TX STE ', matcher.data["tx_icm_addr"])

        return _str


def dr_hw_get_ste_from_loc(loc):
    if loc.gvmi_str != _config_args.get("vhca_id"):
        return None

    addr = hex(loc.index)
    fw_ste_index = None
    for index in _db._stes_range_db:
        _range = _db._stes_range_db.get(index)
        if addr >= _range[0] and addr <= _range[1]:
            fw_ste_index = index
            break

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
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index()),
        ],
        DR_TBL_TYPE_NIC_TX: [
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_0_index()),
        ],
        DR_TBL_TYPE_FDB: [
            (DR_TBL_TYPE_NIC_RX, matcher.get_fw_ste_0_index()),
            (DR_TBL_TYPE_NIC_TX, matcher.get_fw_ste_1_index()),
        ],
    }
    tbl_type = _db._tbl_type_db.get(matcher.data.get("tbl_id"))
    dumps = tbl_type_to_dumps[tbl_type]

    for _tbl_type, match_ste_id in dumps:
        fw_ste_dic = _db._fw_ste_db[match_ste_id]
        for ste_addr in fw_ste_dic:
            ste = fw_ste_dic.get(ste_addr)
            rule = dr_parse_rule()
            while ste != None:
                rule.add_ste(ste, _tbl_type)
                hit_loc = ste.get_hit_location()
                ste = dr_hw_get_ste_from_loc(hit_loc)
            _str += rule.tree_print(verbosity, _tabs, matcher)

        progress_bar_i += 1
        interactive_progress_bar(progress_bar_i, progress_bar_total, PARSING_THE_RULES_STR)

    _config_args["progress_bar_i"] = progress_bar_i

    return _str
