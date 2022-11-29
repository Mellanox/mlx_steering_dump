#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _matchers, _fw_ste_db, _stes_range_db, _tbl_type_db
from src.dr_ste import *


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


    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        for ste in self.rx_ste_arr:
            _str += ste.tree_print(verbosity, tabs, 'RX STE ')
        for ste in self.tx_ste_arr:
            _str += ste.tree_print(verbosity, tabs, 'TX STE ')

        return _str


def dr_hw_get_ste_from_addr(addr):
    fw_ste_index = None
    for index in _stes_range_db:
        _range = _stes_range_db.get(index)
        if addr >= _range[0] and addr <= _range[1]:
            fw_ste_index = index
            break

    if fw_ste_index == None:
        return None

    fw_ste_stes = _fw_ste_db.get(fw_ste_index)
    return fw_ste_stes.get(addr)


def dr_parse_rules(matcher, verbosity, tabs):
    _str = ''
    _tabs = tabs + TAB
    tbl_type = _tbl_type_db.get(matcher.data.get("tbl_id"))
    _range = 2 if (tbl_type == DR_TBL_TYPE_FDB) else 1
    _tbl_type = tbl_type
    for i in range(_range):
        if i == 0:
            fw_ste_id = matcher.get_fw_ste_0_index()
            if tbl_type == DR_TBL_TYPE_FDB:
                _tbl_type = DR_TBL_TYPE_NIC_RX
        if (i == 1) and (tbl_type == "FDB"):
            fw_ste_id = matcher.get_fw_ste_1_index()
            _tbl_type = DR_TBL_TYPE_NIC_TX

        fw_ste_dic = _fw_ste_db[fw_ste_id]
        for ste_addr in fw_ste_dic:
            ste = fw_ste_dic.get(ste_addr)
            rule = dr_parse_rule()
            while ste != None:
                rule.add_ste(ste, _tbl_type)
                hit_addr = ste.get_hit_addr()
                ste = dr_hw_get_ste_from_addr(hit_addr)
            _str += rule.tree_print(verbosity, _tabs)

    return _str
