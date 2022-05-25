#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *
from hw_steering_src.dr_db import _matchers, _fw_ste_db, _stes_range_db, _tbl_type_db
from hw_steering_src.dr_ste import *


class dr_parse_rule():
    def __init__(self):
        self.ste_arr = []
        
    def dump_str(self, verbosity):
        return 'Rule:\n'

    def add_ste(self, ste):  
        self.ste_arr.append(ste)

    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        for ste in self.ste_arr:
            _str += ste.tree_print(verbosity, tabs)

        return _str


def dr_hw_get_ste_from_addr(addr):
    _addr = int(addr, 16)
    fw_ste_index = _stes_range_db.get(_addr)
    if fw_ste_index == None:
        return None

    fw_ste_stes = _fw_ste_db.get(fw_ste_index)
    return fw_ste_stes.get(addr)


def dr_parse_rules(matcher, verbosity, tabs):
    _str = ''
    prefix = ''
    _tabs = tabs + TAB
    tbl_type = _tbl_type_db.get(int(matcher.data.get("tbl_id"), 16))
    _range = 2 if (tbl_type == "FDB") else 1
    prefix = '' if (tbl_type == "FDB") else ('RX:\n' if (tbl_type == 'NIC_RX') else 'TX:\n')
    for i in range(_range):
        if i == 0:
            fw_ste_id = matcher.get_fw_ste_0_index()
            if tbl_type == "FDB":
                prefix = 'RX:\n'
        if (i == 1) and (tbl_type == "FDB"):
            fw_ste_id = matcher.get_fw_ste_1_index()
            prefix = 'TX:\n'

        _str += tabs + prefix
        fw_ste_dic = _fw_ste_db[fw_ste_id]
        for ste_addr in fw_ste_dic:
            #raw_ste = fw_ste_dic.get(ste_addr)
            ste = fw_ste_dic.get(ste_addr)
            rule = dr_parse_rule()
            while ste != None:
                #ste = dr_parse_ste(ste_addr, fw_ste_id, raw_ste)
                rule.add_ste(ste)
                hit_addr = ste.get_hit_addr()
                #raw_ste = dr_hw_get_ste_from_addr(hit_addr)
                ste = dr_hw_get_ste_from_addr(hit_addr)
            _str += rule.tree_print(verbosity, _tabs)

    return _str
