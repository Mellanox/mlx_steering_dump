#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

#Store config. args
_config_args = {}

class _ctx_db:
    def __init__(self):
        #Store Definers
        self._definers = {}
        #Store matchers
        self._matchers = {}
        #Store collision matchers ids
        self._col_matchers = []
        #Store FT's indexes
        self._ft_indexes_arr = []
        #Store FW STE's indexes
        self._fw_ste_indexes_arr = []
        #Store action STE indexes
        self._action_ste_indexes_arr = []
        #Store STC's indexes
        self._stc_indexes_arr = []
        #This hash table holds the FW STE's, as obj index as the key,
        #and the value a dictionary containing the STE's raw data, such as
        #STE icm_addr is the key and STE raw data as the value.
        self._fw_ste_db = {}
        #This hash table holds STE's, as keys are ICM addresses ranges,
        #and values are FW STE index.
        self._stes_range_db = {}
        #This hash table holds tables type, as keys are table id's, and
        #values as table type
        self._tbl_type_db = {}
        #This hash table holds tables level, as keys are table id's, and
        #values as table level
        self._tbl_level_db = {}
        #This hash table holds address as keys, and info structure about them
        self._term_dest_db = {}
        #This hash table holds indexes as keys, and info structure about them
        self._pattern_db = {}
        #This hash table holds indexes as keys, and info structure about them
        self._argument_db = {}
        #This hash table holds indexes as keys, and empty string as info,
        #since this dic is only needed for keys
        self._arg_obj_indexes_dic = {}
        #Hold total matcher match FW STE's to use for progress bar
        #We define it in an array of one index
        self._total_matcher_match_fw_stes = [0]
        #This hash table holds indexes as keys, and empty string as info,
        #since this dic is only needed for keys
        self._flow_counter_indexes_dic = {}
        #This hash table holds indexes as keys, and info structure about them
        self._counters_db = {}

    def load(self, _new):
        self._definers = _new._definers
        self._matchers = _new._matchers
        self._col_matchers = _new._col_matchers
        self._ft_indexes_arr = _new._ft_indexes_arr
        self._fw_ste_indexes_arr = _new._fw_ste_indexes_arr
        self._stc_indexes_arr = _new._stc_indexes_arr
        self._fw_ste_db = _new._fw_ste_db
        self._stes_range_db = _new._stes_range_db
        self._tbl_type_db = _new._tbl_type_db
        self._tbl_level_db = _new._tbl_level_db
        self._term_dest_db = _new._term_dest_db
        self._pattern_db = _new._pattern_db
        self._argument_db = _new._argument_db
        self._arg_obj_indexes_dic = _new._arg_obj_indexes_dic
        self._total_matcher_match_fw_stes = _new._total_matcher_match_fw_stes
        self._counters_db = _new._counters_db



_db = _ctx_db()
