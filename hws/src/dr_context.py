#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.


import sys
import subprocess as sp

from src.dr_common import *
from src.dr_db import _config_args, _ctx_db, _db


def get_mst_dev(dev_name):
    status, output = sp.getstatusoutput('mst status -v')
    if status != 0:
        print(output)
        print('MFT Error')
        exit()
    output_arr = output.split('\n')

    if dev_name.startswith("0000:") == True:
        dev_name = dev_name[5:]

    for l in output_arr:
        if dev_name in l:
            l_arr = l.split()
            if len(l_arr) > 1 and l_arr[1] != 'NA':
                return l_arr[1]

    return None

def get_mst_rdma_dev(dev_name):
    status, output = sp.getstatusoutput('mst status -v')
    if status != 0:
        print(output)
        print('MFT Error')
        exit()
    output_arr = output.split('\n')

    for l in output_arr:
        if dev_name in l:
            l_arr = l.split()
            if len(l_arr) < 3:
                continue
            if l_arr[1] == dev_name and l_arr[3] != 'NA':
                return l_arr[3]

    return None

class dr_parse_context():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "hws_support",
                "dev_name", "debug_version"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.fix_data()
        self.tables = []
        self.attr = None
        self.caps = None
        self.send_engine = []
        self.ctx_db = _ctx_db()
        self.load_to_db()

    def load_to_db(self):
        if _config_args.get("dump_hw_resources"):
            if _config_args.get("device") == None:
                _config_args["dev_name"] = self.data.get("dev_name");
                _config_args["device"] = get_mst_dev(self.data.get("dev_name"))
            else:
                _config_args["dev_name"] = get_mst_rdma_dev(_config_args.get("device"))
        else:
            _config_args["dev_name"] = self.data.get("dev_name");

        _db.load(self.ctx_db)

    def dump_str(self, verbosity):
        return dump_obj_str(["mlx5dr_debug_res_type", "id",
                             "hws_support", "dev_name", "debug_version"],
                             self.data)

    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        _str = _str + tabs + self.attr.dump_str(verbosity)

        if verbosity > 0:
            _str = _str + tabs + self.caps.dump_str(verbosity)

        if verbosity > 3:
            for se in self.send_engine:
                _str = _str + se.tree_print(verbosity, tabs)

        for t in sorted(self.tables):
            _str = _str + t.tree_print(verbosity, tabs)

        return _str

    def fix_data(self):
        self.data["hws_support"] = "True" if self.data["hws_support"] == "1" else "False"

    def add_table(self, table):
        self.tables.append(table)

    def add_attr(self, attr):
        self.attr = attr

    def add_caps(self, caps):
        self.caps = caps

    def add_send_engine(self, send_engine):
        self.send_engine.append(send_engine)


class dr_parse_context_attr():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "ctx_id",
                "pd_num", "queues", "queue_size", "shared_dev_name",
                "vhca_id", "shared_vhca_id"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        _config_args["vhca_id"] = self.data.get("vhca_id")
        shared_dev_name = None if self.data.get("shared_dev_name") == 'None' else self.data.get("shared_dev_name")
        if _config_args.get("dump_hw_resources") and shared_dev_name != None:
            _config_args["shared_dev_name"] = shared_dev_name
            _config_args["shared_device"] = get_mst_dev(shared_dev_name)
            _config_args["shared_vhca_id"] = self.data.get("shared_vhca_id")

    def dump_str(self, verbosity):
        arr = ["mlx5dr_debug_res_type", "ctx_id", "pd_num",
               "queues", "queue_size", "vhca_id"]

        if self.data.get("shared_dev_name") != 'None':
            arr.extend(["shared_dev_name", "shared_vhca_id"])

        return dump_obj_str(arr, self.data)


class dr_parse_context_caps():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "ctx_id", "fw_version",
                "wqe_based_update", "ste_format", "ste_alloc_log_max",
                "log_header_modify_argument_max_alloc", "flex_protocols",
                "rtc_reparse_mode", "rtc_index_mode", "ste_alloc_log_gran",
                "stc_alloc_log_max", "stc_alloc_log_gran",
                "rtc_log_depth_max", "flex_parser_id_gtpu_dw_0",
                "flex_parser_id_gtpu_teid", "flex_parser_id_gtpu_dw_2",
                "flex_parser_id_gtpu_first_ext_dw_0", "nic_ft_max_level",
                "nic_ft_reparse", "fdb_ft_max_level", "fdb_ft_reparse",
                "log_header_modify_argument_granularity",
                "linear_match_definer", "linear_match_definer_field_name"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

        _config_args["fw_version_major"] = int(self.data.get("fw_version").split(".")[0])
        _config_args["cx8"] = True if (_config_args.get("fw_version_major") >= FW_VERSION_MAJOR_CX8) else False

        if _config_args.get("extra_hw_res_pat") == True:
            expected_fw_version = "%s.%s" % (_config_args.get("fw_version_major"), FW_VERSION_MINOR_EXTRA_HW_RES)
            if self.data.get("fw_version") < expected_fw_version:
                print("To dump extra HW resources, please use FW version %s or higher" % expected_fw_version)
                sys.exit(0)

        _config_args["linear_match_definer"] = self.data.get("linear_match_definer")
        _config_args["linear_match_definer_field_name"] = self.data.get("linear_match_definer_field_name")
        if _config_args.get("linear_match_definer") != None:
            #Add to _definers DB as None so in STE parsing tag parsing will be skipped
            _db._definers[int(_config_args.get("linear_match_definer"))] = None

    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "ctx_id"]
        if verbosity > 0:
            _keys.extend(["fw_version", "wqe_based_update"])
        if verbosity > 2:
            _keys.extend(["ste_format", "ste_alloc_log_max",
                          "log_header_modify_argument_max_alloc",
                          "flex_protocols", "rtc_reparse_mode",
                          "rtc_index_mode", "ste_alloc_log_gran",
                          "stc_alloc_log_max", "stc_alloc_log_gran",
                          "rtc_log_depth_max", "flex_parser_id_gtpu_dw_0",
                          "flex_parser_id_gtpu_teid",
                          "flex_parser_id_gtpu_dw_2",
                          "flex_parser_id_gtpu_first_ext_dw_0",
                          "nic_ft_max_level", "nic_ft_reparse",
                          "fdb_ft_max_level", "fdb_ft_reparse",
                          "log_header_modify_argument_granularity",
                          "linear_match_definer",
                          "linear_match_definer_field_name"])

        return dump_obj_str(_keys, self.data)


class dr_parse_context_send_engine():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "ctx_id", "id", "used_entries",
                "th_entries", "rings", "num_entries", "err", "ci", "pi",
                "completed_mask"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.send_ring = []

    def dump_str(self, verbosity):
        return dump_obj_str(["mlx5dr_debug_res_type", "ctx_id", "id",
                             "used_entries", "th_entries", "rings",
                             "num_entries", "err", "ci", "pi"], self.data)

    def tree_print(self, verbosity, tabs):
        _str = tabs + self.dump_str(verbosity)
        tabs = tabs + TAB

        for sr in self.send_ring:
            _str = _str + tabs + sr.dump_str(verbosity)

        return _str

    def add_send_ring(self, send_ring):
        self.send_ring.append(send_ring)


class dr_parse_context_send_ring():
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "ctx_id", "id", "send_engine_index",
                "cqn", "cq_cons_index", "cq_ncqe_mask", "cq_buf_sz",
                "cq_ncqe", "cq_cqe_log_sz", "cq_poll_wqe", "cq_cqe_sz", "sqn",
                "sq_obj_id", "sq_cur_post", "sq_buf_mask"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))

    def dump_str(self, verbosity):
        return dump_obj_str(["mlx5dr_debug_res_type", "ctx_id", "id",
                             "send_engine_index", "cqn", "cq_cons_index",
                             "cq_ncqe_mask", "cq_buf_sz", "cq_ncqe",
                             "cq_cqe_log_sz", "cq_poll_wqe", "cq_cqe_sz",
                             "sqn", "sq_obj_id", "sq_cur_post",
                             "sq_buf_mask"], self.data)
