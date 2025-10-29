#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from src.dr_common import *
from src.dr_db import _db, _config_args

class dr_parse_table(Printable):
    def __init__(self, data):
        keys = ["mlx5dr_debug_res_type", "id", "ctx_id", "ft_id", "type",
                "fw_ft_type", "level", "local_ft_id", "rx_icm_addr",
                "tx_icm_addr", "local_rx_icm_addr", "local_tx_icm_addr",
                "miss_tbl", "ib_port", "vport", "other_vport"]
        self.data = dict(zip(keys, data + [None] * (len(keys) - len(data))))
        self.id = self.data.get("id")
        self.level = int(self.data.get("level"))
        self.fix_data()
        self.matchers = []
        self.col_matcher_ids = {}
        self.save_to_db()

    def __eq__(self, other):
        return self.level == other.level

    def __lt__(self, other):
        return self.level < other.level

    def dump_str(self, verbosity):
        _keys = ["mlx5dr_debug_res_type", "id", "type", "level"]
        if self.data.get("miss_tbl") != "0x0":
             _keys.extend(["miss_tbl"])

        if self.data.get("type") == DR_TBL_TYPE_RDMA_TRANSPORT_RX or \
           self.data.get("type") == DR_TBL_TYPE_RDMA_TRANSPORT_TX:
             _keys.extend(["ib_port"])

        if verbosity < 2:
            return dump_obj_str(_keys, self.data)

        if self.data.get("type") == DR_TBL_TYPE_RDMA_TRANSPORT_RX or \
           self.data.get("type") == DR_TBL_TYPE_RDMA_TRANSPORT_TX:
             _keys.extend(["vport", "other_vport"])

        if self.level ==  0:
            return dump_obj_str(_keys, self.data)

        if _config_args.get("shared_device") is not None:
            _keys.extend(["local_ft_id"])
            ft_idx = _db._ft_idx_dic.get(self.data.get("local_ft_id"))
            if ft_idx is not None:
                self.fix_address(ft_idx[0], ft_idx[1], True)

            if self.data.get("local_rx_icm_addr") != "0x0":
                _keys.extend(["local_rx_icm_addr"])
            if self.data.get("local_tx_icm_addr") != "0x0":
                _keys.extend(["local_tx_icm_addr"])

        _keys.extend(["ft_id"])
        ft_idx = _db._ft_idx_dic.get(self.data.get("ft_id"))
        if ft_idx is not None:
            self.fix_address(ft_idx[0], ft_idx[1])

        if self.data.get("rx_icm_addr") != "0x0":
            _keys.extend(["rx_icm_addr"])
        if self.data.get("tx_icm_addr") != "0x0":
            _keys.extend(["tx_icm_addr"])

        return dump_obj_str(_keys, self.data)

    def dump_obj(self, verbosity: int, transform_for_print: bool) -> dict:
        if not transform_for_print:
            return {
                "data": self.data,
                "matchers": [
                    m.dump_obj(verbosity, False)
                    for m in sorted(self.matchers)
                ]
            }

        matchers = []
        for m in sorted(self.matchers):
            if verbosity < 2 and m.data["id"] in self.col_matcher_ids:
                continue
            if not m:
                continue
            matchers.append(m)
            if verbosity < 2 and m.data["col_matcher_id"] != "0x0":
                self.col_matcher_ids[m.data["col_matcher_id"]] = ""

        return {
            self.dump_str(verbosity): [m.dump_obj(verbosity, True) for m in matchers]
        }

    def fix_data(self):
        rx_icm_addr = self.data.get("rx_icm_addr", "0x0")
        tx_icm_addr = self.data.get("tx_icm_addr", "0x0")
        local_rx_icm_addr = self.data.get("local_rx_icm_addr", "0x0")
        local_tx_icm_addr = self.data.get("local_tx_icm_addr", "0x0")

        self.data["type"] = dr_table_type[int(self.data["type"])]
        self.data["ft_id"] = hex(int(self.data.get("ft_id"))) if self.data.get("ft_id") is not None else "0x0"
        self.data["local_ft_id"] = hex(int(self.data.get("local_ft_id"))) if self.data.get("local_ft_id") is not None else "0x0"

        if self.level == 0:
            return

        if rx_icm_addr == "0x0" and self.data.get("ft_id") != "0x0":
            _db._ft_idx_arr.append(self.data.get("ft_id"))
        else:
            self.fix_address(rx_icm_addr, tx_icm_addr)

        if local_rx_icm_addr == "0x0" and self.data.get("local_ft_id") != "0x0":
            _db._ft_idx_arr.append(self.data.get("local_ft_id"))
        else:
            self.fix_address(local_rx_icm_addr, local_tx_icm_addr, True)


    def fix_address(self, rx_icm_addr, tx_icm_addr, local=False):
        _tbl_type = self.data.get("type")
        if _tbl_type == DR_TBL_TYPE_NIC_TX or\
           _tbl_type == DR_TBL_TYPE_RDMA_TRANSPORT_TX:
            tx_icm_addr = rx_icm_addr
            rx_icm_addr = "0x0"

        if _tbl_type == DR_TBL_TYPE_NIC_RX or\
           _tbl_type == DR_TBL_TYPE_RDMA_TRANSPORT_RX:
            tx_icm_addr = "0x0"

        if local == True:
            self.data["local_rx_icm_addr"] = rx_icm_addr
            self.data["local_tx_icm_addr"] = tx_icm_addr
        else:
            self.data["rx_icm_addr"] = rx_icm_addr
            self.data["tx_icm_addr"] = tx_icm_addr

    def add_matcher(self, matcher):
        self.matchers.append(matcher)

    def save_to_db(self):
        _db._tbl_type_db[self.id] = self.data.get("type")
        _db._tbl_level_db[self.id] = self.level
        if self.data.get("rx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("rx_icm_addr")] = {"type": "FT", "id": self.data.get("ft_id")}
        if self.data.get("tx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("tx_icm_addr")] = {"type": "FT", "id": self.data.get("ft_id")}
        if self.data.get("local_rx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("local_rx_icm_addr")] = {"type": "FT", "id": self.data.get("local_ft_id")}
        if self.data.get("local_tx_icm_addr") != "0x0":
            _db._term_dest_db[self.data.get("local_tx_icm_addr")] = {"type": "FT", "id": self.data.get("local_ft_id")}
