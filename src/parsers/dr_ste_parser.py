# Copyright (c) 2020 Mellanox Technologies, Inc.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from src.dr_constants import *
from src.parsers.dr_ste_v0_parser import mlx5_hw_ste_v0_parser
from src.parsers.dr_ste_v1_parser import mlx5_hw_ste_v1_parser
from src.dr_utilities import hex_2_bin


def mlx5_hw_ste_parser(nic_version, ste_hex_str, definer_id, raw, verbose):
    bin_str = hex_2_bin(ste_hex_str)
    if nic_version == MLX5_HW_CONNECTX_5:
        return mlx5_hw_ste_v0_parser(bin_str, raw)
    elif nic_version == MLX5_HW_CONNECTX_6DX:
        return mlx5_hw_ste_v1_parser(bin_str, definer_id, raw, verbose)
    else:
        print("Unsupported device, currently supporting CX5 and CX6DX")
