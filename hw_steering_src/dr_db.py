#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from hw_steering_src.dr_common import *


#Store config. args
_config_args = {}

#Store Definers
_definers = {}

#Store matchers
_matchers = []

#Store FT's indexes
_ft_indexes_arr = []

#Store FW STE's indexes
_fw_ste_indexes_arr = []

#This hash table holds the FW STE's, as obj index as the key,
#and the value a dictionary containing the STE's raw data, such as
#STE icm_addr is the key and STE raw data as the value.
_fw_ste_db = {}

#This hash table holds STE's, as keys are ICM addresses ranges,
#and values are FW STE index.
_stes_range_db = {}

#This hash table holds tables type, as keys are table id's, and
#values as table type
_tbl_type_db = {}
