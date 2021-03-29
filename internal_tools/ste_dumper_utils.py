# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

import sys
import math
sys.path.insert(0,'..')
from src.parsers.dr_ste_parser import mlx5_hw_ste_parser

ste = mlx5_hw_ste_parser(int(sys.argv[1], 16), sys.argv[2], -1, 1, 0)

next_table_base_31_5_size = 0

if 'next_table_base_31_5_size' in ste:
    next_table_base_31_5_size = int(ste['next_table_base_31_5_size'], 16)

next_log_size = next_table_base_31_5_size & (~(next_table_base_31_5_size - 1)) #get first non zero bit

print('\n##############################################\n')
if 'entry_type' in ste:
    print('\tentry_type: ' + ste['entry_type'])

if 'next_table_base_39_32_size' in ste:
    print('\thit_address: ' + (hex(((int(ste['next_table_base_39_32_size'], 16) << 27) | (next_table_base_31_5_size & (~next_log_size))) >> 1)))

if 'miss_address_31_6' in ste and 'miss_address_39_32' in ste:
    print('\tmiss_address: ' + hex(int(ste['miss_address_31_6'], 16) + (int(ste['miss_address_39_32'], 16) << 26)))

if int(sys.argv[1], 16) == 0:
    print('\tentry_sub_type: ' + ste['entry_sub_type'])
    print('\tnext_lu_type: ' + ste['next_lu_type'])

if next_log_size > 0:
    print('\tnext_log_size: ' + hex(int(math.ceil(math.log(next_log_size, 2)))))
else:
    print('\tnext_log_size: size of the table is zero, bad param')

if 'gvmi' in ste:
    print('\tgvmi: ' + ste['gvmi'])

if 'next_table_base_63_48' in ste:
    print('\tnext_gvmi: ' + ste['next_table_base_63_48'])

if int(sys.argv[4], 16) == 1:
    print('\n\tverboose:')
    for k in ste:
        if (k != 'tag' and k != 'actions') and int(ste[k], 16) != 0:
            print('\t\t' + k + ': ' + str(ste[k]))
        if k == 'tag' or k == 'actions':
            print('\t\t' + k + ':')
            for l in ste[k]:
                print('\t\t\t' + l + ': ' + str(ste[k][l]))
print('\n##############################################\n')
