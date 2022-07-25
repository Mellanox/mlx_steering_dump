# mlx_hw_steering_parser.py
> This is HW steering parser and triggering for dump files in **CSV
> format**.
> This tool triggers the app to dump the app specific data,
> and also triggers the HW to dump the app HW data.

How to trigger the HW steering dump
===================================
The dump can be triggered by calling the dump API directly via:
>  mlx5dr_debug_dump function

Also it can be triggered for a DPDK app via:

    python mlx_hw_steering_dump_parser.py -p <DPDK PID> -f <dump_file>

**Example:**

 - Triggering the Dump from a DPDK app, with dumping HW resources and
   parsing them. (For more data to show you need to pass more
   verbosity, for example for RAW STE you need pass -vvv):

		/mlx_hw_steering_dump_parser.py -p <DPDK PID> -f <dump_file> -v

 - Developer: May need more data to be shown, so increase verbosity,
                for example for RAW STE you need pass -vvv.

        /mlx_hw_steering_dump_parser.py -p <DPDK PID> -f <dump_file> -vvv

 - Customer: May not need to parse the data and just have raw data.
 
        /mlx_hw_steering_dump_parser.py -p <DPDK PID> -f <dump_file> -skip_parse

 - For only parsing a dump CSV file:

        ./mlx_hw_steering_dump_parser.py -f <dump_file> -skip_hw -v

 ***Please see below "Running syntax" for more info.***
 
Running syntax
==============

    ./mlx_hw_steering_parser.py [-f FILE_PATH] [-v] [-hw] [-d DEVICE]
                                [-pid DPDK_PID] [-port DPDK_PORT] [-hw_parse]
                                [-h]

***optional arguments:***
| Flag | Description |
|--|--|
| -f FILE_PATH | Input steering dump file path |
| -v | Increase output verbosity - v, vv, vvv & vvvv for extra verbosity |
| -skip_hw | Skip HW resources dumping |
| -skip_parse | Skip HW dumped resources parsing |
| -d DEVICE | Provide MST device, otherwise it will be guessed automatically |
| -pid DPDK_PID | Trigger DPDK app <PID> |
| -port DPDK_PORT | Trigger DPDK app <PORT> (must provide PID with -pid) |
| -h, --help | It will show the help message and exit |

Required package
===================
**For dumping the app HW resources:**
 - Python3
 - Scapy
 - Cython
 - Pyverbs (Install RDMA-CORE after Cython)
 - MFT (Version 4.21 or higher)
