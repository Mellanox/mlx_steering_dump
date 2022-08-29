# mlx_hw_steering_parser.py
> This is HW steering parser and triggering for dump files in **CSV
> format**. 
> This tool triggers the app to dump the app specific data,
> and also triggers the HW to dump the app HW data.
> 
How to trigger the HW steering dump
===================================
The dump can be triggered by calling the dump API directly via:
>  mlx5dr_debug_dump function

Also it can be triggered for a DPDK app via:

    python mlx_hw_steering_parser.py -p <DPDK PID> -f <dump_file>

**Example:**
 - Developer triggering and parsing a dump with HW resources from a DPDK app:
 
        ./mlx_hw_steering_parser.py -p <DPDK PID> -f <dump_file> -vvv
   
 - Customer producing a dump for developers to debug:
 
        ./mlx_hw_steering_parser.py -p <DPDK PID> -f <dump_file> -skip_parse
  
 - For only parsing a dump CSV file:

        ./mlx_hw_steering_parser.py -f <dump_file> -skip_hw -v

 ***Please see below "Running syntax" for more info.***
 
Running syntax
==============

    ./mlx_hw_steering_parser.py [-f FILE_PATH] [-v] [-skip_hw] [-d DEVICE]
                                [-pid DPDK_PID] [-port DPDK_PORT] [-skip_parse]
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
 - Pyverbs (Install RDMA-CORE after Cython, planned to be removed in August release)
 - MFT (Version 4.21 or higher)
