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
        ./mlx_hw_steering_parser.py -p <DPDK PID> -f <dump_file> -vvv -extra_hw_res pat,arg
   
 - Customer producing a dump for developers to debug:
 
        ./mlx_hw_steering_parser.py -p <DPDK PID> -f <dump_file> -skip_parse
  
 - For only parsing a dump CSV file:

        ./mlx_hw_steering_parser.py -f <dump_file> -skip_dump -v

 ***Please see below "Running syntax" for more info.***
 
Running syntax
==============

    ./mlx_hw_steering_parser.py [-f FILE_PATH] [-v] [-skip_dump] [-d DEVICE]
                                [-pid DPDK_PID] [-port DPDK_PORT] [-skip_parse]
                                [-h]

***optional arguments:***
| Flag | Description |
|--|--|
| -f FILE_PATH | Input steering dump file path |
| -v | Increase output verbosity - v, vv, vvv & vvvv for extra verbosity |
| -skip_dump | Skip HW resources dumping |
| -skip_parse | Skip HW dumped resources parsing |
| -d DEVICE | Provide MST device, otherwise it will be guessed automatically |
| -pid DPDK_PID | Trigger DPDK app <PID> |
| -port DPDK_PORT | Trigger DPDK app <PORT> (must provide PID with -pid) |
| -extra_hw_res [pat, arg] | Request extra HW resources to be dumped. For example: -extra_hw_res pat,arg |
| -h, --help | It will show the help message and exit |

Required package
===================
**For dumping the app HW resources:**
 - Python3
 - MFT (Version 4.22.0-80 provided with OFED 5.8 or higher)
