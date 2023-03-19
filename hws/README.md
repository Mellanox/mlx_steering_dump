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

    python mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file>

**Example:**

 - Trigger a dump to a new CSV file and skip HW dump:

        ./mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file> -skip_dump 

 - Parse an existing dump_file CSV:

        ./mlx_hw_steering_parser.py -f <dump_file> -skip_dump

 - Trigger a DPDK app to dump all the ports HWS app to a new CSV file and skip HW dump:

	./mlx_hw_steering_parser.py -pid <DPDK PID> -port -1 -f <dump_file> -skip_dump

 - Developer triggering and parsing a dump with HW resources from a DPDK app:
 
        ./mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file> -vvv
        ./mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file> -vvv -extra_hw_res pat,arg
   
 - Customer producing a full dump for developers to debug:
 
        ./mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file> -skip_parse

 - Customer producing a control dump for developers to debug:
 
        ./mlx_hw_steering_parser.py -pid <DPDK PID> -f <dump_file> -skip_dump
  
  
 ***Please see below "Running syntax" for more info.***
 
Running syntax
==============

    ./mlx_hw_steering_parser.py -f <FILE_PATH> [-v] [-skip_dump] [-d DEVICE]
                                [-pid DPDK_PID] [-port DPDK_PORT] [-skip_parse]
                                [-s] [-h]

***arguments:***
| Flag | Description |
|--|--|
| -f FILE_PATH | Input steering dump file path, also the output of the tool will be written to FILE_PATH.parsed |

***optional arguments:***
| Flag | Description |
|--|--|
| -v | Increase output verbosity - v, vv, vvv & vvvv for extra verbosity |
| -skip_dump | Skip HW resources dumping |
| -skip_parse | Skip HW dumped resources parsing |
| -d DEVICE | Provide MST device, otherwise it will be guessed automatically |
| -pid DPDK_PID | Trigger DPDK app <PID> |
| -port DPDK_PORT | Trigger DPDK app <PORT> (must provide PID with -pid) |
| -extra_hw_res [pat, arg] | Request extra HW resources to be dumped. For example: -extra_hw_res pat,arg |
| -s | Show dump statistics, such as STE's distribution |
| -h, --help | It will show the help message and exit |

Required package
===================
**For dumping the app HW resources:**
 - Python3
 - MFT (Version 4.22.0-80 provided with OFED 5.8 or higher)
