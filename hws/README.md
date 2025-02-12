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

Also it can be triggered for a DPDK/DOCA app via:

    python mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file>

**Example:**

 - Trigger a dump to a new CSV file and skip HW dump:

        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> --skip_dump

 - Parse an existing dump_file CSV:

        ./mlx_hw_steering_parser.py -f <dump_file> --skip_dump

 - Trigger a DPDK/DOCA app to dump all the ports HWS app to a new CSV file and skip HW dump:

	./mlx_hw_steering_parser.py --pid <APP PID> --port -1 -f <dump_file> --skip_dump

 - Developer triggering and parsing a dump with HW resources from a DPDK/DOCA app:

        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> -vvv
        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> -vvv --extra_hw_res pat,arg

 - Customer producing a full dump for developers to debug:

        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> --skip_parse

 - Customer producing a control dump for developers to debug:

        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> --skip_dump

 - Developer triggering and parsing a dump with HW resources on remote setup from a DPDK/DOCA app:

        ./mlx_hw_steering_parser.py --pid <APP PID> -f <dump_file> --remote_ip <REMOTE IP> --user_name <USER NAME>


 ***Please see below "Running syntax" for more info.***

Running syntax
==============

    ./mlx_hw_steering_parser.py -f <FILE_PATH> [-v] [--skip_dump] [-d DEVICE]
                                [--pid APP_PID] [--port APP_PORT] [--skip_parse]
                                [--extra_hw_res [pat, arg, all]] [-s] [-h]

***arguments:***
| Flag | Description |
|--|--|
| -f FILE_PATH | Input steering dump file path, also the output of the tool will be written to FILE_PATH.parsed |

***optional arguments:***
| Flag | Description |
|--|--|
| -v | Increase output verbosity - v, vv, vvv & vvvv for extra verbosity |
| --skip_dump | Skip HW resources dumping |
| --skip_parse | Skip HW dumped resources parsing |
| -d DEVICE | Provide MST device, otherwise it will be guessed automatically |
| --pid APP_PID | Trigger DPDK/DOCA app <PID> |
| --port APP_PORT | Trigger DPDK/DOCA app <PORT> (must provide PID with -pid) |
| --extra_hw_res [pat, arg, all] | Request extra HW resources to be dumped. For example: -extra_hw_res pat,arg |
| -s | Show dump statistics, such as STE's distribution |
| --remote_ip REMOTE_IP | Indicates to extract HW resources from the remote setup <IP> |
| --user_name USER_NAME | Indicates the user name on the remote setup |
| -h, --help | It will show the help message and exit |

Required package
===================
**For dumping the app HW resources:**
 - Python3
 - MFT (Version 4.22.0-80 provided with OFED 5.8 or higher)
 - Pexpect (Only needed when using --remote_ip option)
