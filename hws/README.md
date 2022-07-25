# mlx_hw_steering_parser.py
This is HW steering parser and triggering for dump files in **CSV format**.
This tool triggers the app to dump the app specific data, and also triggers
the HW to dump the app HW data.


How to trigger the HW steering dump
===================================
The dump can be triggered by calling the dump API directly via:
mlx5dr_debug_dump function.
Also it can be triggered for a DPDK app via:
python mlx_hw_steering_dump_parser.py -p <DPDK PID> -f <dump_file>


Running syntax
==============
./mlx_hw_steering_parser.py [-f FILE_PATH] [-v] [-hw] [-d DEVICE]
                            [-pid DPDK_PID] [-port DPDK_PORT] [-hw_parse]
                            [-h]

optional arguments:
  -f FILE_PATH     Input steering dump file path.
  -v               Increase output verbosity - v, vv, vvv & vvvv for extra
                   verbosity.
  -hw              Dump HW resources.
  -d DEVICE        Provide MST device, otherwise it will be guessed automatically.
  -pid DPDK_PID    Trigger DPDK app <PID>.
  -port DPDK_PORT  Trigger DPDK app <PORT> (must provide PID with -pid).
  -hw_parse        Parse HW dumped resources.
  -h, --help       it will show the help message and exit.


Required package
===================
For dumping the app HW resources:
 -Python3
 -Scapy
 -Cython
 -Pyverbs (Install RDMA-CORE after Cython)
 -MFT (Higher than 4.20.0-00)
