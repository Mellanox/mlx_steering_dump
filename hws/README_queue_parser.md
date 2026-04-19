# mlx_queue_steering_parser.py
> This is a Queue Steering parser tool for analyzing send queue dumps in **HW Steering** format.
> This tool allows you to dump and parse send queue entries from MLX devices,
> providing detailed analysis of WQE (Work Queue Entry) structures.
> The deails are from the HW-steering point of view and indicating the relevant steering information.
>

How to use the Queue Steering Parser
=====================================
The Queue Steering parser analyzes send queue entries from MLX devices, providing
detailed parsing of WQE structures including STC segments, actions, and control segments.

**Example Usage:**

 - Parse a steering dump file with basic output:

        ./mlx_queue_steering_parser.py -f <dump_file> -q <queue_id>

 - Parse with increased verbosity for detailed WQE analysis:

        ./mlx_queue_steering_parser.py -f <dump_file> -q <queue_id> -v

 - Dump and parse a specific send queue from a device:

        ./mlx_queue_steering_parser.py -f <dump_file> -q <queue_id> -d <device>

 - Dump a limited number of entries from a send queue:

        ./mlx_queue_steering_parser.py -f <dump_file> -q <queue_id> -d <device> --entry_num 10

 - Parse with maximum verbosity to see all STC and STE details:

        ./mlx_queue_steering_parser.py -f <dump_file> -q <queue_id> -vvvv

Running Syntax
==============

    ./mlx_queue_steering_parser.py -f <FILE_PATH> -q <QUEUE_ID> [-d DEVICE]
                                    [-v] [--entry_num ENTRY_NUM] [-h]

***Required Arguments:***
| Flag | Description |
|------|-------------|
| -f FILE_PATH | **MANDATORY** - Input steering dump file path. This is the file containing the queue dump data to be parsed. |
| -queue QUEUE_ID | **MANDATORY** - Send queue ID to dump/parse.<br>This identifies which queue to extract from the device or parse from the dump file. |

***Optional Arguments:***
| Flag | Description |
|------|-------------|
| -d DEVICE | MST device for HW resources dumping (e.g., `/dev/mst/mt4129_pciconf0`).<br>Can also specify a remote MST device if `--remote_ip` is used in conjunction.<br>If not provided, the tool will parse an existing dump file. |
| -v | Increase output verbosity level. Can be specified multiple times:<br>• `-v`: Basic verbosity - show action types and basic info<br>• `-vv`: Medium verbosity - show detailed segment parsing<br>• `-vvv`: High verbosity - show all field values<br>• `-vvvv`: Maximum verbosity - show raw data and full debug info |
| --entry_num ENTRY_NUM | Number of entries to dump from the send queue.<br>Use -1 to dump all entries (default: -1).<br>Useful for limiting output when debugging specific entries. |
| -h, --help | Show this help message and exit. |

Output Format
=============
The parser outputs detailed information about each WQE entry including:
- WQE control segments (GTA, ASO, etc.)
- STC (Steering Table Control) segments with action details
- STE (Steering Table Entry) segments with pattern/mask information
- Action types and parameters (COUNT, MODIFY_HEADER, FLOW_TAG, etc.)
- Detailed field-by-field breakdown when verbosity is increased

Example Output Structure:
```
WQE Pair #25: [0x0730] and [0x0731]
WQE Parser:verbose wqe parser: 0
0x0007302c 0x0011b108 0x00000020 0x00000002 ==> opcode: 0x2c (TBL_ACCESS),opmod: 0x00 (GTA_STE), cur_post: 0x730, imm: 0x2(RTC-ID)
0x00000000 0x6000000c 0x00000011 0x00000006 ==> op_mode: 0 (UPDATE), op_dirix: 0x00, ste_offset: 0x0, STCs: 3, 0xc(COUNT/0x8), 0x11(JUMP_TO_STE_TABLE/0x0), 0x6(TAG/0x4), 
0x0000000e 0x00000000 0x00000000 0x00000000 ==> 0xe(MODIFY_HEADER/0x4000), 
0x00000000 0x00000000 0x00000000 0x00000000 ==> gta-ctrl reseverd
0x00000008 0x00000000 0x00000000 0x00000000 ==> rsvd0_ctr_id, rsvd1_definer, reserved, reserved
0x00007000 0x00000004 0x00000000 0x00004000 ==> LSB hit offset, action_data1, action_data2, action_data3
0x00000000 0x00000000 0x00000000 0x05060708 ==> Match Tag
0x00000000 0x000000e0 0x00000000 0x00000000 ==> Match Tag

```

Segment Types Supported
=======================
The parser supports the following segment types:
- **0x3b (fw_stc_action)**: Firmware STC action segments
- **0x3c (ste_stc)**: STE STC segments with pattern and mask data
- **0x14 (rtc)**: RTC (Rule Table Context) segments
- **0x1036 (fw_ste)**: Firmware STE segments

Required Packages
=================
**For parsing queue dumps:**
 - Python 3.6 or higher
 - Standard Python libraries (no external dependencies for basic parsing)

**For dumping HW resources (when using -d option):**
 - MFT (Mellanox Firmware Tools) - Version 4.22.0-80 or higher
 - OFED 5.8 or higher for device access

Notes
=====
- The parser automatically detects and handles different WQE types
- Segment parsing is performed based on segment type identifiers
- The tool caches parsed STC data for improved performance with repeated segments
- Verbosity levels control the detail of output, with higher levels showing raw hex data

Troubleshooting
===============
If you encounter parsing errors:
1. Ensure the dump file is in the correct format
2. Try increasing verbosity (`-v`) to see detailed parsing information
3. Check that the device path is correct when using `-d` option
4. Verify that you have proper permissions to access the device

For support or bug reports, please contact the HW Steering team.
