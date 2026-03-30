#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2026 NVIDIA CORPORATION. All rights reserved.

from abc import ABC, abstractmethod
from typing import NamedTuple, List, Union, Tuple
from typing import Dict, Any, Optional

import struct
import subprocess
import os
import traceback
import sys

from src.dr_common import *
from src.dr_db import _config_args, _db
from src.dr_wqe_factory import WQEParserFactory, get_wqe_parser_factory
from src.dr_stc_parse import SegmentBufferParser


def red(text):
    #return f"\033[91m{text}\033[0m"
    return f"**{text}** "

def bold_red(text):
    return f"\033[1m\033[91m{text}\033[0m"

SEND_WQE_GTA_OP_ACTIVATE = 0
SEND_WQE_GTA_OP_DEACTIVATE = 1

def get_stc_real_data_action_location(action_type: int, action_dw_location: int) -> int:
    stc_info = stc_action_type_info[action_type]
    if stc_info[1] == 1:
        return action_dw_location

    if (action_type == DR_ACTION_INSERT_POINTER or
        action_type == DR_ACTION_ACCELERATED_MODIFY_LIST):
        return action_dw_location + 1

    return action_dw_location

class WQEGtaFlowUpdateParsedData(NamedTuple):
    """Structure to hold parsed WQE data from 128 bytes (32 dwords)"""
    ctrl1: List[int]        # 4 dwords
    op_directx: int         # 1 dword
    stc_array: List[int]    # 5 dwords
    reserved1: List[int]    # 6 dwords
    ctr_id: int            # 1 dword
    definer: int           # 1 dword
    rsvd2: List[int]       # 3 dwords
    action_data: List[int]  # 3 dwords
    tag: List[int]         # 8 dwords

class WQEGneralCtrlSeg(NamedTuple):
    """Structure to hold parsed General Control Segment data"""
    opcode: int            # 8 bits
    opmod: int             # 8 bits
    cur_post: int          # 16 bits
    flags: int             # 32 bits
    imm: int               # 32 bits
    qpn_ds: int            # 32 bits

class DumpLines:
    """Structure to hold a list of lines for dumping output"""

    def __init__(self, lines: List[str] = None):
        """Initialize with optional list of lines"""
        self.lines: List[str] = lines if lines is not None else []

    def to_string(self) -> str:
        """Join all lines into a single string"""
        return '\n'.join(self.lines)

    def add_line(self, line: str):
        """Add a line to the collection"""
        self.lines.append(line)

    def add_lines(self, lines: List[str]):
        """Add multiple lines to the collection"""
        self.lines.extend(lines)

    def __str__(self) -> str:
        """String representation - same as to_string()"""
        return self.to_string()

    def __len__(self) -> int:
        """Return number of lines"""
        return len(self.lines)

    def clear(self):
        """Clear all lines"""
        self.lines.clear()

    def append_to_line(self, line_index: int, text: str):
        """Append text to the end of a specific line

        Args:
            line_index: Index of the line to append to (0-based)
            text: Text to append to the line
        """
        if 0 <= line_index < len(self.lines):
            self.lines[line_index] += text
        else:
            raise IndexError(f"Line index {line_index} out of range. Total lines: {len(self.lines)}")

    def prepend_to_line(self, line_index: int, text: str):
        """Prepend text to the beginning of a specific line

        Args:
            line_index: Index of the line to prepend to (0-based)
            text: Text to prepend to the line
        """
        if 0 <= line_index < len(self.lines):
            self.lines[line_index] = text + self.lines[line_index]
        else:
            raise IndexError(f"Line index {line_index} out of range. Total lines: {len(self.lines)}")

    def insert_line_at(self, line_index: int, text: str):
        """Insert a new line at a specific index

        Args:
            line_index: Index where to insert the new line (0-based)
            text: Text of the new line to insert
        """
        if 0 <= line_index <= len(self.lines):
            self.lines.insert(line_index, text)
        else:
            raise IndexError(f"Line index {line_index} out of range. Valid range: 0-{len(self.lines)}")

    def get_line(self, line_index: int) -> str:
        """Get a specific line by index

        Args:
            line_index: Index of the line to get (0-based)

        Returns:
            The line at the specified index
        """
        if 0 <= line_index < len(self.lines):
            return self.lines[line_index]
        else:
            raise IndexError(f"Line index {line_index} out of range. Total lines: {len(self.lines)}")

class dr_action_verify(ABC):
    """Abstract base class for action verification"""
    @abstractmethod
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Abstract method to verify action"""
        pass

    @staticmethod
    def verify(action_type: int, action_info: List[int],
               dump_lines: DumpLines, line_index: int) -> bool:
        """Verify current action offset location is in the allowed list per action type"""

        if not dr_action_verify.verify_action_offset_location(action_type, action_info[0]):
            error_msg = (f"Action offset {action_info[0]} is out of range for action type {stc_action_type_info[action_type][1]}")
            dump_lines.append_to_line(line_index, red(error_msg + ", "))
            return False

        verifier = dr_action_verify.get_verifier(action_type)
        if verifier != None:
            return verifier.verify_action(action_info, dump_lines, line_index)

        return False

    @staticmethod
    def get_verifier(action_type: int) -> "dr_action_verify":
        if action_type == DR_ACTION_NOPE:
            return dr_action_verify_nope()
        elif action_type == DR_ACTION_COPY:
            return dr_action_verify_copy()
        elif action_type == DR_ACTION_SET:
            return dr_action_verify_set()
        elif action_type == DR_ACTION_ADD:
            return dr_action_verify_add()
        elif action_type == DR_ACTION_REMOVE_BY_SIZE:
            return dr_action_verify_remove_by_size()
        elif action_type == DR_ACTION_REMOVE_HEADER2HEADER:
            return dr_action_verify_remove_header2header()
        elif action_type == DR_ACTION_INSERT_INLINE:
            return dr_action_verify_insert_inline()
        elif action_type == DR_ACTION_INSERT_POINTER:
            return dr_action_verify_insert_pointer()
        elif action_type == DR_ACTION_ACCELERATED_MODIFY_LIST:
            return dr_action_verify_insert_pointer()
        elif action_type == DR_ACTION_COUNTER:
            return dr_action_verify_counter()
        elif action_type == DR_ACTION_FLOW_TAG:
            return dr_action_verify_flow_tag()
        elif action_type == DR_ACTION_ASO:
            return dr_action_verify_aso()
        elif action_type == DR_ACTION_IPSEC_ENC:
            return dr_action_verify_ipsec_enc()
        elif action_type == DR_ACTION_IPSEC_DEC:
            return dr_action_verify_ipsec_dec()
        elif action_type == DR_ACTION_PSP_ENC:
            return dr_action_verify_psp_enc()
        elif action_type == DR_ACTION_PSP_DEC:
            return dr_action_verify_psp_dec()
        elif action_type == DR_ACTION_TRAILER:
            return dr_action_verify_trailer()
        elif action_type == DR_ACTION_ADD_FIELD:
            return dr_action_verify_add_field()
        elif action_type == DR_ACTION_JUMP_TO_STE_TABLE:
            return dr_action_verify_jump_to_ste_table()
        elif action_type == DR_ACTION_JUMP_TO_TIR:
            return dr_action_verify_jump_to_tir()
        elif action_type == DR_ACTION_JUMP_TO_FLOW_TABLE:
            return dr_action_verify_jump_to_flow_table()
        elif action_type == DR_ACTION_JUMP_TO_DROP:
            return dr_action_verify_jump_to_drop()
        elif action_type == DR_ACTION_JUMP_TO_ALLOW:
            return dr_action_verify_jump_to_allow()
        elif action_type == DR_ACTION_JUMP_TO_VPORT:
            return dr_action_verify_jump_to_vport()
        else:
            return None

    @staticmethod
    def verify_action_offset_location(action_type: int, action_offset: int) -> bool:
        """Verify current action offset location is in the allowed list per action type"""
        action_info = stc_action_type_info[action_type]
        for offset in action_info[3]:
            if action_offset == offset:
                return True
        return False
class dr_action_verify_nope(dr_action_verify):
    """Verify NOPE action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify NOPE action"""
        return True
class dr_action_verify_copy(dr_action_verify):
    """Verify COPY action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify COPY action"""
        return True
class dr_action_verify_set(dr_action_verify):
    """Verify SET action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify SET action"""
        return True
class dr_action_verify_add(dr_action_verify):
    """Verify ADD action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify ADD action"""
        return True
class dr_action_verify_remove_by_size(dr_action_verify):
    """Verify REMOVE_BY_SIZE action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify REMOVE_BY_SIZE action"""
        return True
class dr_action_verify_remove_header2header(dr_action_verify):
    """Verify REMOVE_HEADER2HEADER action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify REMOVE_HEADER2HEADER action"""
        return True
class dr_action_verify_insert_inline(dr_action_verify):
    """Verify INSERT_INLINE action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify INSERT_INLINE action"""
        return True
class dr_action_verify_insert_pointer(dr_action_verify):
    """Verify INSERT_POINTER / MODIFY Header action"""
    def verify_action(self, action_info: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify INSERT_POINTER / MODIFY Header action"""
        action_data = action_info[1]

        # Check if any bits are set outside the 24-bit mask (0x00ffffff)
        if action_data[action_info[0]] & ~action_info[2]:
            dump_lines.append_to_line(line_index,
                                      red(f"\naction data (0x{action_data[action_info[0]]:x}) not masked by 0x{action_info[2]:x} "))
            return False

        return True

class dr_action_verify_counter(dr_action_verify):
    """Verify COUNTER action"""
    def verify_action(self, action_info: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify COUNTER action"""
        action_data = action_info[1]
        stc_allowed_bits = action_info[2]
        # Check if any bits are set outside the 24-bit mask (0x00ffffff)
        if action_data[action_info[0]] & ~stc_allowed_bits:
            error_msg = (f"Counter value (0x{action_data[action_info[0]]:x}) "
                        f"should be masked by 0x{stc_allowed_bits:x}")
            dump_lines.append_to_line(line_index, red(error_msg + ", "))
            return False

        return True
class dr_action_verify_flow_tag(dr_action_verify):
    """Verify FLOW_TAG action"""
    def verify_action(self, action_info: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify FLOW_TAG action"""
        action_data = action_info[1]
        stc_info = stc_action_type_info[DR_ACTION_FLOW_TAG]
        # Check if any bits are set outside the 24-bit mask (0x00ffffff)
        if action_data[action_info[0]] & ~stc_info[2][0]:
            error_msg = (f"Flow tag value (0x{action_data[action_info[0]]:x}) "
                        f"should be masked by 0x{stc_info[2][0]:x}")
            dump_lines.append_to_line(line_index, red(error_msg + ", "))
            return False

        return True
class dr_action_verify_aso(dr_action_verify):
    """Verify ASO action"""
    def verify_action(self, action_info: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify ASO action"""
        action_data = action_info[1]
        stc_allowed_bits = action_info[2]
        # Check if any bits are set outside the 24-bit mask (0x00ffffff)
        if action_data[action_info[0]] & ~stc_allowed_bits:
            error_msg = (f"ASO value (0x{action_data[action_info[0]]:x}) "
                        f"should be masked by 0x{stc_allowed_bits:x}")
            dump_lines.append_to_line(line_index, red(error_msg + ", "))

        return True
class dr_action_verify_add_field(dr_action_verify):
    """Verify ADD_FIELD action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify ADD_FIELD action"""
        return True
class dr_action_verify_jump_to_ste_table(dr_action_verify):
    """Verify JUMP_TO_STE_TABLE action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_STE_TABLE action"""
        return True
class dr_action_verify_jump_to_tir(dr_action_verify):
    """Verify JUMP_TO_TIR action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_TIR action"""
        return True
class dr_action_verify_jump_to_flow_table(dr_action_verify):
    """Verify JUMP_TO_FLOW_TABLE action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_FLOW_TABLE action"""
        return True
class dr_action_verify_jump_to_drop(dr_action_verify):
    """Verify JUMP_TO_DROP action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_DROP action"""
        return True
class dr_action_verify_jump_to_allow(dr_action_verify):
    """Verify JUMP_TO_ALLOW action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_ALLOW action"""
        return True
class dr_action_verify_jump_to_vport(dr_action_verify):
    """Verify JUMP_TO_VPORT action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify JUMP_TO_VPORT action"""
        return True

class dr_action_verify_ipsec_enc(dr_action_verify):
    """Verify IPSEC_ENC action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify IPSEC_ENC action"""
        return True

class dr_action_verify_ipsec_dec(dr_action_verify):
    """Verify IPSEC_DEC action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify IPSEC_DEC action"""
        return True

class dr_action_verify_psp_enc(dr_action_verify):
    """Verify PSP_ENC action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify PSP_ENC action"""
        return True

class dr_action_verify_psp_dec(dr_action_verify):
    """Verify PSP_DEC action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify PSP_DEC action"""
        return True

class dr_action_verify_trailer(dr_action_verify):
    """Verify TRAILER action"""
    def verify_action(self, action_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify TRAILER action"""
        return True

class dr_wqe(ABC):
    """Abstract base class for WQE parsing"""

    def __init__(self, data, gen_ctrl_seg, verbosity=0):
        self.data = data
        self.wqe_parsed_data = None
        self.type = "ABCDR_WQE"
        self.gen_ctrl_seg = gen_ctrl_seg
        self.verbosity = verbosity

    @abstractmethod
    def dump_str(self, verbosity, data=None):
        """Abstract method to dump WQE data as string"""
        pass

    @abstractmethod
    def parse_wqe_data(self, dump_lines: DumpLines):
        """Abstract method to parse WQE data"""
        pass

    def parse_hex_string_to_bytes(hex_string: str, big_endian: bool = False) -> bytes:
        """
        Convert a space-separated hex string to bytes.

        Args:
            hex_string: String like "00000008 00000000 ..."
            big_endian: If True, interpret hex values as big-endian

        Returns:
            bytes: Binary data
        """
        hex_values = hex_string.split()

        # Convert each hex value to bytes
        byte_data = b''
        for hex_val in hex_values:
            # Convert to int and then to 4 bytes
            val = int(hex_val, 16)
            byte_data += val.to_bytes(4, byteorder='big' if big_endian else 'little')

        return byte_data

    def dump_wqe_general_ctrl_seg(self, dump_lines: DumpLines):
        # Create dictionaries mapping values to macro names (last two words)
        opcode_names = {
            0x2c: "TBL_ACCESS",
            0x2d: "ACCESS_ASO"
        }

        opmod_names = {
            0: "GTA_STE",
            1: "GTA_MOD_ARG",
            0xf: "COUNTER",
            2: "METER",
            4: "FLOW HIT",
            7: "ENTROPY",
            8: "BUFFER-MGMT",
            9: "MEMORY",
        }

        imm_names = {
            0: "RTC-ID",
            1: "ARG-ID"
        }

        # Get opcode and opmod names
        opcode_name = opcode_names.get(self.gen_ctrl_seg.opcode, "UNKNOWN")
        opmod_name = opmod_names.get(self.gen_ctrl_seg.opmod, "UNKNOWN")
        # Add gen_ctrl_seg info with names
        dump_lines.add_line("WQE CTRL:\n\t")
        dump_lines.append_to_line(0, f" Ctrl: opcode: 0x{self.gen_ctrl_seg.opcode:02x} ({opcode_name}),"
                                  f"opmod: 0x{self.gen_ctrl_seg.opmod:02x} ({opmod_name}), "
                                  f"cur_post: 0x{self.gen_ctrl_seg.cur_post:x}, imm: 0x{self.gen_ctrl_seg.imm:x}")

        # Only print debug output if opcode is 0x2c (TBL_ACCESS)
        if self.gen_ctrl_seg.opcode == 0x2c:
            dump_lines.append_to_line(0, f"({imm_names.get(self.gen_ctrl_seg.opmod, 'UNKNOWN')})")
            if self.gen_ctrl_seg.opmod == 0:
                # Check if this RTC ID belongs to a collision matcher
                # self.gen_ctrl_seg.imm is an integer from the WQE
                rtc_id_int = self.gen_ctrl_seg.imm
                # Check each collision matcher to see if its match_rtc_0_id matches
                for col_matcher_id in _db._col_matchers:
                    col_matcher = _db._matchers.get(col_matcher_id)
                    if col_matcher and int(col_matcher.data.get("match_rtc_0_id")) == rtc_id_int:
                        dump_lines.append_to_line(0, f" (C)")
                        break

    def get_wqe_line(self, start_index: int, end_index: int) -> str:
        hex_values = ' '.join(f'0x{dword:08x}' for dword in self.dwords[start_index:end_index])
        return hex_values

    def parse_stc_dump_specifc_action(self, stc_data: Dict[str, Any], action_type: int) -> int:

        if action_type == DR_ACTION_COUNTER:
            value = stc_data['counter_id_mask'] & 0x00FFFFFF
            return value
        # For DR_ACTION_INSERT_POINTER / MODIFY Header, get the resource size mask
        elif (action_type == DR_ACTION_INSERT_POINTER or
              action_type == DR_ACTION_ACCELERATED_MODIFY_LIST):
              return stc_data['inline_actions_mask_dw2']
        elif action_type == DR_ACTION_ASO:
            return stc_data['inline_actions_mask_dw1']
        return 0

    def parse_stc_dump(self, raw_dump: str, verbosity: int = 0) -> Tuple[str, int, List[int], str]:
        """Parse STC dump and extract action information"""

        # Look for fw_stc segment (0x1036) first
        # Debug: Show what we're trying to parse
        #traceback.print_stack()
        # Parse the raw dump using SegmentBufferParser
        parser = SegmentBufferParser(raw_dump)

        # Try to parse 0x3b segment
        stc_data = parser.get_parsed_segment(0x3b)
        lines = ""  # Initialize as empty string
        if verbosity >= 1:
            stc_data_line = parser.print_segment(0x3b)
            if stc_data_line:
                lines += stc_data_line
        ste_stc_data = parser.get_parsed_segment(0x3c)
        if verbosity >= 1:
            ste_stc_data_line = parser.print_segment(0x3c)
            if ste_stc_data_line:
                lines += ste_stc_data_line

        action_type = stc_data['action_type']
        dword_index_in_ste = stc_data['ste_action_offset']
        dword_index_in_ste = get_stc_real_data_action_location(action_type, dword_index_in_ste)

        action_specific = self.parse_stc_dump_specifc_action(ste_stc_data, action_type)

        if action_type in stc_action_type_info:
             action_info = stc_action_type_info[action_type]
             # Add stc_info to the return value
             return [action_info[0], action_info[1], dword_index_in_ste, action_type,
                        action_specific, lines]
        else:
               return ["UNKNOWN", 0, 0, 0, 0]

    def parse_rtc_dump(self, raw_dump: str) -> int:
        """Parse RTC dump and extract the STC base ID"""
        stc_base_id = ""
        i = 0
        for line in raw_dump.split('\n'):
            if "0x0014002C" in line:
                i = 2
            elif i > 0:
                if i == 1:
                    stc_base_id = line
                i -= 1

        if stc_base_id:
            stc_base_id = int(stc_base_id.split(' ')[1].strip(), 16)
            return stc_base_id
        return 0

    def get_rd_dump(self, device: str,
                    rdma_device: str,
                    vhca_id : int = 0,
                    segment: str = "STC",
                    base_index: int = 0,
                    index: int = 0, 
                    all: str = "-n2 1") -> str:
        """Get resourcedump output"""
        str_all = f"-n2 {all} " if all is not None else ""
        str_index = f"-i2 {index} " if index is not None else ""
        if vhca_id is None:
            vhca_id = 0
        # Check if already running as root
        if os.geteuid() == 0:
            # Already root, don't use sudo
            cmd = f"resourcedump dump -d {device} -s {segment} -i1 {base_index} {str_index} {str_all} -m {rdma_device} -v {vhca_id}"
        else:
            # Not root, use sudo
            cmd = f"sudo resourcedump dump -d {device} -s {segment} -i1 {base_index} {str_index} {str_all} -m {rdma_device} -v {vhca_id}"

        #print(f"Executing command: {cmd}")

        try:
            response = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if response.returncode != 0:
                print(f"Command failed with return code: {response.returncode}")
                print(f"Error output: {response.stderr}")
                print(f"Standard output: {response.stdout}")
                return response.stderr if response.stderr else "Command failed with no error message"
            return response.stdout
        except subprocess.TimeoutExpired:
            print(f"Command timed out after 30 seconds")
            return "Command timed out"
        except Exception as e:
            print(f"Exception occurred: {type(e).__name__}: {str(e)}")
            return f"Exception: {str(e)}"

    def get_stc_base_from_rtc(self, device: str, 
                              rdma_device: str,
                              vhca_id : int = 0) -> int:
        """Get STC base from RTC segment"""
        output = self.get_rd_dump(device, rdma_device, vhca_id, "RTC",
                                  self.gen_ctrl_seg.imm, None, None)
        stc_base = self.parse_rtc_dump(output)
        return stc_base

    def verify_wqe_stc(self, stc_base: int,
                       stc_details: Tuple[str, int, List[int]],
                       stc_data: List[int],
                       dump_lines: DumpLines, line_index: int) -> bool:
        """Verify WQE STC"""
        stc_name, stc_id, stc_data = stc_details

        dump_lines.append_to_line(line_index, f" ==> {stc_name  }: 0x{stc_id:06x}, data value: {stc_data[0]}")
        return True

class dr_wqe_aso(dr_wqe):
    """WQE GTA STE class for parsing and handling WQE GTA STE"""
    def __init__(self, data, gen_ctrl_seg, verbosity=0):
        super().__init__(data, gen_ctrl_seg, verbosity)
        self.type = "ABCDR_WQE_ASO"
        # Store the raw bytes for parsing
        self.raw_bytes = data
        # Convert bytes to dwords for WQE parsing
        if isinstance(data, bytes):
            self.dwords = list(struct.unpack('<32I', data[:128])) if len(data) >= 128 else []
        else:
            self.dwords = []

    def dump_str(self, verbosity, data=None):
        """Dump WQE ASO data as string"""
        str = "==============================================\n"
        str += "WQE ASO:\n"
        str += f"Type: {self.type}\n"
        str += f"Opcode: 0x{self.gen_ctrl_seg.opcode:02x}\n"
        str += f"Opmod: 0x{self.gen_ctrl_seg.opmod:02x}\n"
        str += "==============================================\n"
        return str

    def parse_wqe_data(self, dump_lines: DumpLines):
        """Parse WQE ASO data"""
        self.dump_wqe_general_ctrl_seg(dump_lines)
        # Add ASO-specific parsing here if needed
        for i in range(4, len(self.dwords), 4):
            if i + 4 <= len(self.dwords):
                hex_values = self.get_wqe_line(i, min(i + 4, len(self.dwords)))
                dump_lines.add_line(f"{hex_values}")

class dr_wqe_gta_arg(dr_wqe):
    """WQE GTA MOD ARG class for parsing and handling WQE GTA MOD ARG"""
    def __init__(self, data, gen_ctrl_seg, verbosity=0):
        super().__init__(data, gen_ctrl_seg, verbosity)
        self.type = "ABCDR_WQE_GTA_ARG"
        # Store the raw bytes for parsing
        self.raw_bytes = data
        # Convert bytes to dwords for WQE parsing
        if isinstance(data, bytes):
            self.dwords = list(struct.unpack('<32I', data[:128])) if len(data) >= 128 else []
        else:
            self.dwords = []

    def dr_arg_get_pd(self, arg_index: int) -> int:
        #sudo resourcedump dump -d /dev/mst/mt4129_pciconf0 -s HW_MODIFY_ARG -i1 0x20010  -m mlx5_0
        device = _config_args.get("device", "/dev/mst/mt4129_pciconf0")
        rdma_device = _config_args.get("dev_name", "mlx5_0")
        base_index = arg_index  # Use the arg_index parameter

        # Check if already running as root
        if os.geteuid() == 0:
            # Already root, don't use sudo
            cmd = f"resourcedump dump -d {device} -s HW_MODIFY_ARG -i1 0x{base_index:x} -m {rdma_device}"
        else:
            # Not root, use sudo
            cmd = f"sudo resourcedump dump -d {device} -s HW_MODIFY_ARG -i1 0x{base_index:x} -m {rdma_device}"

        #print(f"Executing command: {cmd}")

        try:
            response = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if response.returncode != 0:
                print(f"Command failed with return code: {response.returncode}")
                print(f"Error output: {response.stderr}")
                print(f"Standard output: {response.stdout}")
                return 0  # Return 0 on error

            # Parse the response to find Segment Type: 0x1012
            lines = response.stdout.split('\n')
            found_segment_1012 = False

            for i, line in enumerate(lines):
                if "Segment Type: 0x1012" in line:
                    found_segment_1012 = True
                    # Look for Segment Data after this line
                    for j in range(i+1, len(lines)):
                        if "Segment Data:" in lines[j]:
                            # Collect data lines until we hit another segment or end
                            data_lines = []
                            for k in range(j+1, len(lines)):
                                line_k = lines[k].strip()
                                # Stop if we hit another segment marker or empty line
                                if not line_k or "Segment Type:" in line_k or "---" in line_k:
                                    break
                                if "0x" in line_k:
                                    data_lines.append(line_k)

                            # Get the last word from all collected data
                            if data_lines:
                                # Split all data lines into hex values
                                all_hex_values = []
                                for data_line in data_lines:
                                    hex_values = data_line.split()
                                    all_hex_values.extend(hex_values)

                                if all_hex_values:
                                    # Get the last hex value
                                    last_word = all_hex_values[-1]
                                    # Convert to int and extract lower 16 bits
                                    value = int(last_word, 16) & 0xFFFF
                                    return value
                            break
                    break

            # If segment 0x1012 not found, return 0
            return 0

        except Exception as e:
            print(f"Exception occurred: {type(e).__name__}: {str(e)}")
            return 0  # Return 0 on exception

    def arg_verify(self, arg_data: List[int], dump_lines: DumpLines, line_index: int) -> bool:
        """Verify ARG data"""
        # check if the pd fits the context pd
        pd = self.dr_arg_get_pd(arg_data[0])
        if pd == 0:
            dump_lines.append_to_line(line_index, red(f"//ARG index: 0x{arg_data[0]:x} is out of range"))
            return False
        return True

    def dump_str(self, verbosity, data=None):
        """Dump WQE GTA ARG data as string"""
        str = "==============================================\n"
        str += "WQE GTA ARG:\n"
        str += f"Type: {self.type}\n"
        str += f"Opcode: 0x{self.gen_ctrl_seg.opcode:02x}\n"
        str += f"Opmod: 0x{self.gen_ctrl_seg.opmod:02x}\n"
        str += "==============================================\n"
        return str

    def parse_wqe_data(self, dump_lines: DumpLines):
        """Parse WQE GTA ARG data"""
        self.dump_wqe_general_ctrl_seg(dump_lines)
        for i in range(4, len(self.dwords), 4):
            if i + 4 <= len(self.dwords):
                hex_values = self.get_wqe_line(i, min(i + 4, len(self.dwords)))
                dump_lines.add_line(f"{hex_values}")

        if self.verbosity > 0:
            self.arg_verify([self.dwords[3]], dump_lines, 0)
        for i in range(3):
            dump_lines.append_to_line(i+1, f" ==> GTA ctrl WQE ")
        for i in range(4):
            dump_lines.append_to_line(i+4, f" ==> GTA ARG data ")

class dr_wqe_unknown(dr_wqe):
    """WQE UNKNOWN class for parsing and handling WQE UNKNOWN"""
    def __init__(self, data, gen_ctrl_seg, verbosity=0):
        super().__init__(data, gen_ctrl_seg, verbosity)
        self.type = "ABCDR_WQE_UNKNOWN"
        # Store the raw bytes for parsing
        self.raw_bytes = data
        # Convert bytes to dwords for WQE parsing
        if isinstance(data, bytes):
            self.dwords = list(struct.unpack('<32I', data[:128])) if len(data) >= 128 else []
        else:
            self.dwords = []

    def dump_str(self, verbosity, data=None):
        """Dump WQE Unknown data as string"""
        str = "==============================================\n"
        str += "WQE Unknown:\n"
        str += f"Type: {self.type}\n"
        str += f"Opcode: 0x{self.gen_ctrl_seg.opcode:02x}\n"
        str += f"Opmod: 0x{self.gen_ctrl_seg.opmod:02x}\n"
        str += "==============================================\n"
        return str

    def parse_wqe_data(self, dump_lines: DumpLines):
        """Parse WQE Unknown data"""
        self.dump_wqe_general_ctrl_seg(dump_lines)
        # Dump remaining data as hex
        for i in range(4, len(self.dwords), 4):
            if i + 4 <= len(self.dwords):
                hex_values = self.get_wqe_line(i, min(i + 4, len(self.dwords)))
                dump_lines.add_line(f"{hex_values}")

class dr_wqe_error(dr_wqe):
    """WQE Error class for parsing and handling WQE Error"""
    def __init__(self, data, verbosity=0):
        # Note: dr_wqe_error has different initialization than other subclasses
        # It doesn't receive gen_ctrl_seg, so we create a dummy one
        dummy_gen_ctrl_seg = None
        super().__init__(data, dummy_gen_ctrl_seg, verbosity)
        self.type = "ABCDR_WQE_ERROR"
        keys = ["mlx5dr_debug_res_type", "ctx_id", "id", "send_engine_index", "syndrom", "raw_data"]
        # Take first 5 fields as separate values, concatenate the rest as raw_data
        if len(data) > 5:
            # First 5 fields remain as they are
            first_five = data[:5]
            # Concatenate remaining fields with spaces instead of commas
            raw_data = ' '.join(data[5:])
            # Combine first 5 fields with the concatenated raw_data
            processed_data = first_five + [raw_data]
        else:
            # If data has 5 or fewer fields, use as is with empty raw_data
            processed_data = data + ['']

        self.data = dict(zip(keys, processed_data + [None] * (len(keys) - len(processed_data))))

class dr_wqe_match(dr_wqe):
    """WQE match class for parsing and handling WQE """

    def __init__(self, data, gen_ctrl_seg, verbosity=0):
        super().__init__(data, gen_ctrl_seg, verbosity)
        self.type = "ABCDR_WQE_MATCH"

        # Store the raw bytes for parsing
        self.raw_bytes = data

        # Convert bytes to dwords for WQE parsing
        if isinstance(data, bytes):
            self.dwords = list(struct.unpack('<32I', data[:128])) if len(data) >= 128 else []
        else:
            self.dwords = []

        # Initialize empty data dict for compatibility
        self.data = {}
        self.wqe_err = None
        self.wqe_parsed_data = None
        self.verbosity = verbosity

    def dump_str(self, verbosity, data=None):
        str = "==============================================\n"
        str += "WQE Error:\n"

        # Use the stored dwords if available
        if self.dwords:
            self.wqe_parsed_data = self.get_gta_ctrl_seg_fields(self.dwords)
            str += "\nParsed WQE Data (hex format):\n"
            str += self.format_wqe_parsed_data(self.wqe_parsed_data, hex_format=True)
            str += "\n"

        str += "==============================================\n"

        return str

    def parse_line_wqe(self, line: str) -> WQEGtaFlowUpdateParsedData:
        """
        Parse 128 bytes (32 dwords) of WQE data according to the specified format.

        Args:
            line: bytes object containing exactly 128 bytes

        Returns:
            WQEParsedData: Named tuple containing all parsed fields

        Raises:
            ValueError: If data is not exactly 128 bytes
        """
        if len(line) != 128:
            raise ValueError(f"Expected 128 bytes, got {len(line)} bytes")

        # Parse all dwords (32-bit little-endian unsigned integers)
        dwords = struct.unpack('<32I', line)

        # Extract fields according to specification
        idx = 0
        idx += 5 # Skip the first 5 dwords (ctx, id, id, etc.)

        return self.parse_wqe_data(dwords)

    def parse_wqe_data(self, dump_lines: DumpLines):

        self.dump_wqe_general_ctrl_seg(dump_lines)

        parsed = self.get_gta_ctrl_seg_fields(self.dwords)
        self.parse_wqe_gta_ctrl_seg(parsed, dump_lines)
        self.parse_wqe_gta_data_seg(parsed, dump_lines)
        self.print_raw_wqe(dump_lines)

    def get_gta_ctrl_seg_fields(self, dwords: List[int]):
        idx = 0

        ctrl1 = list(dwords[idx:idx + 4])
        idx += 4

        op_directx = dwords[idx]
        idx += 1

        stc_array = list(dwords[idx:idx + 5])
        idx += 5

        reserved1 = list(dwords[idx:idx + 6])
        idx += 6

        ctr_id = dwords[idx]
        idx += 1

        definer = dwords[idx]
        idx += 1

        rsvd2 = list(dwords[idx:idx+3])
        idx += 3

        action_data = list(dwords[idx:idx+3])
        idx += 3

        tag = list(dwords[idx:idx+8])
        idx += 8

        return WQEGtaFlowUpdateParsedData(
            ctrl1=ctrl1,
            op_directx=op_directx,
            stc_array=stc_array,
            reserved1=reserved1,
            ctr_id=ctr_id,
            definer=definer,
            rsvd2=rsvd2,
            action_data=action_data,
            tag=tag
        )

    def format_wqe_parsed_data(self, parsed_data: WQEGtaFlowUpdateParsedData, hex_format: bool = True) -> str:
        """
        Format WQEParsedData for display.

        Args:
            parsed_data: The parsed WQE data
            hex_format: If True, display values in hex format, otherwise decimal

        Returns:
            Formatted string representation
        """
        lines = []

        if hex_format:
            lines.append(f"ctrl1: {' '.join(f'0x{val:08x}' for val in parsed_data.ctrl1)}")
            lines.append(f"op_directx: 0x{parsed_data.op_directx:08x}")
            lines.append(f"stc_array: {' '.join(f'0x{val:08x}' for val in parsed_data.stc_array)}")
            lines.append(f"reserved1: {' '.join(f'0x{val:08x}' for val in parsed_data.reserved1)}")
            lines.append(f"ctr_id: 0x{parsed_data.ctr_id:08x}")
            lines.append(f"definer: 0x{parsed_data.definer:08x}")
            lines.append(f"rsvd2: {' '.join(f'0x{val:08x}' for val in parsed_data.rsvd2)}")
            lines.append(f"action_data: {' '.join(f'0x{val:08x}' for val in parsed_data.action_data)}")
            lines.append(f"tag: {' '.join(f'0x{val:08x}' for val in parsed_data.tag)}")
        else:
            lines.append(f"ctrl1: {' '.join(str(val) for val in parsed_data.ctrl1)}")
            lines.append(f"op_directx: {parsed_data.op_directx}")
            lines.append(f"stc_array: {' '.join(str(val) for val in parsed_data.stc_array)}")
            lines.append(f"reserved1: {' '.join(str(val) for val in parsed_data.reserved1)}")
            lines.append(f"ctr_id: {parsed_data.ctr_id}")
            lines.append(f"definer: {parsed_data.definer}")
            lines.append(f"rsvd2: {' '.join(str(val) for val in parsed_data.rsvd2)}")
            lines.append(f"action_data: {' '.join(str(val) for val in parsed_data.action_data)}")
            lines.append(f"tag: {' '.join(str(val) for val in parsed_data.tag)}")

        return '\n'.join(lines)

    def dump_wqe_gta_ctrl_get_stc_ix(self, stc_base: int, stc_ix: List[int], actions_data: List[int],
                                     dump_lines: DumpLines):
        """
        Dump the stc_ix array from the WQE GTA ctrl seg.
        """
        dev = _config_args.get("device")
        dev_name = _config_args.get("dev_name")
        vhca_id = _config_args.get("vhca_id")
        verfy_dump_lines = DumpLines()
        verfy_dump_lines.add_line("")
        # Parse last_stc from the 3 MSB bits of stc_ix[0]
        # Bits 29-31 (3 MSB bits) indicate last_stc
        last_stc = (stc_ix[0] >> 29) & 0x7  # Extract bits 29-31
        hex_values = self.get_wqe_line(8, 12)
        line = f"STCs: {last_stc}: "
        i = 0
        detailed_stc_lines = ""
        while i <= last_stc:
            cur_stc = stc_ix[i] & 0xFFFFFF
            # Check cache first
            cache_key = (stc_base, cur_stc)
            if cache_key in _db._stc_parsed_cache:
                parsed_output = _db._stc_parsed_cache[cache_key]
            else:
                output = self.get_rd_dump(dev, dev_name, vhca_id, "STC", stc_base, cur_stc, "1")
                parsed_output = self.parse_stc_dump(output, self.verbosity)
                # Store in cache
                _db._stc_parsed_cache[cache_key] = parsed_output
            detailed_stc_lines += parsed_output[5] + "\n"
            # Only create and use verifier if verbosity > 0
            if self.verbosity:
                dr_action_verify.verify(parsed_output[3], [parsed_output[2],
                                                actions_data, parsed_output[4]],
                                                verfy_dump_lines, 0)

            line  += f"0x{cur_stc:x}({parsed_output[0]}/0x{actions_data[parsed_output[2]]:x}), "
            i+=1
        dump_lines.add_line(f"\t\t {line}")
        dump_lines.append_to_line(1, "\n\t\t" + verfy_dump_lines.to_string())

    def parse_wqe_gta_ctrl_seg(self, gta_parsed: WQEGtaFlowUpdateParsedData , dump_lines: DumpLines):
         """
         struct send_wqe_gta_ctrl_seg {
             __be32 op_dirix;
             __be32 stc_ix[5];
             __be32 rsvd0[6];
         };
         """
         # Extract op_dirix from parsed.op_directx
         op_dirix = gta_parsed.op_directx

         # Parse op_dirix fields
         # Bits 0-23: ste_offset (24 bits)
         ste_offset = op_dirix & 0xFFFFFF

        # Bit 29: operation mode (0: insert flow/STE, 1: delete flow/MOD_ARG)
         op_mode_bit = (op_dirix >> 29) & 0x1
         op_mode = "DELETE" if op_mode_bit else "UPDATE"
         # Extract stc_ix array from parsed.stc_array
         stc_ix = gta_parsed.stc_array  # This is already a list of 5 dwords
         actions_data = [gta_parsed.ctr_id, gta_parsed.definer] + gta_parsed.rsvd2 + gta_parsed.action_data

         # Format the extracted fields
         hex_values = self.get_wqe_line(4, 8)
         dump_lines.append_to_line(0, f"op_mode: {op_mode_bit} ({op_mode}), op_dirix: 0x{op_dirix:02x}, "
                                   f"ste_offset: 0x{ste_offset:x}, ")

         # get stc base from RTC segment
         stc_base = self.get_stc_base_from_rtc(_config_args.get("device"),
                                               _config_args.get("dev_name"),
                                               _config_args.get("vhca_id"))
         self.dump_wqe_gta_ctrl_get_stc_ix(stc_base, stc_ix, actions_data, dump_lines)

    def parse_wqe_gta_data_seg(self, gta_parsed: WQEGtaFlowUpdateParsedData, dump_lines: DumpLines):

        dump_lines.add_line(f"WQE DATA:\n")

        ctr_id = gta_parsed.ctr_id & 0x00FFFFFF
        action_data1 = gta_parsed.action_data[0]
        action_data2 = gta_parsed.action_data[1]
        action_data3 = gta_parsed.action_data[2]
        hit_address_high = gta_parsed.rsvd2[1]
        hit_address_low = gta_parsed.rsvd2[2]
        dump_lines.add_line(f"\tcounter_id: {ctr_id}, hit_address_high: {hit_address_high}, ")
        dump_lines.append_to_line(3, f"hit_address_low: {hit_address_low}, ")
        dump_lines.append_to_line(3, f"action_data1: {action_data1}, ")
        dump_lines.append_to_line(3, f"action_data2: {action_data2}, ")
        dump_lines.append_to_line(3, f"action_data3: {action_data3}\n")

    def print_raw_wqe(self, dump_lines: DumpLines):
        """
        print the raw WQE data
        """
        dump_lines.add_line(f"RAW WQE DATA:\n")
        for i in range(8):
            hex_values = self.get_wqe_line(i*4, i*4 + 4)
            dump_lines.add_line(f"\t{hex_values}")
        dump_lines.add_line(f"\n")

class dr_wqe_error():
    """WQE ERROR class for parsing and handling WQE ERROR"""
    def __init__(self, data, verbosity=4):
        self.type = "ABCDR_WQE_ERROR"
        self.verbosity = verbosity
        keys = ["mlx5dr_debug_res_type", "ctx_id", "id", "send_engine_index", "syndrom", "raw_data"]
        # Take first 5 fields as separate values, concatenate the rest as raw_data
        if len(data) > 5:
            # First 5 fields remain as they are
            first_five = data[:5]
            # Concatenate remaining fields with spaces instead of commas
            raw_data = ' '.join(data[5:])
            # Combine first 5 fields with the concatenated raw_data
            processed_data = first_five + [raw_data]
        else:
            # If data has 5 or fewer fields, use as is with empty raw_data
            processed_data = data + ['']
            raw_data = ''
        self.data = dict(zip(keys, processed_data + [None] * (len(keys) - len(processed_data))))
        # Use the factory to get the WQE parser
        factory = WQEParserFactory.get_instance()
        self.wqe_parser = factory.get_wqe_parser(raw_data, verbosity)

    def dump_str(self, verbosity, data=None):
        self.verbosity = verbosity
        dump_lines = DumpLines()
        self.wqe_parser.parse_wqe_data(dump_lines)
        #str = "==============================================\n"
        str = "WQE Error:\n"
        str += dump_obj_str(["mlx5dr_debug_res_type", "ctx_id", "id", "send_engine_index", "syndrom"], self.data)
        str += dump_lines.to_string()
        #str += "\n=============================================\n"
        return str

    def parse_wqe_data(self, dump_lines: DumpLines):
        pass

def dr_wqe_parse_queue(data, num_entries, verbosity=0):
    """Parse WQE queue dump data.

    Args:
        data: String containing the WQE queue dump
        num_entries: Number of WQE entries to process (from pi)

    Returns:
        None (prints parsed output)
    """
    lines = data.strip().split('\n')

    print(f"Processing {num_entries} WQE entries")
    print("=" * 80)

    # Process WQEs in a single loop, pairing them on the fly
    current_wqe_data = []
    current_idx = None
    pair_first_idx = None
    pair_first_data = None
    wqe_count = 0
    processed_pairs = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip separator lines and header lines
        if "=" * 10 in line or any(keyword in line.lower() for keyword in ['dump of sq', 'connected']):
            continue

        # Check if this is an index line like "[idx = 0x013b]"
        if line.startswith("[idx"):
            # Process previous WQE if exists
            if current_wqe_data and current_idx is not None:
                wqe_data_str = ' '.join(current_wqe_data)
                wqe_count += 1

                # Stop if we've processed enough WQEs
                if wqe_count > num_entries:
                    break

                if pair_first_idx is None:
                    # This is the first WQE of a pair
                    pair_first_idx = current_idx
                    pair_first_data = wqe_data_str
                else:
                    # This is the second WQE of a pair - process the pair
                    processed_pairs += 1
                    print(f"\nWQE Pair #{processed_pairs}: [{pair_first_idx}] and [{current_idx}]")

                    combined_data = pair_first_data + ' ' + wqe_data_str

                    try:
                        # Create WQE parser with combined data
                        factory = WQEParserFactory.get_instance()
                        wqe_parser = factory.get_wqe_parser(combined_data, verbosity)
                        print(f"WQE Parser:verbose wqe parser: {wqe_parser.verbosity}")
                        # Create DumpLines object for output formatting
                        dump_lines = DumpLines()

                        # Parse the WQE data
                        wqe_parser.parse_wqe_data(dump_lines)

                        # Print the parsed output
                        print(dump_lines.to_string())

                    except Exception as e:
                        print(f"Error parsing WQE pair: {str(e)}")

                    # Reset for next pair
                    pair_first_idx = None
                    pair_first_data = None

                current_wqe_data = []

            # Extract new index
            try:
                idx_part = line.split(']')[0]
                current_idx = idx_part.split('=')[1].strip()

                # Get hex data from the rest of the line after "]"
                hex_data = line.split(']')[1].strip()
                if hex_data:
                    current_wqe_data.append(hex_data)
            except (IndexError, ValueError) as e:
                print(f"Warning: Could not parse index line: {line}")
                continue

        elif current_idx is not None:
            # This is a continuation line with hex data
            if any(c in '0123456789abcdefABCDEF' for c in line):
                # Skip lines that are headers or other metadata
                if not any(keyword in line.lower() for keyword in ['entries', 'ts:', 'pi', 'ci']):
                    current_wqe_data.append(line.strip())

    # Process the last WQE(s) if within num_entries limit
    if current_wqe_data and current_idx is not None and wqe_count < num_entries:
        wqe_data_str = ' '.join(current_wqe_data)
        wqe_count += 1

        if pair_first_idx is None:
            # Single WQE left
            print(f"\nSingle WQE: [{current_idx}]")
            print("-" * 80)

            try:
                factory = WQEParserFactory.get_instance()
                wqe_parser = factory.get_wqe_parser(wqe_data_str, verbosity=0)
                dump_lines = DumpLines()
                wqe_parser.parse_wqe_data(dump_lines)
                print(dump_lines.to_string())
            except Exception as e:
                print(f"Error parsing WQE: {str(e)}")
        else:
            # Complete the last pair
            processed_pairs += 1
            print(f"\nWQE Pair #{processed_pairs}: [{pair_first_idx}] and [{current_idx}]")
            print("-" * 80)

            combined_data = pair_first_data + ' ' + wqe_data_str

            try:
                factory = WQEParserFactory.get_instance()
                wqe_parser = factory.get_wqe_parser(combined_data, verbosity=0)
                dump_lines = DumpLines()
                wqe_parser.parse_wqe_data(dump_lines)
                print(dump_lines.to_string())
            except Exception as e:
                print(f"Error parsing WQE pair: {str(e)}")
    elif pair_first_idx is not None and wqe_count <= num_entries:
        # We have an unpaired first WQE
        print(f"\nSingle WQE: [{pair_first_idx}]")
        print("-" * 80)

        try:
            factory = WQEParserFactory.get_instance()
            wqe_parser = factory.get_wqe_parser(pair_first_data, verbosity=0)
            dump_lines = DumpLines()
            wqe_parser.parse_wqe_data(dump_lines)
            print(dump_lines.to_string())
        except Exception as e:
            print(f"Error parsing WQE: {str(e)}")

    print("\n" + "=" * 80)
    print(f"Total WQEs processed: {min(wqe_count, num_entries)} (limit: {num_entries})")
    print(f"Total pairs processed: {processed_pairs}")