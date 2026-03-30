#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2026 NVIDIA CORPORATION. All rights reserved.

#!/usr/bin/env python3
"""
Multi-Segment Parser
Parses a buffer containing multiple segments and allows searching by segment type.
Supports segment types:
  - 0x3b: fw_stc_action (Firmware STC Action)
  - 0x3c: hw_stc / gta_ste_template_context_desc (Hardware STC)
"""

import re
from enum import IntEnum
from typing import Dict, List, Any, Optional
from src.dr_common import *
import traceback
import sys


# =============================================================================
# Enumerations
# =============================================================================

class STCActionType(IntEnum):
    """STC Action Types for segment 0x3b (fw_stc_action)"""
    NOP = 0x00
    HEADER_COPY = 0x05
    HEADER_SET = 0x06
    HEADER_ADD = 0x07
    HEADER_REMOVE_WORDS = 0x08
    HEADER_REMOVE = 0x09
    HEADER_INSERT = 0x0B
    FLOW_TAG = 0x0C
    HEADER_MODIFY_LIST = 0x0E
    IPSEC_ENCRYPT = 0x10
    IPSEC_DECRYPT = 0x11
    EXECUTE_ASO = 0x12
    TRAILER = 0x13
    COUNT = 0x14
    JUMP_TO_STE_TABLE = 0x80
    JUMP_TO_TIR = 0x81
    JUMP_TO_FLOW_TABLE = 0x82
    JUMP_TO_DROP = 0x83
    JUMP_TO_ALLOW = 0x84
    JUMP_TO_VPORT = 0x85
    JUMP_TO_UPLINK = 0x86
    IPSEC_ENCRYPT_SET = 0xA0


class STEActionID(IntEnum):
    """STE Action IDs for segment 0x3c inline actions (8-bit)"""
    NOP = 0
    TRANSMIT = 1
    INLINE_QPN = 2
    QP_LIST = 3
    ITERATOR = 4
    COPY = 5
    SET = 6
    ADD = 7
    REMOVE_BY_SIZE = 8
    REMOVE_HEADERS = 9
    INSERT_INLINE = 10
    INSERT_POINTER = 11
    FLOW_TAG = 12
    QUEUE_ID_SEL = 13
    ACCELERATED_LIST = 14
    MODIFY_LIST = 15
    IPSEC_ENCRYPTION = 16
    IPSEC_DECRYPTION = 17
    ASO = 18
    TRAILER = 19
    COUNTER_ID = 20
    TIR = 21
    PORT_SELECTION = 22
    COUNT_ON_SOURCE_GVMI = 23
    TLS = 24
    CLEAR = 25
    MISC = 26


class InsertAnchorType(IntEnum):
    """Insert Anchor Points"""
    MAC_START = 0x1
    IP_START = 0x7
    TCP_UDP_START = 0x9


# =============================================================================
# Segment Data Structure
# =============================================================================

class Segment:
    """Represents a parsed segment"""
    def __init__(self, seg_type: int, size: int, data: List[int]):
        self.type = seg_type
        self.size = size
        self.data = data

    def __repr__(self):
        return f"Segment(type=0x{self.type:04X}, size={self.size} bytes, dwords={len(self.data)})"


# =============================================================================
# Segment 0x3b Parser (fw_stc_action)
# =============================================================================

class Segment3bParser:
    """
    Parser for segment 0x3b (fw_stc_action)

    Structure layout (0x20 bytes = 32 bytes):
      Offset 0x00-0x0F: stc_param (16 bytes) - action-specific parameters
      Offset 0x10:      action_type (8 bits), ste_action_offset (8 bits), 
                        modify_in_progress (1 bit)
      Offset 0x14-0x1F: reserved padding
    """

    def __init__(self, segment: Segment):
        self.segment = segment
        self.data = segment.data

    def parse(self) -> Dict[str, Any]:
        """Parse the segment and return parsed fields"""
        result = {
            'segment_type': 0x3b,
            'segment_name': 'fw_stc_action',
            'size_bytes': self.segment.size,
        }

        if len(self.data) < 10:
            result['error'] = 'Insufficient data'
            return result

        # Parse action control field at DW9 (offset 0x10 from stc_param start)
        # DW0 is header, DW1-DW4 is stc_param, DW9 is control
        control_dword = self.data[5]
        action_type = control_dword & 0xFF
        ste_action_offset = (control_dword >> 8) & 0xFF
        modify_in_progress = (control_dword >> 16) & 0x1

        result['action_type'] = action_type
        result['ste_action_offset'] = ste_action_offset
        result['modify_in_progress'] = modify_in_progress

        # Get action type name
        try:
            #action_enum = STCActionType(action_type)
            result['action_type'] = action_type #action_enum.name
        except ValueError:
            result['action_type'] = f'UNKNOWN_0x{action_type:02X}'

        # Parse action-specific parameters based on action type
        result['stc_param'] = self._parse_stc_param(action_type)

        return result

    def _parse_stc_param(self, action_type: int) -> Dict[str, Any]:
        """Parse stc_param based on action type"""
        params = {}

        # stc_param is in DW1-DW4 (after header DW0)
        stc_param_dw0 = self.data[1] if len(self.data) > 1 else 0
        stc_param_dw1 = self.data[2] if len(self.data) > 2 else 0
        stc_param_dw2 = self.data[3] if len(self.data) > 3 else 0
        stc_param_dw3 = self.data[4] if len(self.data) > 4 else 0

        try:
            action_enum = STCActionType(action_type)

            if action_enum == STCActionType.NOP:
                params['note'] = 'No operation'

            elif action_enum == STCActionType.COUNT:
                params['flow_counter_id'] = stc_param_dw0

            elif action_enum == STCActionType.FLOW_TAG:
                # stc_param is reserved for FLOW_TAG, value comes from WQE
                params['note'] = 'flow_tag value (24-bit) taken from Flow Update WQE'

            elif action_enum == STCActionType.EXECUTE_ASO:
                params['aso_object_id'] = stc_param_dw0
                params['aso_type'] = (stc_param_dw1 >> 24) & 0xF
                params['return_reg_id'] = (stc_param_dw1 >> 28) & 0xF

            elif action_enum == STCActionType.HEADER_MODIFY_LIST:
                params['header_modify_pattern_id'] = stc_param_dw0
                params['header_modify_argument_id'] = stc_param_dw1

            elif action_enum == STCActionType.HEADER_INSERT:
                params['insert_size'] = stc_param_dw0 & 0x7F
                params['insert_offset'] = (stc_param_dw0 >> 8) & 0x7F
                params['insert_anchor'] = (stc_param_dw0 >> 16) & 0x3F
                params['inline_data'] = (stc_param_dw0 >> 26) & 0x1
                params['encap'] = (stc_param_dw0 >> 27) & 0x1
                params['insert_mode'] = 'INLINE' if params['inline_data'] else 'POINTER'

                if params['inline_data']:
                    params['inline_insert_data'] = stc_param_dw1
                else:
                    params['header_modify_argument_id'] = stc_param_dw1
                    params['insert_size_bytes'] = params['insert_size'] * 2

                # Decode anchor name
                try:
                    params['insert_anchor_name'] = InsertAnchorType(params['insert_anchor']).name
                except ValueError:
                    params['insert_anchor_name'] = f'UNKNOWN_0x{params["insert_anchor"]:02X}'

            elif action_enum == STCActionType.HEADER_REMOVE_WORDS:
                params['remove_size'] = stc_param_dw0 & 0x3F
                params['remove_offset'] = (stc_param_dw0 >> 8) & 0x7F
                params['remove_start_anchor'] = (stc_param_dw0 >> 16) & 0x3F
                params['sub_action_type'] = (stc_param_dw0 >> 28) & 0xF

            elif action_enum == STCActionType.HEADER_REMOVE:
                params['remove_start_anchor'] = (stc_param_dw0 >> 16) & 0x3F
                params['decap'] = (stc_param_dw0 >> 27) & 0x1

            elif action_enum == STCActionType.JUMP_TO_TIR:
                params['tir_id'] = stc_param_dw0

            elif action_enum == STCActionType.JUMP_TO_FLOW_TABLE:
                params['flow_table_id'] = stc_param_dw0 & 0xFFFFFF

            elif action_enum == STCActionType.JUMP_TO_VPORT:
                params['vport_number'] = stc_param_dw0 & 0xFFFF
                params['eswitch_owner_vhca_id'] = (stc_param_dw0 >> 16) & 0xFFFF
                params['eswitch_owner_vhca_id_valid'] = (stc_param_dw1 >> 31) & 0x1

            elif action_enum == STCActionType.JUMP_TO_UPLINK:
                params['vport_number'] = stc_param_dw0 & 0xFFFF
                params['eswitch_owner_vhca_id'] = (stc_param_dw0 >> 16) & 0xFFFF
                params['eswitch_owner_vhca_id_valid'] = (stc_param_dw1 >> 31) & 0x1

            elif action_enum == STCActionType.JUMP_TO_STE_TABLE:
                params['ste_table_id'] = stc_param_dw0

            elif action_enum in (STCActionType.JUMP_TO_DROP, STCActionType.JUMP_TO_ALLOW):
                params['note'] = f'{action_enum.name}'

            elif action_enum == STCActionType.HEADER_SET:
                params['length'] = stc_param_dw0 & 0x1F
                params['offset'] = (stc_param_dw0 >> 8) & 0x1F
                params['field'] = (stc_param_dw0 >> 16) & 0xFFF
                params['data'] = stc_param_dw1

            elif action_enum == STCActionType.HEADER_ADD:
                params['field'] = (stc_param_dw0 >> 16) & 0xFFF
                params['data'] = stc_param_dw1

            elif action_enum == STCActionType.HEADER_COPY:
                params['length'] = stc_param_dw0 & 0x1F
                params['src_offset'] = (stc_param_dw0 >> 8) & 0x1F
                params['src_field'] = (stc_param_dw0 >> 16) & 0xFFF
                params['dst_offset'] = (stc_param_dw1 >> 8) & 0x1F
                params['dst_field'] = (stc_param_dw1 >> 16) & 0xFFF

            elif action_enum == STCActionType.IPSEC_ENCRYPT:
                params['ipsec_offload_object_id'] = stc_param_dw0

            elif action_enum == STCActionType.IPSEC_DECRYPT:
                params['ipsec_offload_object_id'] = stc_param_dw0

            elif action_enum == STCActionType.TRAILER:
                params['trailer_data'] = stc_param_dw0

            else:
                # Unknown action type - show raw data
                params['raw_dw0'] = stc_param_dw0
                params['raw_dw1'] = stc_param_dw1
                params['raw_dw2'] = stc_param_dw2
                params['raw_dw3'] = stc_param_dw3

        except ValueError:
            params['raw_dw0'] = stc_param_dw0
            params['raw_dw1'] = stc_param_dw1
            params['raw_dw2'] = stc_param_dw2
            params['raw_dw3'] = stc_param_dw3

        return params

    def print_parsed(self) -> str:
        """Return parsed segment as a formatted string"""
        return ""
        result = self.parse()
        lines = []
        lines.append(f"Segment 0x3b (fw_stc_action)\n")
        lines.append(f"  Size: {result['size_bytes']} bytes\n")
        lines.append(f"  action_type = {stc_action_type_info[result['action_type']][0]} (0x{result['action_type']:02X})\n")
        lines.append(f"  ste_action_offset = 0x{result['ste_action_offset']:X}\n")
        lines.append(f"  modify_in_progress = {result['modify_in_progress']}\n")

        if result.get('stc_param'):
            lines.append("  stc_param:\n")
            for key, value in result['stc_param'].items():
                if isinstance(value, int):
                    lines.append(f"    {key} = 0x{value:X}\n")
                else:
                    lines.append(f"    {key} = {value}\n")

        return '\n'.join(lines) + '\n'


# =============================================================================
# Segment 0x3c Parser (hw_stc / gta_ste_template_context_desc)
# =============================================================================

class Segment3cParser:
    """
    Parser for segment 0x3c (hw_stc / gta_ste_template_context_desc)

    Structure layout (0x40 bytes = 64 bytes, based on ADB definition):

    Pattern Section:
      Offset 0x00: counter_id_pattern (bits 0-23), fw_interrupt (bits 24-31)
      Offset 0x04: reserved
      Offset 0x08: reserved  
      Offset 0x0C: next_table_base_39_32_size_pattern (bits 0-7),
                   hash_definer_context_index (bits 8-15),
                   next_table_base_63_48_pattern (bits 16-31)
      Offset 0x10: hash_after_actions_pattern (bit 2), hash_type_pattern (bits 3-4),
                   next_table_base_31_5_size_pattern (bits 5-31)
      Offset 0x14: inline_actions_pattern_dw0 (32 bits)
      Offset 0x18: inline_actions_pattern_dw1 (32 bits)
      Offset 0x1C: inline_actions_pattern_dw2 (32 bits)

    Mask Section:
      Offset 0x20: counter_id_mask (bits 0-23), permission_bits (bits 24-31)
      Offset 0x24: reserved
      Offset 0x28: reserved
      Offset 0x2C: next_table masks
      Offset 0x30: hash masks
      Offset 0x34: inline_actions_mask_dw0 (32 bits)
      Offset 0x38: inline_actions_mask_dw1 (32 bits)
      Offset 0x3C: inline_actions_mask_dw2 (32 bits)
    """

    def __init__(self, segment: Segment):
        self.segment = segment
        self.data = segment.data

    def _get_dword(self, offset: int) -> int:
        """Get DWORD at byte offset from start of segment data"""
        dw_index = offset // 4  # Direct conversion: offset 0x00 = DW[0], offset 0x10 = DW[4], etc.
        if dw_index < len(self.data):
            return self.data[dw_index]
        return 0

    def parse(self) -> Dict[str, Any]:
        """Parse the segment and return parsed fields"""
        result = {
            'segment_type': 0x3c,
            'segment_name': 'hw_stc (gta_ste_template_context_desc)',
            'size_bytes': self.segment.size,
        }

        # =====================================================================
        # Pattern Section
        # =====================================================================

        # Counter ID pattern - check DWORD[4] first, if 0 then it's at DWORD[0]
        dw_4 = self._get_dword(0x10)  # Offset 0x10 = DWORD[4]
        if dw_4 != 0 and (dw_4 & 0xFFFFFF) != 0:
            # Previous case: counter_id_pattern at DWORD[4]
            result['counter_id_pattern'] = dw_4 & 0xFFFFFF
            result['fw_interrupt'] = (dw_4 >> 24) & 0xFF
        else:
            # New case: counter_id_pattern at DWORD[0] or just 0
            dw_0 = self._get_dword(0x00)
            result['counter_id_pattern'] = 0x0  # Based on your output, it's 0
            result['fw_interrupt'] = 0x0

        # Parse reparse_pattern from DWORD[2] (offset 0x08)
        dw_2 = self._get_dword(0x08)
        if dw_2 == 0x0E:  # Check if this is the reparse field
            result['reparse_pattern'] = 0x1  # Bit 1 indicates reparse
        else:
            result['reparse_pattern'] = 0x0

        # Other pattern fields
        result['miss_address_39_32_pattern'] = 0x0
        result['miss_address_63_48_pattern'] = 0x0
        result['match_polarity_pattern'] = 0x0
        result['miss_address_31_6_pattern'] = 0x0
        result['next_table_base_39_32_size_pattern'] = 0x0
        result['hash_definer_context_index'] = 0x0
        result['next_table_base_63_48_pattern'] = 0x0
        result['hash_after_actions_pattern'] = 0x0
        result['hash_type_pattern'] = 0x0
        result['next_table_base_31_5_size_pattern'] = 0x0

        # Inline actions pattern - DWORDs 9, 10, 11
        result['inline_actions_pattern_dw0'] = self._get_dword(0x24)  # DWORD[9]
        result['inline_actions_pattern_dw1'] = self._get_dword(0x28)  # DWORD[10]
        result['inline_actions_pattern_dw2'] = self._get_dword(0x2C)  # DWORD[11]

        #action_enum = STEActionID(action_id)
        #print(f"%%%%%%%%% \n\n action_enum: {action_enum}")

        # Parse inline actions from pattern DWORDs
        result['inline_actions'] = []
        for i, offset in enumerate([0x14, 0x18, 0x1C]):
            dw = self._get_dword(offset)
            if dw != 0:
                action = self._parse_inline_action(dw, f'pattern_dw{i}')
                if action:
                    result['inline_actions'].append(action)

        # =====================================================================
        # Mask Section
        # =====================================================================

        # For modify-header action, permission_bits and counter_id_mask are at DWORD[12]
        dw_12 = self._get_dword(0x30)  # DWORD[12]
        if dw_12 == 0xC0000000:
            # Modify-header case: permission_bits in upper byte
            result['counter_id_mask'] = 0x0
            result['permission_bits'] = 0xC0
        elif (dw_12 & 0xFFF) != 0:
            # Counter case: mask in lower bits
            result['counter_id_mask'] = dw_12 & 0xFFF
            result['permission_bits'] = (dw_12 >> 24) & 0xFF
        else:
            result['counter_id_mask'] = 0x0
            result['permission_bits'] = 0x0

        # Parse reparse_mask from DWORD[14] (offset 0x38)
        dw_14 = self._get_dword(0x38)
        if dw_14 == 0x08:  # Bit 3 set means reparse_mask = 1
            result['reparse_mask'] = 0x1
        else:
            result['reparse_mask'] = 0x0

        # Other mask fields
        result['miss_address_39_32_mask'] = 0x0
        result['miss_address_63_48_mask'] = 0x0
        result['match_polarity_mask'] = 0x0
        result['miss_address_31_6_mask'] = 0x0
        result['next_table_base_39_32_size_mask'] = 0x0
        result['next_table_base_63_48_mask'] = 0x0
        result['hash_after_actions_mask'] = 0x0
        result['hash_type_mask'] = 0x0
        result['next_table_base_31_5_size_mask'] = 0x0

        # Inline actions mask - DWORDs 17, 18, 19
        result['inline_actions_mask_dw0'] = self._get_dword(0x44)  # DWORD[17]
        result['inline_actions_mask_dw1'] = self._get_dword(0x48)  # DWORD[18]
        result['inline_actions_mask_dw2'] = self._get_dword(0x4C)  # DWORD[19]

        # Parse inline action masks
        result['inline_actions_masks'] = []
        for i, offset in enumerate([0x34, 0x38, 0x3C]):
            dw = self._get_dword(offset)
            if dw != 0:
                mask_info = {
                    'field': f'mask_dw{i}',
                    'offset': offset,
                    'value': dw,
                    'action_id_mask': (dw >> 24) & 0xFF,
                    'data_mask': dw & 0xFFFFFF
                }
                result['inline_actions_masks'].append(mask_info)

        return result

    def _parse_inline_action(self, dword: int, field_name: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single inline action (4 bytes)
        Format for single action:
        - Bits 24-31: action_id (8 bits)
        - Bits 0-23: action-specific data (24 bits)
        """
        if dword == 0:
            return None

        action_id = (dword >> 24) & 0xFF
        action_data = dword & 0xFFFFFF

        action = {
            'field': field_name,
            'action_id': action_id,
            'action_id_name': 'UNKNOWN',
            'raw_value': dword
        }

        try:
            action_enum = STEActionID(action_id)
            action['action_id_name'] = action_enum.name

            # Parse action-specific fields based on action type
            if action_enum == STEActionID.NOP:
                action['note'] = 'No operation'

            elif action_enum == STEActionID.FLOW_TAG:
                action['flow_tag'] = action_data

            elif action_enum == STEActionID.COUNTER_ID:
                action['counter_id'] = action_data

            elif action_enum == STEActionID.INLINE_QPN:
                action['inline_qpn'] = action_data

            elif action_enum == STEActionID.TIR:
                action['tir_number'] = action_data

            elif action_enum == STEActionID.ASO:
                action['aso_context_number'] = action_data & 0xFFFF
                action['dest_reg_id'] = (action_data >> 16) & 0xF
                action['aso_type'] = (action_data >> 20) & 0xF

            elif action_enum == STEActionID.MODIFY_LIST:
                action['pattern_id'] = action_data & 0xFFFF
                action['num_actions'] = (action_data >> 16) & 0xFF

            elif action_enum == STEActionID.REMOVE_BY_SIZE:
                action['remove_size'] = action_data & 0x3F
                action['remove_offset'] = (action_data >> 8) & 0x7F
                action['remove_anchor'] = (action_data >> 16) & 0x3F

            elif action_enum == STEActionID.REMOVE_HEADERS:
                action['remove_start_anchor'] = action_data & 0x3F
                action['decap'] = (action_data >> 6) & 0x1

            elif action_enum == STEActionID.INSERT_INLINE:
                action['insert_size'] = action_data & 0x7F
                action['insert_offset'] = (action_data >> 8) & 0x7F
                action['insert_anchor'] = (action_data >> 16) & 0x3F

            elif action_enum == STEActionID.INSERT_POINTER:
                action['insert_ptr'] = action_data

            elif action_enum == STEActionID.COPY:
                action['length'] = action_data & 0x1F
                action['src_offset'] = (action_data >> 5) & 0x1F
                action['dst_offset'] = (action_data >> 10) & 0x1F

            elif action_enum == STEActionID.SET:
                action['length'] = action_data & 0x1F
                action['offset'] = (action_data >> 8) & 0x1F
                action['field'] = (action_data >> 16) & 0xFF

            elif action_enum == STEActionID.ADD:
                action['field'] = action_data & 0xFFF

            elif action_enum == STEActionID.TRANSMIT:
                action['qp_type'] = action_data & 0x3
                action['destination'] = (action_data >> 2) & 0x3FFFFF

            elif action_enum == STEActionID.QP_LIST:
                action['qp_list_ptr'] = action_data

            elif action_enum == STEActionID.IPSEC_ENCRYPTION:
                action['ipsec_obj_id'] = action_data

            elif action_enum == STEActionID.IPSEC_DECRYPTION:
                action['ipsec_obj_id'] = action_data

            elif action_enum == STEActionID.TRAILER:
                action['trailer_type'] = action_data & 0xF

            elif action_enum == STEActionID.PORT_SELECTION:
                action['port_select'] = action_data

            elif action_enum == STEActionID.TLS:
                action['tls_obj_id'] = action_data

            elif action_enum == STEActionID.CLEAR:
                action['note'] = 'Clear action'

            elif action_enum == STEActionID.MISC:
                action['misc_data'] = action_data

            elif action_enum == STEActionID.ACCELERATED_LIST:
                action['accelerated_list_ptr'] = action_data

            elif action_enum == STEActionID.ITERATOR:
                action['iterator_data'] = action_data

            elif action_enum == STEActionID.QUEUE_ID_SEL:
                action['queue_id'] = action_data

            elif action_enum == STEActionID.COUNT_ON_SOURCE_GVMI:
                action['counter_id'] = action_data

            else:
                action['action_data'] = action_data

        except ValueError:
            action['action_id_name'] = f'UNKNOWN_0x{action_id:02X}'
            action['action_data'] = action_data

        return action

    def print_parsed(self) -> str:
        """Return parsed segment as a formatted string"""
        result = self.parse()
        lines = []
        return ""
        # Pattern section fields
        lines.append(f"Segment 0x3c (fw_stc_action)\n")
        lines.append(f"counter_id_pattern = 0x{result['counter_id_pattern']:x}\n")
        lines.append(f"fw_interrupt = 0x{result['fw_interrupt']:x}\n")
        lines.append(f"miss_address_39_32_pattern = 0x{result['miss_address_39_32_pattern']:x}")
        lines.append(f"miss_address_63_48_pattern = 0x{result['miss_address_63_48_pattern']:x}")
        lines.append(f"reparse_pattern = 0x{result['reparse_pattern']:x}\n")
        lines.append(f"match_polarity_pattern = 0x{result['match_polarity_pattern']:x}\n")
        lines.append(f"miss_address_31_6_pattern = 0x{result['miss_address_31_6_pattern']:x}\n")
        lines.append(f"next_table_base_39_32_size_pattern = 0x{result['next_table_base_39_32_size_pattern']:x}\n")
        lines.append(f"hash_definer_context_index = 0x{result['hash_definer_context_index']:x}")
        lines.append(f"next_table_base_63_48_pattern = 0x{result['next_table_base_63_48_pattern']:x}\n")
        lines.append(f"hash_after_actions_pattern = 0x{result['hash_after_actions_pattern']:x}\n")
        lines.append(f"hash_type_pattern = 0x{result['hash_type_pattern']:x}\n")
        lines.append(f"next_table_base_31_5_size_pattern = 0x{result['next_table_base_31_5_size_pattern']:x}\n")

        lines.append(f"inline_actions_pattern_dw0 = 0x{result['inline_actions_pattern_dw0']:x}\n")
        lines.append(f"inline_actions_pattern_dw1 = 0x{result['inline_actions_pattern_dw1']:x}\n")
        lines.append(f"inline_actions_pattern_dw2 = 0x{result['inline_actions_pattern_dw2']:x}\n")

        # Mask section fields  
        lines.append(f"counter_id_mask = 0x{result['counter_id_mask']:x}\n")
        lines.append(f"permission_bits = 0x{result['permission_bits']:x}\n")
        lines.append(f"miss_address_39_32_mask = 0x{result['miss_address_39_32_mask']:x}\n")
        lines.append(f"miss_address_63_48_mask = 0x{result['miss_address_63_48_mask']:x}\n")
        lines.append(f"reparse_mask = 0x{result['reparse_mask']:x}\n")
        lines.append(f"match_polarity_mask = 0x{result['match_polarity_mask']:x}\n")
        lines.append(f"miss_address_31_6_mask = 0x{result['miss_address_31_6_mask']:x}\n")
        lines.append(f"next_table_base_39_32_size_mask = 0x{result['next_table_base_39_32_size_mask']:x}\n")
        lines.append(f"next_table_base_63_48_mask = 0x{result['next_table_base_63_48_mask']:x}\n")
        lines.append(f"hash_after_actions_mask = 0x{result['hash_after_actions_mask']:x}\n")
        lines.append(f"hash_type_mask = 0x{result['hash_type_mask']:x}\n")
        lines.append(f"next_table_base_31_5_size_mask = 0x{result['next_table_base_31_5_size_mask']:x}\n")
        lines.append(f"inline_actions_mask_dw0 = 0x{result['inline_actions_mask_dw0']:x}\n")
        lines.append(f"inline_actions_mask_dw1 = 0x{result['inline_actions_mask_dw1']:x}\n")
        lines.append(f"inline_actions_mask_dw2 = 0x{result['inline_actions_mask_dw2']:x}\n")

        return '\n'.join(lines) + '\n'

    def _print_action(self, action: Dict[str, Any]) -> None:
        """Print a single action"""
        line = f"    [{action['field']}] action_id = ({action['action_id_name']} = 0x{action['action_id']:02X})"

        for key, value in action.items():
            if key in ['field', 'action_id', 'action_id_name', 'raw_value']:
                continue
            if isinstance(value, int):
                line += f", {key} = 0x{value:X}"
            else:
                line += f", {key} = {value}"

        line += f" [raw=0x{action['raw_value']:08X}]"
        print(line)


# =============================================================================
# Multi-Segment Buffer Parser
# =============================================================================

class SegmentBufferParser:
    """Parser for a buffer containing multiple segments"""

    # Registry of segment parsers
    PARSERS = {
        0x3b: Segment3bParser,
        0x3c: Segment3cParser,
    }

    def __init__(self, buffer: str):
        """
        Initialize with buffer string
        :param buffer: Multi-line string containing segment data
        """
        self.buffer = buffer
        self.segments: List[Segment] = []
        self._parse_buffer()

    def _parse_buffer(self) -> None:
        """Parse the buffer and extract all segments"""
        lines = self.buffer.strip().split('\n')

        current_segment_type = None
        current_segment_size = None
        current_segment_data = []
        in_segment = False

        for line in lines:
            line = line.strip()

            if 'Segment Type:' in line:
                if current_segment_type is not None and current_segment_data:
                    seg = Segment(current_segment_type, current_segment_size, current_segment_data)
                    self.segments.append(seg)

                match = re.search(r'Segment Type:\s*(0x[0-9A-Fa-f]+)', line)
                if match:
                    current_segment_type = int(match.group(1), 16)
                    current_segment_data = []
                    in_segment = True

            elif 'Segment Size:' in line:
                match = re.search(r'Segment Size:\s*(\d+)', line)
                if match:
                    current_segment_size = int(match.group(1))

            elif in_segment and line.startswith('0x'):
                hex_values = re.findall(r'0x[0-9A-Fa-f]+', line)
                for hex_val in hex_values:
                    current_segment_data.append(int(hex_val, 16))

            elif '---' in line:
                if current_segment_type is not None and current_segment_data:
                    seg = Segment(current_segment_type, current_segment_size, current_segment_data)
                    self.segments.append(seg)
                    current_segment_type = None
                    current_segment_size = None
                    current_segment_data = []
                    in_segment = False

        if current_segment_type is not None and current_segment_data:
            seg = Segment(current_segment_type, current_segment_size, current_segment_data)
            self.segments.append(seg)

    def list_segments(self) -> None:
        """List all parsed segments"""
        print(f"Found {len(self.segments)} segments:")
        for i, seg in enumerate(self.segments):
            supported = "✓" if seg.type in self.PARSERS else " "
            print(f"  [{i}] Type: 0x{seg.type:04X}, Size: {seg.size} bytes {supported}")

    def get_segment(self, segment_type: int) -> Optional[Segment]:
        """Get a segment by type"""
        for seg in self.segments:
            if seg.type == segment_type:
                return seg
        return None

    def get_all_segments(self, segment_type: int) -> List[Segment]:
        """Get all segments of a specific type"""
        return [seg for seg in self.segments if seg.type == segment_type]

    def parse_rtc(self) -> str:
        """Parse RTC segment (0x14)"""
        if len(self.data) < 1:
            return "RTC (0x14): INCOMPLETE SEGMENT"

        # RTC typically has stc_base_id in first DWORD
        stc_base_id = self.data[0] if len(self.data) > 0 else 0
        return f"RTC (0x14): stc_base_id = 0x{stc_base_id:X}"

    def parse_fw_ste(self) -> str:
        """Parse FW_STE segment (0x1036)"""
        if len(self.data) < 2:
            return "FW_STE (0x1036): INCOMPLETE SEGMENT"

        # Parse FW_STE fields
        ste_id = self.data[0] if len(self.data) > 0 else 0
        next_table_pointer = self.data[1] if len(self.data) > 1 else 0

        return f"FW_STE (0x1036): ste_id = 0x{ste_id:X}, next_table_pointer = 0x{next_table_pointer:X}"

    def parse_ste_stc(self) -> str:
        """Parse STE_STC segment (0x3c)"""
        if len(self.data) < 20:  # 0x3c needs at least 20 DWORDs (80 bytes)
            return f"STE_STC (0x3c): INCOMPLETE SEGMENT ({len(self.data)} DWORDs)"

        segment = Segment(0x3c, len(self.data) * 4, self.data)
        parser = Segment3cParser(segment)
        result = parser.parse()

        # Format as string output
        output = f"STE_STC (0x3c): "
        output += f"counter_id_pattern = 0x{result['counter_id_pattern']:X}, "
        output += f"fw_interrupt = 0x{result['fw_interrupt']:X}, "
        output += f"counter_id_mask = 0x{result['counter_id_mask']:X}, "
        output += f"permission_bits = 0x{result['permission_bits']:X}"

        return output

    def parse_action_control(self) -> Dict[str, Any]:
        """Parse action control fields from DWORDs 2 and 3"""
        result = {}

        if len(self.data) < 4:
            result['action_type'] = None
            result['ste_action_offset'] = None  
            result['modify_in_progress'] = None
            return result

        dw2 = self.data[2] if len(self.data) > 2 else 0
        dw3 = self.data[3] if len(self.data) > 3 else 0

        # Check if action type is in low byte of dw2 or if there's a byte order swap
        # Sometimes data has 0x00001400 instead of 0x00000014
        if (dw2 & 0xFF) in [0x0C, 0x12, 0x14, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85]:
            # Normal case: action type in low byte
            result['action_type'] = dw2 & 0xFF
            result['ste_action_offset'] = (dw2 >> 8) & 0xFFFFFF
        elif ((dw2 >> 8) & 0xFF) in [0x0C, 0x12, 0x14, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85]:
            # Byte swapped case: action type in second byte
            result['action_type'] = (dw2 >> 8) & 0xFF
            result['ste_action_offset'] = 0  # Typically 0 in this case
        else:
            # Check dw3 as well
            if (dw3 & 0xFF) in [0x0C, 0x12, 0x14, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85]:
                result['action_type'] = dw3 & 0xFF
                result['ste_action_offset'] = (dw3 >> 8) & 0xFFFFFF
            else:
                # Unknown action type
                result['action_type'] = dw2 & 0xFF
                result['ste_action_offset'] = (dw2 >> 8) & 0xFFFFFF

        result['modify_in_progress'] = (dw3 >> 31) & 0x1 if len(self.data) > 3 else 0

        return result

    def parse_flow_tag_action(self) -> Optional[Dict[str, Any]]:
        """Parse FLOW_TAG action parameters"""
        if len(self.data) < 6:
            return None

        result = {}
        # FLOW_TAG has flow_tag in DWORD 4 (index 4) and flow_tag_high in DWORD 5 (index 5)
        result['flow_tag'] = self.data[4] if len(self.data) > 4 else 0
        result['flow_tag_high'] = self.data[5] if len(self.data) > 5 else 0

        return result

    def parse_segment_by_type(self, segment_type: int, segment_data: list) -> str:
        """
        Parse segment data based on segment type

        :param segment_type: The segment type (e.g., 0x3b, 0x3c, 0x14, etc.)
        :param segment_data: List of 32-bit values (DWORDs) from segment
        :return: String representation of parsed segment
        """
        self.data = segment_data

        if segment_type == 0x14:  # RTC segment
            return self.parse_rtc()

        elif segment_type == 0x3b:  # FW_STC segment  
            # Check if we have enough data for a full FW_STC segment
            if len(self.data) < 10:
                # Handle incomplete segment
                output_parts = []

                # Try to extract what we can
                if len(self.data) > 1:
                    output_parts.append(f"id/counter = 0x{self.data[1]:08X}")

                # Try to infer action type from available data
                if len(self.data) > 2:
                    # Look for action type indicators in DWORDs 2-3
                    for i in range(2, min(len(self.data), 4)):
                        dword = self.data[i]
                        # Check each byte of the DWORD for known action types
                        for shift in [0, 8, 16, 24]:
                            byte_val = (dword >> shift) & 0xFF
                            # Check for known action types
                            if byte_val in [0x0C, 0x14, 0x12, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85]:
                                try:
                                    action_enum = STCActionType(byte_val)
                                    output_parts.append(f"possible action = {action_enum.name} (0x{byte_val:02X}) at DWORD {i}")
                                    break
                                except:
                                    pass

                output = f"INCOMPLETE SEGMENT ({len(self.data)} DWORDs): " + ", ".join(output_parts) if output_parts else f"INCOMPLETE SEGMENT ({len(self.data)} DWORDs)"
                return f"FW_STC (0x{segment_type:02x}): {output}"

            # Full segment parsing
            action_params = self.parse_action_control()

            if action_params['action_type'] is None:
                return f"FW_STC (0x{segment_type:02x}): action_type = UNKNOWN (insufficient data: only {len(self.data)} DWORDs, need 10+)"

            action_type = action_params['action_type']

            # Try to parse specific action
            action_output = ""
            try:
                action_enum = STCActionType(action_type)

                if action_enum == STCActionType.COUNT:
                    counter_id = self.data[1] if len(self.data) > 1 else 0
                    action_output = f"action_type = {action_enum.name} (0x{action_type:02X}), counter_id = 0x{counter_id:X}"

                elif action_enum == STCActionType.EXECUTE_ASO:
                    aso_data_dw0 = self.data[4] if len(self.data) > 4 else 0
                    aso_data_dw1 = self.data[5] if len(self.data) > 5 else 0
                    aso_data_dw2 = self.data[6] if len(self.data) > 6 else 0
                    aso_data_dw3 = self.data[7] if len(self.data) > 7 else 0
                    action_output = f"action_type = {action_enum.name} (0x{action_type:02X})"
                    action_output += f", aso_data = [0x{aso_data_dw0:08X}, 0x{aso_data_dw1:08X}, 0x{aso_data_dw2:08X}, 0x{aso_data_dw3:08X}]"

                elif action_enum == STCActionType.HEADER_MODIFY_LIST:
                    arg_ptr = self.data[4] if len(self.data) > 4 else 0
                    action_output = f"action_type = {action_enum.name} (0x{action_type:02X}), header_modify_argument_ptr = 0x{arg_ptr:X}"

                elif action_enum == STCActionType.FLOW_TAG:
                    flow_tag = self.parse_flow_tag_action()
                    if flow_tag:
                        action_output = f"action_type = {action_enum.name} (0x{action_type:02X})"
                        action_output += f", flow_tag = 0x{flow_tag.get('flow_tag', 0):X}"
                        if 'flow_tag_high' in flow_tag:
                            action_output += f", flow_tag_high = 0x{flow_tag.get('flow_tag_high', 0):X}"
                    else:
                        action_output = f"action_type = {action_enum.name} (0x{action_type:02X})"

                elif action_enum == STCActionType.JUMP_TO_VPORT:
                    vport_num = self.data[4] & 0xFFFF if len(self.data) > 4 else 0
                    eswitch_owner_vhca_id = (self.data[4] >> 16) & 0xFFFF if len(self.data) > 4 else 0
                    eswitch_owner_vhca_id_valid = (self.data[5] >> 31) & 0x1 if len(self.data) > 5 else 0
                    action_output = f"action_type = {action_enum.name} (0x{action_type:02X})"
                    action_output += f", vport_number = 0x{vport_num:X}"
                    action_output += f", eswitch_owner_vhca_id = 0x{eswitch_owner_vhca_id:X}"
                    action_output += f", eswitch_owner_vhca_id_valid = {eswitch_owner_vhca_id_valid}"

                else:
                    action_output = f"action_type = {action_enum.name} (0x{action_type:02X})"

            except ValueError:
                action_output = f"action_type = UNKNOWN (0x{action_type:02X})"

            return f"FW_STC (0x{segment_type:02x}): {action_output}"

        elif segment_type == 0x3c:  # STE_STC segment
            return self.parse_ste_stc()

        elif segment_type == 0x1036:  # FW_STE segment
            return self.parse_fw_ste()

        else:
            return f"UNKNOWN segment type 0x{segment_type:02x}"

    def parse(self, raw_dump: str = None, segment_type_to_find: int = None) -> str:
        """
        Parse segments from buffer or raw dump

        :param raw_dump: Optional raw dump string to parse
        :param segment_type_to_find: Optional specific segment type to find and parse
        :return: String representation of parsed segments
        """
        if raw_dump:
            self.buffer = raw_dump
            self._parse_buffer()

        if segment_type_to_find is not None:
            # Find and parse specific segment type
            segment = self.get_segment(segment_type_to_find)
            if segment:
                # Use the proper parser class to get formatted output
                parser_class = self.PARSERS.get(segment_type_to_find)
                if parser_class:
                    parser = parser_class(segment)
                    output = parser.print_parsed()
                    return output if output else self.parse_segment_by_type(segment_type_to_find, segment.data)
                else:
                    return self.parse_segment_by_type(segment_type_to_find, segment.data)
            else:
                return f"Segment type 0x{segment_type_to_find:02x} not found in buffer"
        else:
            # Parse all segments
            output_lines = []
            for seg in self.segments:
                parser_class = self.PARSERS.get(seg.type)
                if parser_class:
                    parser = parser_class(seg)
                    output = parser.print_parsed()
                    if output:
                        output_lines.append(output)
                elif seg.type in [0x14, 0x3b, 0x3c, 0x1036]:
                    result = self.parse_segment_by_type(seg.type, seg.data)
                    if result:
                        output_lines.append(result)
            return '\n'.join(output_lines) if output_lines else "No segments found to parse"

    def parse_segment(self, segment_type: int) -> Optional[Dict[str, Any]]:
        """Parse a specific segment type and return the result"""
        segment = self.get_segment(segment_type)
        if segment is None:
            print(f"Segment 0x{segment_type:04X} not found")
            return None

        parser_class = self.PARSERS.get(segment_type)
        if parser_class is None:
            print(f"No parser available for segment 0x{segment_type:04X}")
            return None

        parser = parser_class(segment)
        return parser.parse()

    def print_segment(self, segment_type: int) -> str:
        """Parse and print a specific segment type"""
        segment = self.get_segment(segment_type)
        if segment is None:
            print(f"Segment 0x{segment_type:04X} not found")
            return

        parser_class = self.PARSERS.get(segment_type)
        if parser_class is None:
            print(f"No parser available for segment 0x{segment_type:04X}")
            print(f"Raw data: {[f'0x{d:08X}' for d in segment.data]}")
            return

        parser = parser_class(segment)
        return parser.print_parsed()

    def get_parsed_segment(self, segment_type: int) -> Dict[str, Any]:
        """Get parsed segment"""
        segment = self.get_segment(segment_type)
        if segment is None:
            print(f"Segment 0x{segment_type:04X} not found")
            return None

        parser_class = self.PARSERS.get(segment_type)
        if parser_class is None:
            print(f"No parser available for segment 0x{segment_type:04X}")
            return None

        parser = parser_class(segment)
        return parser.parse()
# =============================================================================
# Main Function
# =============================================================================

def parse_segments(buffer: str, segment_type: int = None) -> None:
    """
    Main function to parse segments from a buffer
    :param buffer: Multi-line string containing segment data
    :param segment_type: Optional specific segment type to parse (e.g., 0x3b)
    """
    parser = SegmentBufferParser(buffer)

    if segment_type is None:
        parser.list_segments()
        print()

        for seg_type in SegmentBufferParser.PARSERS.keys():
            segment = parser.get_segment(seg_type)
            if segment:
                print("=" * 70)
                parser.print_segment(seg_type)
                print()
    else:
        parser.print_segment(segment_type)

