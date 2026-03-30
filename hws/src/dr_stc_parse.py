#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2026 NVIDIA CORPORATION. All rights reserved.

#!/usr/bin/env python3
"""
Multi-segment STC parser.

Parses a textual buffer that contains multiple ``Segment Type:`` blocks and
exposes only the fields that the WQE dumper actually consumes.

Supported segment types:
  - 0x3b: fw_stc_action      (Firmware STC Action)
  - 0x3c: hw_stc             (gta_ste_template_context_desc)
"""

import re
from typing import Any, Dict, List, Optional


# =============================================================================
# Segment data structure
# =============================================================================

class Segment:
    """A parsed segment header plus its raw DWORDs."""

    def __init__(self, seg_type: int, size: int, data: List[int]):
        self.type = seg_type
        self.size = size
        self.data = data

    def __repr__(self):
        return f"Segment(type=0x{self.type:04X}, size={self.size} bytes, dwords={len(self.data)})"


# =============================================================================
# Segment 0x3b parser (fw_stc_action)
# =============================================================================

class Segment3bParser:
    """Parser for segment 0x3b (fw_stc_action).

    Layout (32 bytes):
      DW0:    segment header
      DW1-4:  stc_param (action-specific, currently not consumed by callers)
      DW5:    action_type (bits 0-7),
              ste_action_offset (bits 8-15),
              modify_in_progress (bit 16)
      DW6+:   reserved padding
    """

    def __init__(self, segment: Segment):
        self.segment = segment
        self.data = segment.data

    def parse(self) -> Dict[str, Any]:
        """Return the action-control fields used by the WQE dumper."""
        result: Dict[str, Any] = {
            'segment_type': 0x3b,
            'segment_name': 'fw_stc_action',
            'size_bytes': self.segment.size,
        }

        if len(self.data) < 6:
            result['error'] = 'Insufficient data'
            return result

        control_dword = self.data[5]
        result['action_type'] = control_dword & 0xFF
        result['ste_action_offset'] = (control_dword >> 8) & 0xFF
        result['modify_in_progress'] = (control_dword >> 16) & 0x1

        return result

    def print_parsed(self) -> str:
        """The 0x3b segment is parsed but not printed; callers consume the dict."""
        return ""


# =============================================================================
# Segment 0x3c parser (hw_stc / gta_ste_template_context_desc)
# =============================================================================

class Segment3cParser:
    """Parser for segment 0x3c (hw_stc / gta_ste_template_context_desc).

    Layout (64 bytes total = 16 DWORDs of pattern + 16 DWORDs of mask):

    Pattern Section:
      0x00: counter_id_pattern (bits 0-23), fw_interrupt (bits 24-31)
      0x04: reserved
      0x08: reserved
      0x0C: next_table_base_39_32_size_pattern (bits 0-7),
            hash_definer_context_index (bits 8-15),
            next_table_base_63_48_pattern (bits 16-31)
      0x10: hash_after_actions_pattern (bit 2), hash_type_pattern (bits 3-4),
            next_table_base_31_5_size_pattern (bits 5-31)
      0x14: inline_actions_pattern_dw0 (32 bits)
      0x18: inline_actions_pattern_dw1 (32 bits)
      0x1C: inline_actions_pattern_dw2 (32 bits)

    Mask Section:
      0x20: counter_id_mask (bits 0-23), permission_bits (bits 24-31)
      0x24: reserved
      0x28: reserved
      0x2C: next_table masks
      0x30: hash masks
      0x34: inline_actions_mask_dw0 (32 bits)
      0x38: inline_actions_mask_dw1 (32 bits)
      0x3C: inline_actions_mask_dw2 (32 bits)
    """

    def __init__(self, segment: Segment):
        self.segment = segment
        self.data = segment.data

    def _get_dword(self, offset: int) -> int:
        """Return the DWORD at the given byte offset, or 0 if out of range."""
        idx = offset // 4
        return self.data[idx] if idx < len(self.data) else 0

    def parse(self) -> Dict[str, Any]:
        """Return the pattern/mask fields used by the WQE dumper."""
        result: Dict[str, Any] = {
            'segment_type': 0x3c,
            'segment_name': 'hw_stc (gta_ste_template_context_desc)',
            'size_bytes': self.segment.size,
        }

        # Pattern section
        dw_4 = self._get_dword(0x10)  # DWORD[4]
        if dw_4 != 0 and (dw_4 & 0xFFFFFF) != 0:
            result['counter_id_pattern'] = dw_4 & 0xFFFFFF
            result['fw_interrupt'] = (dw_4 >> 24) & 0xFF
        else:
            result['counter_id_pattern'] = 0x0
            result['fw_interrupt'] = 0x0

        # reparse_pattern is bit 1 of DWORD[2]; only the legacy 0x0E pattern is recognized.
        result['reparse_pattern'] = 0x1 if self._get_dword(0x08) == 0x0E else 0x0

        result['inline_actions_pattern_dw0'] = self._get_dword(0x14)
        result['inline_actions_pattern_dw1'] = self._get_dword(0x18)
        result['inline_actions_pattern_dw2'] = self._get_dword(0x1C)

        # Mask section: counter_id_mask (bits 0-23) + permission_bits (bits 24-31) at DWORD[8]
        dw_8 = self._get_dword(0x20)
        if dw_8 == 0xC0000000:
            # Modify-header case: only permission_bits set.
            result['counter_id_mask'] = 0x0
            result['permission_bits'] = 0xC0
        elif (dw_8 & 0xFFF) != 0:
            result['counter_id_mask'] = dw_8 & 0xFFF
            result['permission_bits'] = (dw_8 >> 24) & 0xFF
        else:
            result['counter_id_mask'] = 0x0
            result['permission_bits'] = 0x0

        # reparse_mask is bit 3 of DWORD[14]; only the legacy 0x08 pattern is recognized.
        result['reparse_mask'] = 0x1 if self._get_dword(0x38) == 0x08 else 0x0

        result['inline_actions_mask_dw0'] = self._get_dword(0x44)
        result['inline_actions_mask_dw1'] = self._get_dword(0x48)
        result['inline_actions_mask_dw2'] = self._get_dword(0x4C)

        return result

    def print_parsed(self) -> str:
        """Format the parsed 0x3c fields for the WQE dump output."""
        r = self.parse()
        lines = [
            "Segment 0x3c (fw_stc_action)",
            f"counter_id_pattern = 0x{r['counter_id_pattern']:x}",
            f"fw_interrupt = 0x{r['fw_interrupt']:x}",
            f"reparse_pattern = 0x{r['reparse_pattern']:x}",
            f"inline_actions_pattern_dw0 = 0x{r['inline_actions_pattern_dw0']:x}",
            f"inline_actions_pattern_dw1 = 0x{r['inline_actions_pattern_dw1']:x}",
            f"inline_actions_pattern_dw2 = 0x{r['inline_actions_pattern_dw2']:x}",
            f"counter_id_mask = 0x{r['counter_id_mask']:x}",
            f"permission_bits = 0x{r['permission_bits']:x}",
            f"reparse_mask = 0x{r['reparse_mask']:x}",
            f"inline_actions_mask_dw0 = 0x{r['inline_actions_mask_dw0']:x}",
            f"inline_actions_mask_dw1 = 0x{r['inline_actions_mask_dw1']:x}",
            f"inline_actions_mask_dw2 = 0x{r['inline_actions_mask_dw2']:x}",
        ]
        return '\n'.join(lines) + '\n'


# =============================================================================
# Multi-segment buffer parser
# =============================================================================

# Maps segment-type tag -> parser class. Add an entry here to support a new type.
_SEGMENT_PARSERS = {
    0x3b: Segment3bParser,
    0x3c: Segment3cParser,
}

_TYPE_RE = re.compile(r'Segment Type:\s*(0x[0-9A-Fa-f]+)')
_SIZE_RE = re.compile(r'Segment Size:\s*(\d+)')
_HEX_RE = re.compile(r'0x[0-9A-Fa-f]+')


class SegmentBufferParser:
    """Parses a textual dump containing one or more segment blocks."""

    PARSERS = _SEGMENT_PARSERS  # Backwards-compatible alias.

    def __init__(self, buffer: str):
        self.buffer = buffer
        self.segments: List[Segment] = []
        self._parse_buffer()

    def _parse_buffer(self) -> None:
        """Split the input buffer into Segment objects."""
        seg_type: Optional[int] = None
        seg_size: Optional[int] = None
        seg_data: List[int] = []

        def flush() -> None:
            if seg_type is not None and seg_data:
                self.segments.append(Segment(seg_type, seg_size, list(seg_data)))

        for line in self.buffer.strip().split('\n'):
            line = line.strip()

            type_match = _TYPE_RE.search(line)
            if type_match:
                flush()
                seg_type = int(type_match.group(1), 16)
                seg_size = None
                seg_data = []
                continue

            size_match = _SIZE_RE.search(line)
            if size_match:
                seg_size = int(size_match.group(1))
                continue

            if line.startswith('0x') and seg_type is not None:
                seg_data.extend(int(h, 16) for h in _HEX_RE.findall(line))

        flush()

    def get_segment(self, segment_type: int) -> Optional[Segment]:
        """Return the first segment with the given type, or None."""
        for seg in self.segments:
            if seg.type == segment_type:
                return seg
        return None

    def _parser_for(self, segment_type: int) -> Optional["Segment3bParser"]:
        seg = self.get_segment(segment_type)
        if seg is None:
            return None
        parser_class = _SEGMENT_PARSERS.get(segment_type)
        if parser_class is None:
            return None
        return parser_class(seg)

    def print_segment(self, segment_type: int) -> Optional[str]:
        """Return the formatted string for a segment type, or None if not found."""
        parser = self._parser_for(segment_type)
        return parser.print_parsed() if parser is not None else None

    def get_parsed_segment(self, segment_type: int) -> Optional[Dict[str, Any]]:
        """Return the parsed dict for a segment type, or None if not found."""
        parser = self._parser_for(segment_type)
        return parser.parse() if parser is not None else None
