#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2026 NVIDIA CORPORATION. All rights reserved.

from typing import Union, List, Optional, TYPE_CHECKING
import struct
import threading

# Import constants and WQE classes
from src.dr_common import *

if TYPE_CHECKING:
    from src.dr_wqe import dr_wqe

# Constants from dr_wqe.py that we need
SEND_WQE_OPCODE_TBL_ACCESS = 0x2c
SEND_WQE_OPCODE_ACCESS_ASO = 0x2d
SEND_WQE_OPMOD_GTA_STE = 0
SEND_WQE_OPMOD_GTA_MOD_ARG = 1

class WQEParserFactory:
    """
    Singleton factory class for creating WQE parsers.

    This class implements the Singleton pattern to ensure only one instance
    of the factory exists throughout the application lifetime.
    """

    _instance: Optional["WQEParserFactory"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "WQEParserFactory":
        """
        Create or return the singleton instance of WQEParserFactory.

        This method is thread-safe and ensures only one instance is created.
        """
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking pattern
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """
        Initialize the factory instance.

        This initialization only happens once due to the _initialized flag.
        """
        if self._initialized:
            return

        self._initialized = True
        # Add any initialization code here if needed
        # For example, you might want to register parser types dynamically
        self._parser_registry = {}

    @classmethod
    def get_instance(cls) -> "WQEParserFactory":
        """
        Alternative way to get the singleton instance.

        Returns:
            The singleton instance of WQEParserFactory
        """
        return cls()

    def get_wqe_parser(self, data: Union[str, List[str]], verbosity: int = 0):
        """
        Create the appropriate WQE parser based on the data.

        This method analyzes the input data and returns the appropriate
        WQE parser subclass instance based on the opcode and opmod values.

        Args:
            data: Either a hex string or a list containing a hex string
            verbosity: Verbosity level for debug output (default 0)

        Returns:
            Appropriate dr_wqe subclass instance

        Raises:
            ValueError: If the data format is invalid
        """
        # Import here to avoid circular dependencies
        from src.dr_wqe import (
            dr_wqe, dr_wqe_match, dr_wqe_gta_arg, dr_wqe_aso, 
            dr_wqe_unknown, WQEGneralCtrlSeg
        )

        # Handle both string and list input
        if isinstance(data, list):
            hex_string = data[0] if len(data) > 0 else ""
        else:
            hex_string = data

        if not hex_string:
            raise ValueError("Empty data provided to WQE parser factory")

        # Convert hex string to bytes
        hex_values = hex_string.split()
        data_bytes = b''
        for hex_val in hex_values:
            try:
                val = int(hex_val, 16)
                data_bytes += val.to_bytes(4, byteorder='little')
            except ValueError as e:
                raise ValueError(f"Invalid hex value in data: {hex_val}") from e

        # Ensure we have exactly 128 bytes for 32 dwords
        if len(data_bytes) < 128:
            # Pad with zeros if we have less than 128 bytes
            data_bytes += b'\x00' * (128 - len(data_bytes))
        elif len(data_bytes) > 128:
            # Truncate if we have more than 128 bytes
            data_bytes = data_bytes[:128]

        # Convert bytes to dwords
        dwords = list(struct.unpack('<32I', data_bytes))

        # Parse the general control segment from dwords
        opmod_idx_opcode = dwords[0]
        opcode = opmod_idx_opcode & 0xFF
        opmod = (opmod_idx_opcode >> 24) & 0xFF
        cur_post = (opmod_idx_opcode >> 8) & 0xFFFF
        qpn_ds = dwords[1] if len(dwords) > 1 else 0
        flags = dwords[2] if len(dwords) > 2 else 0
        imm = dwords[3] if len(dwords) > 3 else 0

        gen_ctrl_seg = WQEGneralCtrlSeg(
            opcode=opcode,
            opmod=opmod,
            cur_post=cur_post,
            flags=flags,
            imm=imm,
            qpn_ds=qpn_ds
        )

        # Select the appropriate parser based on opcode and opmod
        if gen_ctrl_seg.opcode == SEND_WQE_OPCODE_TBL_ACCESS:
            if gen_ctrl_seg.opmod == SEND_WQE_OPMOD_GTA_STE:
                return dr_wqe_match(data_bytes, gen_ctrl_seg, verbosity)
            elif gen_ctrl_seg.opmod == SEND_WQE_OPMOD_GTA_MOD_ARG:
                return dr_wqe_gta_arg(data_bytes, gen_ctrl_seg, verbosity)
            else:
                return dr_wqe_unknown(data_bytes, gen_ctrl_seg, verbosity)
        elif gen_ctrl_seg.opcode == SEND_WQE_OPCODE_ACCESS_ASO:
            return dr_wqe_aso(data_bytes, gen_ctrl_seg, verbosity)
        else:
            return dr_wqe_unknown(data_bytes, gen_ctrl_seg, verbosity)

    def register_parser(self, opcode: int, opmod: Optional[int], parser_class):
        """
        Register a custom parser for a specific opcode/opmod combination.

        This allows for dynamic extension of the factory with new parser types.

        Args:
            opcode: The WQE opcode
            opmod: The WQE opmod (optional, use None for any opmod)
            parser_class: The parser class to use for this combination
        """
        key = (opcode, opmod)
        self._parser_registry[key] = parser_class

    def unregister_parser(self, opcode: int, opmod: Optional[int] = None):
        """
        Unregister a custom parser.

        Args:
            opcode: The WQE opcode
            opmod: The WQE opmod (optional)
        """
        key = (opcode, opmod)
        if key in self._parser_registry:
            del self._parser_registry[key]

    def clear_registry(self):
        """
        Clear all registered custom parsers.
        """
        self._parser_registry.clear()


# Global factory instance getter for convenience
def get_wqe_parser_factory() -> WQEParserFactory:
    """
    Get the global WQE parser factory instance.

    Returns:
        The singleton WQEParserFactory instance
    """
    return WQEParserFactory.get_instance()
