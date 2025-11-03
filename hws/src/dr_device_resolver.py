#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2025 NVIDIA CORPORATION. All rights reserved.

"""
Device resolver module for HWS dump tool.
Accepts multiple device identifier formats and resolves to PCI BDF and device names.

Supported input formats:
- MST device: /dev/mst/mt4129_pciconf0
- PCI BDF: 0000:bb:dd.f or bb:dd.f (with or without domain)
- IB device: mlx5_2
- Netdev: enp202s0f0np0, eth0, etc.
"""

import os
import re
import subprocess as sp
from pathlib import Path


class DeviceIdentifier:
    """Holds resolved device identifiers"""

    def __init__(self, pci_bdf, rdma_dev=None, mst_dev=None):
        self.pci_bdf = pci_bdf           # PCI address in 0000:bb:dd.f format
        self.rdma_dev = rdma_dev         # RDMA/IB device name (mlx5_X)
        self.mst_dev = mst_dev           # MST device path

    def __repr__(self):
        return f"DeviceIdentifier(pci={self.pci_bdf}, rdma={self.rdma_dev}, mst={self.mst_dev})"


def _normalize_pci_bdf(bdf):
    """
    Normalize PCI BDF to full format (0000:bb:dd.f)

    Args:
        bdf: PCI address in various formats (bb:dd.f, 0000:bb:dd.f, etc.)
    Returns:
        Normalized PCI BDF string with domain
    """
    # Remove any leading/trailing whitespace
    bdf = bdf.strip()

    # Check if domain is present (format: dddd:bb:dd.f)
    if bdf.count(':') == 2:
        return bdf

    # Add default domain (0000)
    if bdf.count(':') == 1:
        return f"0000:{bdf}"

    raise ValueError(f"Invalid PCI BDF format: {bdf}")


def _detect_device_type(device_str):
    """
    Detect the type of device identifier string.

    Returns: 'mst', 'pci', 'ib', 'netdev', or None
    """
    device_str = device_str.strip()

    # MST device: starts with /dev/mst/
    if device_str.startswith('/dev/mst/'):
        return 'mst'

    # PCI BDF: matches patterns like bb:dd.f or 0000:bb:dd.f
    # Format: [dddd:]bb:dd.f where d=domain digit, b=bus, d=device, f=function
    pci_pattern = r'^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$'
    if re.match(pci_pattern, device_str):
        return 'pci'

    # InfiniBand device: typically mlx5_N
    # Check both pattern and sysfs
    if re.match(r'^mlx\d+_\d+$', device_str):
        if os.path.exists(f'/sys/class/infiniband/{device_str}'):
            return 'ib'

    # Netdev: check if it exists in /sys/class/net/
    if os.path.exists(f'/sys/class/net/{device_str}'):
        return 'netdev'

    return None


def _get_pci_from_mst(mst_device):
    """
    Extract PCI BDF from MST device.
    Uses mst status or parses the device name.
    """
    # Try mst status first
    try:
        status, output = sp.getstatusoutput('mst status -v')
        if status == 0:
            # Parse the formatted output
            # Format: DEVICE_TYPE   MST   PCI   RDMA   NET   NUMA
            lines = output.split('\n')
            for line in lines:
                if mst_device in line and not line.startswith('DEVICE_TYPE'):
                    # Split by whitespace
                    parts = line.split()
                    # Find the MST device in the parts
                    for i, part in enumerate(parts):
                        if part == mst_device:
                            # PCI address should be the next field
                            if i + 1 < len(parts):
                                pci_candidate = parts[i + 1]
                                # PCI might be in short format (no domain): bb:dd.f
                                # Normalize it
                                if re.match(r'^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$', pci_candidate):
                                    return _normalize_pci_bdf(pci_candidate)
                                elif re.match(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$', pci_candidate):
                                    return pci_candidate
                            break
    except Exception:
        pass

    # Fallback: try to parse from device name
    # Format examples: mt4129_pciconf0 might encode PCI info
    # This is hardware-specific and may not always work
    # For now, return None if mst status fails
    return None


def _get_pci_from_sysfs(device_name, device_type):
    """
    Resolve PCI BDF using sysfs for IB devices and netdevs.

    Args:
        device_name: Name of the device (e.g., mlx5_2, eth0)
        device_type: 'ib' or 'netdev'
    Returns:
        PCI BDF string or None
    """
    if device_type == 'ib':
        device_path = f'/sys/class/infiniband/{device_name}/device'
    elif device_type == 'netdev':
        device_path = f'/sys/class/net/{device_name}/device'
    else:
        return None

    # The 'device' is a symlink to the PCI device
    # Example: /sys/class/infiniband/mlx5_2/device -> ../../../0000:bb:dd.f
    try:
        if os.path.islink(device_path):
            # Resolve the symlink
            real_path = os.path.realpath(device_path)
            # Extract PCI BDF from path (last component)
            pci_bdf = os.path.basename(real_path)
            # Validate format
            if re.match(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$', pci_bdf):
                return pci_bdf
    except Exception:
        pass

    return None


def _get_rdma_from_pci(pci_bdf):
    """
    Find RDMA device name from PCI BDF by scanning /sys/class/infiniband/
    """
    try:
        ib_dir = Path('/sys/class/infiniband')
        if not ib_dir.exists():
            return None

        for ib_dev in ib_dir.iterdir():
            if not ib_dev.is_dir():
                continue

            device_link = ib_dev / 'device'
            if device_link.is_symlink():
                real_path = os.path.realpath(device_link)
                if pci_bdf in str(real_path):
                    return ib_dev.name
    except Exception:
        pass

    return None


def _get_mst_from_pci(pci_bdf):
    """
    Find MST device from PCI BDF using mst status.
    """
    try:
        # Normalize the input PCI BDF
        pci_normalized = _normalize_pci_bdf(pci_bdf)
        # Also try short format without domain
        pci_short = pci_normalized.split(':', 1)[1] if ':' in pci_normalized else pci_normalized

        status, output = sp.getstatusoutput('mst status -v')
        if status == 0:
            # Parse the formatted output
            lines = output.split('\n')
            for line in lines:
                # Check for both full and short PCI format in the line
                if pci_normalized in line or pci_short in line:
                    if line.startswith('DEVICE_TYPE'):
                        continue
                    # Split by whitespace
                    parts = line.split()
                    # Find MST device (should start with /dev/mst/)
                    for part in parts:
                        if part.startswith('/dev/mst/'):
                            return part
    except Exception:
        pass

    return None


def _get_rdma_from_mst(mst_device):
    """
    Get RDMA device name from MST device using mst status.
    """
    try:
        status, output = sp.getstatusoutput('mst status -v')
        if status == 0:
            # Parse the formatted output
            lines = output.split('\n')
            for line in lines:
                if mst_device in line and not line.startswith('DEVICE_TYPE'):
                    # Split by whitespace
                    parts = line.split()
                    # Find the MST device in the parts
                    for i, part in enumerate(parts):
                        if part == mst_device:
                            # RDMA device should be 2 fields after MST (MST, PCI, RDMA)
                            if i + 2 < len(parts):
                                rdma_candidate = parts[i + 2]
                                if rdma_candidate != 'NA' and re.match(r'^mlx\d+_\d+$', rdma_candidate):
                                    return rdma_candidate
                            break
    except Exception:
        pass

    return None


def resolve_device(device_str):
    """
    Main function to resolve device identifier to all formats.

    Args:
        device_str: Device identifier in any supported format

    Returns:
        DeviceIdentifier object with resolved values

    Raises:
        ValueError: If device string cannot be resolved
    """
    device_type = _detect_device_type(device_str)

    if device_type is None:
        raise ValueError(f"Unable to detect device type for: {device_str}")

    pci_bdf = None
    rdma_dev = None
    mst_dev = None

    if device_type == 'mst':
        # MST device provided
        mst_dev = device_str
        pci_bdf = _get_pci_from_mst(mst_dev)
        if pci_bdf:
            rdma_dev = _get_rdma_from_pci(pci_bdf)
        else:
            # Try to get RDMA directly from mst status
            rdma_dev = _get_rdma_from_mst(mst_dev)
            if rdma_dev:
                # Try to get PCI from RDMA
                pci_bdf = _get_pci_from_sysfs(rdma_dev, 'ib')

    elif device_type == 'pci':
        # PCI BDF provided
        pci_bdf = _normalize_pci_bdf(device_str)
        rdma_dev = _get_rdma_from_pci(pci_bdf)
        mst_dev = _get_mst_from_pci(pci_bdf)

    elif device_type == 'ib':
        # InfiniBand device provided
        rdma_dev = device_str
        pci_bdf = _get_pci_from_sysfs(device_str, 'ib')
        if pci_bdf:
            mst_dev = _get_mst_from_pci(pci_bdf)

    elif device_type == 'netdev':
        # Network device provided
        pci_bdf = _get_pci_from_sysfs(device_str, 'netdev')
        if pci_bdf:
            rdma_dev = _get_rdma_from_pci(pci_bdf)
            mst_dev = _get_mst_from_pci(pci_bdf)

    # Validate that we at least have PCI BDF
    if pci_bdf is None:
        raise ValueError(f"Unable to resolve PCI BDF for device: {device_str}")

    return DeviceIdentifier(pci_bdf=pci_bdf, rdma_dev=rdma_dev, mst_dev=mst_dev)


def get_device_for_resourcedump(device_str):
    """
    Convenience function to get the best device identifier for resourcedump.

    Resourcedump can accept:
    - PCI BDF (most universal)
    - MST device path

    This function returns PCI BDF as it's the most universal format.

    Args:
        device_str: Device identifier in any supported format

    Returns:
        String suitable for resourcedump -d parameter
    """
    dev_id = resolve_device(device_str)

    # Prefer PCI BDF as it's most universal
    if dev_id.pci_bdf:
        return dev_id.pci_bdf

    # Fallback to MST device if available
    if dev_id.mst_dev:
        return dev_id.mst_dev

    raise ValueError(f"Unable to determine resourcedump device for: {device_str}")
