import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.dr_constants import MLX5_HW_CONNECTX_5, MLX5_HW_CONNECTX_6DX
from src.parsers.dr_ste_parser import mlx5_hw_ste_parser

# MPLS label stack entry (RFC 3032): label 0x12345, TC/EXP 5, S 1, TTL 64
LABEL, EXP, BOS, TTL = 0x12345, 5, 1, 0x40
LSE = (LABEL << 12) | (EXP << 9) | (BOS << 8) | TTL


def ste_v1(lu_type, tag):
    # 48 byte reduced STE, BWC format: entry_format is the high byte of the
    # lookup type and match_definer_ctx_idx is the low byte.
    ctrl = "%02x" % (lu_type >> 8) + "00" * 5 + "%02x" % (lu_type & 0xff) + "00" * 25
    return ctrl + tag


def ste_v0(lu_type, tag):
    # 48 byte reduced STE, rx_steering_mult: entry_type 2, entry_sub_type is
    # the lookup type.
    ctrl = "20" + "%02x" % lu_type + "00" * 30
    return ctrl + tag


def parse_tag(nic, ste):
    tag = mlx5_hw_ste_parser(nic, ste, None, True, 0)["tag"]
    return {k: int(v, 16) for k, v in tag.items() if int(v, 16)}


class TestSteV1MplsTag(unittest.TestCase):
    expected = {"mpls0_label": LABEL, "mpls0_exp": EXP,
                "mpls0_s_bos": BOS, "mpls0_ttl": TTL}

    def test_mpls_o(self):
        # mlx5_ifc_ste_mpls_v1_bits: the first label sits in the second dword
        tag = "%08x%08x%08x%08x" % (0, LSE, 0, 0)
        self.assertEqual(parse_tag(MLX5_HW_CONNECTX_6DX, ste_v1(0x010b, tag)),
                         self.expected)

    def test_mpls_i(self):
        tag = "%08x%08x%08x%08x" % (0, LSE, 0, 0)
        expected = {"inner_" + k: v for k, v in self.expected.items()}
        self.assertEqual(parse_tag(MLX5_HW_CONNECTX_6DX, ste_v1(0x010c, tag)),
                         expected)

    def test_mpls_v0(self):
        # mlx5_ifc_ste_mpls_bits: the first label sits in the first dword
        tag = "%08x%08x%08x%08x" % (LSE, 0, 0, 0)
        self.assertEqual(parse_tag(MLX5_HW_CONNECTX_5, ste_v0(0x15, tag)),
                         self.expected)


if __name__ == '__main__':
    unittest.main()
