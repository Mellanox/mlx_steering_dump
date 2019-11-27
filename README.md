# mlx_steering_dump
This is Mellanox SW steering Dump Tool.

How to trigger a dump.file generation
=====================================
Dump generation is done using rdma-core,
it can be done directly by calling mlx5dv_dump_dr_domain API
or using mlx5_pmd

Running examples
================
mlx_steering_dump.py -f /tmp/dump.file

Recommended python
==================
Python 2.6.6 and above
