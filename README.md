# mlx_steering_dump
This is Mellanox SW steering Dump Tool.

How to trigger a dump.file generation
=====================================
Dump generation is done using rdma-core,
it can be done directly by calling mlx5dv_dump_dr_domain API
or using mlx5_pmd

dump example
============
example.json

Running examples
================
To show steering rules run:
	mlx_steering_dump.py -f `pwd`/example.json<br/>
To show steering tree/hierarchy run:
	mlx_steering_dump.py -f `pwd`/example.json -t<br/>
To trigger DPDK app run for pid=5336 and mlx5_port=0:
	mlx_steering_dump/mlx_steering_dump.py -d 5336 0 -f /tmp/my_json_dump<br/>
To trigger testpmd app:
	mlx_steering_dump.py -d `pgrep testpmd` 0  -f /tmp/my_json_dump -t

Recommended python
==================
Python 3
