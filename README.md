# mlx_steering_dump_parser
This is Mellanox SW steering dump file parser.

How to trigger a dump.file generation
=====================================
Dump generation is done using rdma-core,
it can be done directly by calling mlx5dv_dump_dr_domain API
or using mlx5_pmd

Dump file example
============
example.csv

Running examples
================
To show steering rules run:<br/>
<pre>mlx_steering_dump_parser.py -f `pwd`/example.csv</pre>
To show steering tree/hierarchy run:<br/>
<pre>mlx_steering_dump_parser.py -f `pwd`/example.csv -t</pre>
To trigger DPDK app run:<br/>
<pre>mlx_steering_dump_parser.py -p &lt;DPDK PID&gt; -f &lt;dump_file&gt;</pre>

Recommended python
==================
Python 2<br/>
Python 3
