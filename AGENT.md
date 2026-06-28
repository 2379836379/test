在网计算的核心思想是：把本应在主机端完成的计算（这里是 AllReduce 的“求和”）下沉到交换机/路由器里完成。交换机里有一组“聚合单元”（aggregator），每个单元负责把同一个序列号位置上来自各个成员的载荷累加起来。这要求：
每一个数据分组（packet）的载荷长度，必须与交换机里聚合单元的长度严格一致，且分组与聚合单元一一对应。
本实验的做法：抛弃 socket，改用 libpcap 直接收发二层原始帧（与实验四相同的 IO 模式）， 保留 IP 首部，但在 IP 之上自己实现一个极简的传输协议 MTP。这样应用层对每一个分组的边界和 载荷长度有完全的控制权，聚合单元与分组严格一一对应，在网计算才得以正确实现。

3.4 Reliability and Congestion Control
In-network multicast and aggregation break the traditional
end-to-end connections, where a single packet at the switch
is replicated into multiple packets, and multiple packets are
aggregated back into one packet by the switch. Therefore, we
need to redesign the reliability guarantee and congestion con￾trol mechanisms to ensure correct and efficient transmission.
For reliability guarantee, when a vertex is sent, SwitchGNN
maintains two bitmaps for each vertex to track the status of
its neighbors at the host. One bitmap records the acknowledg￾ment status of the sent vertex features, while the other tracks
the reception status of each vertex’s neighbor features. Upon
receiving the aggregation result, the corresponding reception
bitmap is set to all ones, and the worker multicasts ACKs to
the vertex’s neighbors. When the sending bitmap becomes all
ones, it indicates that the vertex’s transmission has success￾fully completed. When receiving a data packet of a vertex,
the worker first determines whether the packet is a complete
aggregation result from the switch. If a non-aggregated fea￾ture is received, the non-aggregated feature is cached in the
worker. When other boundary vertices in the worker also need
to participate in aggregation with this non-aggregated feature,
they can share it from the local cache instead of fetching it
again from remote workers, thereby reducing network traffic.
Additionally, SwitchGNN employs a timeout mechanism to
handle packet loss caused by network congestion. When a
worker exceeds the timeout threshold without receiving fea￾tures from the current block, it pulls the required features
of the unaggregated vertices from other workers. Once the
pulled packets arrive at the switch, the corresponding aggre￾gators are released. The features pulled from the worker are
marked as "bypass", meaning they no longer participate in
switch-based aggregation but are directly forwarded to the
host for aggregation.
For congestion control, SwitchGNN continuously sends
vertices according to the scheduling order and adjusts the
sending rate according to the Explicit Congestion Notification
(ECN) marking, similar to DCQCN [32]. Upon receiving an
ECN marking, the sending rate is halved. If the network is
not congested, the sending rate increases additively.
4 Implementation
We implement SwitchGNN using Data Plane Development
Kit (DPDK) protocol stack and P4-Programmable switch.
Host. On the host side, SwitchGNN is used as a plugin
integrated with the DGL framework. We modify the commu￾nication context of DGL by using SwitchGNN with DPDK
host stack. In the DPDK, we use rte_pktmbu f _mtod_o f f set
to add SwitchGNN’s header fields after the IP header,
which includes 32bit Src_id, 32bit Dst_id, 16bit Block_id,
16bit Count, 1bit Is_ACK, 1bit Is_Fetch, 1bit ECN, and 1bit
Resend fields. The Src_id and Dst_id fields carry the IDs
of source vertex and destination vertex, respectively. The
Block_id field is used to notice the transmission batch, ensur￾ing that the same block’s features participate in in-network
aggregation in the same batch. The Count field carries the
number of boundary neighbors for the current vertices. The
Is_ACK and Is_Fetch fields are used to identify the type
of packet, indicating whether it is an acknowledgment or a
fetch request, respectively. The ECN field is marked when
the switch queue length exceeds a certain threshold, while the
Resend field is set to 1 for retransmitted packets.
Switch. On the switch, we store the mapping relationship
between each vertex ID and its corresponding aggregator
indexes in the table. When a packet arrives, it can directly
query the table using the source vertex ID to determine which
aggregators should be aggregated at. In SwitchGNN, each
aggregator is allocated 128 bytes for aggregation. The aggre￾gator format is similar to ATP [16]. The difference is that
instead of using a bitmap to track which vertices have been
added in the aggregator, we determine aggregation comple￾tion according to the aggregation count. To avoid errors from
duplicate accumulation due to retransmitted packets, we mark
these packets with a Resend flag. When such a packet reaches
the switch, it releases the corresponding aggregator and is
directly forwarded to the designated worker for aggregation.
To multicast the packet into multiple aggregators, the same
register needs to be accessed multiple times. However, Tofino
switch allows a packet to access a register only once per
pipeline pass. Therefore, after accumulating the payload into
the first aggregator, we loop the packet back to the ingress
240 2025 USENIX Annual Technical Conference USENIX Association
pipeline for subsequent aggregator operations until all multicast aggregators are accessed.
Moreover, SwitchGNN adopts in-network aggregation only
for traffic that crosses hosts or racks, while GPUs within the
same host use NVLink or PCIe for communication. When
workers are distributed across multiple switches, multi-level
aggregation is required. SwitchGNN uses a mechanism similar to existing in-network aggregation solutions [16, 18].
SwitchGNN needs to extend packet headers and aggregator
fields to record the level of each switch. For example, in a twolevel aggregation with three switches, two level-1 switches
perform partial aggregation for directly connected workers,
and their partial aggregation results are then forwarded to a
level-2 switch for final aggregation.