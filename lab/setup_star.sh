#!/bin/bash

# 拓扑：1 个 router 居中，4 个 host 各自连到 router 的一个端口（星形）。
#   host1-eth0(10.0.0.1) --- router-eth0
#   host2-eth0(10.0.0.2) --- router-eth1
#   host3-eth0(10.0.0.3) --- router-eth2
#   host4-eth0(10.0.0.4) --- router-eth3
#
# 与基于 socket 的旧实验不同，本实验主机和路由器都通过 libpcap 直接收发原始
# 帧，不依赖内核协议栈，因此无需配置路由 / ARP / 关闭 offload 等。

nodes=(router host1 host2 host3 host4)

# 每条链路： router 端口   router-MAC            host 端口     host-MAC
links=( router router-eth0 66:77:88:00:00:01 host1 host1-eth0 66:77:88:00:00:02 \
        router router-eth1 66:77:88:00:00:03 host2 host2-eth0 66:77:88:00:00:04 \
        router router-eth2 66:77:88:00:00:05 host3 host3-eth0 66:77:88:00:00:06 \
        router router-eth3 66:77:88:00:00:07 host4 host4-eth0 66:77:88:00:00:08 )

# 主机 IP（router 端口不配 IP，避免内核插手 253 号协议分组）
ips=(host1-eth0 10.0.0.1/24 \
     host2-eth0 10.0.0.2/24 \
     host3-eth0 10.0.0.3/24 \
     host4-eth0 10.0.0.4/24 )

setup() {
    for node in ${nodes[@]}; do
        echo "Creating and starting $node"
        docker container create --cap-add NET_ADMIN --name $node -v $(pwd):/app node
        docker container start $node
    done

    for ((i=0; i<${#links[@]}; i+=6)); do
        c1=${links[i]};   v1=${links[i+1]}; m1=${links[i+2]}
        c2=${links[i+3]}; v2=${links[i+4]}; m2=${links[i+5]}
        echo "Link $c1($v1) <-> $c2($v2)"
        sudo ip link add $v1 type veth peer name $v2
        sudo ip link set $v1 address $m1
        sudo ip link set $v2 address $m2
        sudo ip link set $v1 netns $(docker inspect -f '{{.State.Pid}}' $c1)
        sudo ip link set $v2 netns $(docker inspect -f '{{.State.Pid}}' $c2)
        sudo docker exec $c1 ip link set $v1 up
        sudo docker exec $c2 ip link set $v2 up
    done

    for ((i=0; i<${#ips[@]}; i+=2)); do
        iface=${ips[i]}; addr=${ips[i+1]}; container=${iface%-*}
        echo "Configuring $iface = $addr in $container"
        sudo docker exec $container ip addr add $addr dev $iface
    done
}

clean() {
    for node in ${nodes[@]}; do
        echo remove $node
        docker container rm -f $node
    done
}

case "$1" in
    setup) setup ;;
    clean) clean ;;
    *) echo "Usage: $0 {setup|clean}"; exit 1 ;;
esac
