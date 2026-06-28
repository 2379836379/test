# In-Network AllReduce Only

当前目录已经收口为单一功能版本，只保留 `allreduce` 路径。

约定模型：
- 4 个主机 + 1 个中心交换节点
- 默认单 `block`，`block_id = 0`
- 默认 4 顶点全连接图
- `rank == vertex_id`
- 交换机端运行 `INC()`
- 主机端通过 `m_send()` / `m_recv()` 完成发送、接收、重传和 fetch 恢复

入口：
- `router` 只支持 `allreduce`
- `host` 只支持 `allreduce`
- `main.c` 不再调用旧的 `shift()` / `allreduce()` 包装函数

构建与测试：
```bash
make
make test_allreduce
```

拓扑管理：
```bash
make setup_topo
make clean_topo
```
