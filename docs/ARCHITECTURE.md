# proxytun 技术架构

**简体中文** · [English](ARCHITECTURE_en.md)

> 面向使用者和后续研发人员。读完应当能回答：程序的一次连接从发出到抵达代理，中间经过了什么;每个模块负责什么;
> 哪些设计是被内核或安全约束逼出来的，改动前要小心。
>
> **阅读顺序建议**:第一次接触网络命名空间、TUN 的读者先读[第 0 节](architecture/primer.md)和术语表;
> 只想知道"数据怎么流"的从[第 1 节](architecture/overview.md)读到第 3 节;要改代码的再从[第 4 节](architecture/modules.md)读到第 8 节;
> 做部署或安全评估的读[第 5 节](architecture/privilege.md)。每项设计取舍的理由集中在 [DESIGN.md](DESIGN.md)。

正文按章节分成下面几篇，每篇开头有同样的导航。为了让图表都能正常渲染，每篇最多三张图。

| 篇 | 章节 | 内容 |
|---|---|---|
| [入门](architecture/primer.md) | 0 | 网络命名空间、user namespace、挂载命名空间、TUN、用户态地址改写、用到的其他内核机制、术语表 |
| [总览](architecture/overview.md) | 1–2 | 要解决的问题、总体架构(进程、线程与共享状态) |
| [核心流程](architecture/flow.md) | 3.0–3.2 | 几种地址、启动流程、一次 HTTPS 访问的完整时序 |
| [流程细节](architecture/flow-details.md) | 3.3–3.6 | TUN 上每个包的处理、地址改写表与条目状态、中继判定与嗅探、主机端口转发、假 DNS |
| [模块](architecture/modules.md) | 4 | 两个 crate、各模块职责、共享状态与线程 |
| [运行模式与 sudo 助手](architecture/privilege.md) | 5 | userns / sudo / root 三种模式、sudo 助手的流程与安全边界、安装要求 |
| [进程、信号与生命周期](architecture/lifecycle.md) | 6 | 进程树与见证进程、信号转发、退出、被忽略的信号与 SIGPIPE、日志写入 |
| [负载均衡与运维](architecture/operations.md) | 7–8 | 节点选择、握手失败分类与故障转移、健康检查、热加载、统计、日志、各类上限与耗尽时的行为 |

其他文档:

| 文档 | 内容 |
|---|---|
| [CONFIG.md](CONFIG.md) | 每个配置项的说明、默认值、生效方式、示例与常见报错 |
| [PERFORMANCE.md](PERFORMANCE.md) | 性能测试方法、结果与分析 |
| [DESIGN.md](DESIGN.md) | 设计决策与理由 |
| [CENTOS7.md](CENTOS7.md) | 在 CentOS 7 真机上验证 sudo 模式的步骤 |
