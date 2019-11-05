---
description: Enclave内执行代码时上下文安全和保护
---

# 多线程机制

## TCS

Thread Control Structure的简称。在Enclave内执行代码需要关联一个TCS数据结构。每个TCS数据结构实例是4KB对齐。

| 字段 | 偏移 | 大小\(字节\) | 描述 |
| :--- | :--- | :--- | :--- |
| STAGE | 0 | 8 | 执行状态:1代表正在运行；0代表可用 |
| FLAGS | 8 | 8 | 执行标志，参考下文 |
| OSSA | 16 | 8 | 运行栈基址偏移\(相对enclave基址\) |
| CSSA | 24 | 4 | 当前的栈帧位置 |
| NSSA | 28 | 4 | 最大可用的栈帧数 |
| OENTRY | 32 | 8 | 入口地址，相对于Enclave基址偏移 |
| AEP | 40 | 8 | AEP处理程序地址 |
| OFSBASGX | 48 | 8 | enclave内生成fs段地址的偏移\(相对于enclave基址\) |
| OGSBASGX | 56 | 8 | enclave内生成gs段地址的偏移\(相对于enclave基址\) |
| FSLIMIT | 64 | 4 | 32位模式下fs段大小 |
| GSLIMIT | 68 | 4 | 32位模式下gs段大小 |
| RESERVED | 72 | 4024 | 保留，必须是0 |

### 执行标志\(Flag\)

| 字段 | 位 | 描述 |
| :--- | :--- | :--- |
| DBGOPTIN | 0 | 是否处理调试模式，支持单步，断点等 |
| RESERVED | 1-63 | 保留 |

## SSA

STATE SAVE AREA \(SSA\) FRAME的简称。

Enclave执行代码过程中，如果出现一些异常事件需要离开Enclave环境，则会当前处理器的执行上下文保存在SSA帧\(`TCS.CSSA`字段指定的帧\)中。

| 区域 | 偏移 | 大小 | 描述 |
| :--- | :--- | :--- | :--- |
| XSAVE | 0 | 体系结构相关 |  |
| Pad | End of XSAVE region | 开发者选择 | 需要保证GPRSGX区域结尾以4K对齐 |
| MISC | base of GPRSGX  | Calculate from highest set bit of SECS.MISCSELECT |  |
| GPRSGX | SSAFRAMESIZE-176 | 176 |  |

### GPRSGX区域

 包含CPU在执行过程中的上下文: 寄存器等值 

