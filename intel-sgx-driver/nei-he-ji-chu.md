---
description: 驱动程序使用到的一些内核技术
---

# 内核基础

### 数据结构

| 结构体 | 作用 |
| :--- | :--- |
| struct vm\_area\_struct | 代表一个连续的虚拟内存区域 |
| struct mmu\_notifier\_ops | 定义一些回调函数，用于监听进程的内存管理事件 |

### 函数或宏

| 函数或宏 | 作用 |
| :--- | :--- |
| current | 当前的进程 |
| PFN\_DOWN\(x\) | 用来返回小于x的最后一个页面号 |
| PFN\_UP\(x\) | 用来返回大于x的第一个页面号 |
| kmap\_atomic | 高端内存映射，用于紧急的，短时间的映射 |
| void down\_read\(struct rw\_semaphore\* rw\_sem\) | 获取读信号量 |
| void up\_read\(struct rw\_semaphore\* rw\_sem\) | 释放读信号量 |
| find\_vma\(struct mm\_struct \*mm, unsigned long addr\) | 查找包含虚址addr的虚拟内存区域 |
| void mmu\_notifier\_register\(struct mmu\_notifier _mn, struct mm\_struct_ mm\); | 在特定的虚址空间注册内存管理事件回调 |
| kref\_init | 初始化kref的计数值为1 |
| kref\_get | 递增kref的计数值 |
| kref\_put | 递减kref的计数值，如果计数值减为0，说明kref所指向的结构生命周期结束，会执行release释放函数 |
| INIT\_WORK\(\_work, \_func\) | 启动一个处理加页请求的工作线程 |
| task\_tgid | 返回当前进程的TGID |
| get\_pid | 获取进程PID, 并将引用计数+1 |
| put\_pid | 获取进程PID, 并将引用计数-1 |
|  |  |

