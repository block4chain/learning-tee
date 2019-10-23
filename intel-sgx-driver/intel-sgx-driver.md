---
description: EPC是系统内存的一部分，这部分内存只允许Enclave内的代码访问，系统代码或用户代码都无法访问。Intel SGX驱动程序负责管理这部分内存。
---

# EPC管理

## EPC块

EPC位于系统内存的固定区域 ，可以通过CPUID指令获得。Intel处理器将EPC内存划分为多个块，每个块在驱动程序中用一个`epc_bank`表示

{% code-tabs %}
{% code-tabs-item title="sgx.h" %}
```c
struct sgx_epc_bank {
	unsigned long pa;
#ifdef CONFIG_X86_64
	unsigned long va;
#endif
	unsigned long size;
};
```
{% endcode-tabs-item %}
{% endcode-tabs %}

在驱动程序初始化时会探测和注册EPC内存块:

{% code-tabs %}
{% code-tabs-item title="sgx\_main.c" %}
```c
static int sgx_dev_init(struct device *parent)
{
	//省略部分代码
	//SGX_MAX_EPC_BANKS:8 
    for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC_BANKS, &eax, &ebx,
			    &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);  //物理地址起始位置
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);  //EPC内存块大小
		
		sgx_epc_banks[i].pa = pa;
		sgx_epc_banks[i].size = size;
	}
	sgx_nr_epc_banks = i;   //EPC内存块个数
	//注册EPC内存块
	for (i = 0; i < sgx_nr_epc_banks; i++) {
#ifdef CONFIG_X86_64
		sgx_epc_banks[i].va = (unsigned long)
			ioremap_cache(sgx_epc_banks[i].pa,sgx_epc_banks[i].size);
		if (!sgx_epc_banks[i].va) {
			sgx_nr_epc_banks = i;
			ret = -ENOMEM;
			goto out_iounmap;
		}
#endif
		ret = sgx_add_epc_bank(sgx_epc_banks[i].pa,sgx_epc_banks[i].size, i);
		if (ret) {
			sgx_nr_epc_banks = i + 1;
			goto out_iounmap;
		}
	}
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

