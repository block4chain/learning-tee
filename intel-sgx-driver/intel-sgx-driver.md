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
	//省略部分代码.....
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## EPC页划分

EPC内存块被划分成多个EPC页，每个页大小是4KB，所有的EPC内存页通过一个链表进行管理。

{% code-tabs %}
{% code-tabs-item title="sgx.h" %}
```c
struct sgx_epc_page {
	resource_size_t	pa;   //页物理起始地址
	struct list_head list;     //EPC页链表表头
	struct sgx_encl_page *encl_page;
};

static LIST_HEAD(sgx_free_list);   //EPC页链表
```
{% endcode-tabs-item %}
{% endcode-tabs %}

在注册EPC Bank时将EPC内存块拆分成多个EPC页:

{% code-tabs %}
{% code-tabs-item title="sgx\_page\_cache.c" %}
```c
int sgx_add_epc_bank(resource_size_t start, unsigned long size, int bank)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);  //生成一个epc内核对象
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = (start + i) | bank;   //设置EPC页起始地址，并将所在的bank记录在地址尾部

		spin_lock(&sgx_free_list_lock);
		list_add_tail(&new_epc_page->list, &sgx_free_list);  //将EPC页添加到空闲链表
		sgx_nr_total_epc_pages++;  //EPC页总数+1
		sgx_nr_free_pages++;  //EPC空闲页数+1
		spin_unlock(&sgx_free_list_lock);
	}

	return 0;
err_freelist:  //申请内存失败处理
	list_for_each_safe(parser, temp, &sgx_free_list) {
		spin_lock(&sgx_free_list_lock);
		entry = list_entry(parser, struct sgx_epc_page, list);
		list_del(&entry->list);
		spin_unlock(&sgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 分配EPC页

{% code-tabs %}
{% code-tabs-item title="sgx\_page\_cache.c" %}
```go
struct sgx_epc_page *sgx_alloc_page(unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_alloc_page_fast();   //从EPC页链表中获取一个页
		if (entry)
			break;   //成功直接返回
		/* We need at minimum two pages for the #PF handler. */
		if (atomic_read(&sgx_va_pages_cnt) >
		    (sgx_nr_total_epc_pages - 2))
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}
		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}
		sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
		schedule();
	}
	if (sgx_nr_free_pages < sgx_nr_low_pages)
		wake_up(&ksgxswapd_waitq);
	return entry;
}
```
{% endcode-tabs-item %}

{% code-tabs-item title="sgx\_page\_cache.c" %}
```c
static struct sgx_epc_page *sgx_alloc_page_fast(void)
{
	struct sgx_epc_page *entry = NULL;

	spin_lock(&sgx_free_list_lock);

	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 list);
		list_del(&entry->list);
		sgx_nr_free_pages--;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 释放EPC页

{% code-tabs %}
{% code-tabs-item title="sgx\_page\_cache.c" %}
```c
void sgx_free_page(struct sgx_epc_page *entry, struct sgx_encl *encl)
{
	void *epc;
	int ret;

	epc = sgx_get_page(entry);
	ret = __eremove(epc);  //释放Enclave页
	sgx_put_page(epc);

	if (ret)
		sgx_crit(encl, "EREMOVE returned %d\n", ret);

	spin_lock(&sgx_free_list_lock);
	list_add(&entry->list, &sgx_free_list);  //重新加入EPC页
	sgx_nr_free_pages++;
	spin_unlock(&sgx_free_list_lock);
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## EPC换页

驱动程序在初始化时也会启动一个内核线程，当空闲EPC页数低于一定值时，会进行换页操作。

{% code-tabs %}
{% code-tabs-item title="sgx\_page\_cache.c" %}
```go
//SGX_NR_LOW_EPC_PAGES_DEFAULT: 32
static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT; 
static unsigned int sgx_nr_high_pages;

int sgx_page_cache_init(void)
{
	struct task_struct *tmp;
	sgx_nr_high_pages = 2 * sgx_nr_low_pages;
	tmp = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (!IS_ERR(tmp))
		ksgxswapd_tsk = tmp;
	return PTR_ERR_OR_ZERO(tmp);
}
//内核线程函数
static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq,
				     kthread_should_stop() ||
				     sgx_nr_free_pages < sgx_nr_high_pages);

		if (sgx_nr_free_pages < sgx_nr_high_pages)
			sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
	}

	pr_info("%s: done\n", __func__);
	return 0;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 参考资料

* [https://insujang.github.io/2017-04-05/intel-sgx-instructions-in-enclave-initialization/](https://insujang.github.io/2017-04-05/intel-sgx-instructions-in-enclave-initialization/)

