# Enclave管理

## Enclave结构体

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
struct sgx_encl {
	unsigned int flags;
	uint64_t attributes;
	uint64_t xfrm;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct mm_struct *mm;
	struct file *backing;
	struct file *pcmd;
	struct list_head load_list;  //已经加载到enclave的epc页链表
	struct kref refcount;   //对象引用计数
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;  //已经分配给该enclave的epc页链表
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;  //新页请求链表
	struct work_struct add_page_work;
	struct sgx_encl_page secs;
	struct sgx_tgid_ctx *tgid_ctx;   //enclave绑定的线程组上下文
	struct list_head encl_list;
	struct mmu_notifier mmu_notifier;
};
```
{% endcode-tabs-item %}
{% endcode-tabs %}

驱动程序利用SECS实例初始化一个sgx\_encl实例:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs)
{
	unsigned long ssaframesize;
	struct sgx_encl *encl;
	struct file *backing;
	struct file *pcmd;

	ssaframesize = sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);  //计算ssa frame大小
	if (sgx_validate_secs(secs, ssaframesize))   //校验用户传入的secs
		return ERR_PTR(-EINVAL);

	backing = shmem_file_setup("[dev/sgx]", secs->size + PAGE_SIZE,
				   VM_NORESERVE);   //在tmpfs创建一个inode，用于共享内存
	if (IS_ERR(backing))
		return (void *)backing;

	pcmd = shmem_file_setup("[dev/sgx]", (secs->size + PAGE_SIZE) >> 5,
				VM_NORESERVE);   //在tmpfs创建一个inode，用于共享内存, 与backing的区别??
	if (IS_ERR(pcmd)) {
		fput(backing);
		return (void *)pcmd;
	}

	encl = kzalloc(sizeof(*encl), GFP_KERNEL);  //从内核中动态分配encl结构体
	if (!encl) {
		fput(backing);
		fput(pcmd);
		return ERR_PTR(-ENOMEM);
	}

	encl->attributes = secs->attributes;  //enclave属性屏蔽位向量
	encl->xfrm = secs->xfrm;  //xfrm数据

	kref_init(&encl->refcount);  //初始化引用计数器
	INIT_LIST_HEAD(&encl->add_page_reqs);   //初始化加页请求链表
	INIT_LIST_HEAD(&encl->va_pages);  //初始化epc页链表
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	INIT_LIST_HEAD(&encl->load_list);  //初始化已经加载的epc页链表
	INIT_LIST_HEAD(&encl->encl_list);
	mutex_init(&encl->lock);   //初始化enclave互斥锁
	INIT_WORK(&encl->add_page_work, sgx_add_page_worker); //初始化加页请求工作线程

	encl->mm = current->mm;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssaframesize;
	encl->backing = backing;
	encl->pcmd = pcmd;

	return encl;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 创建Enclave

用户进程通过系统调用将enclave代码\(so文件\)加载到进程的地址空间\(占用一个vma\)，然后向驱动程序发起一个创建enclave的请求\(包括一个secs结构参数\)，驱动程序处理请求代码:

{% code-tabs %}
{% code-tabs-item title="sgx\_ioctl.c" %}
```c
static long sgx_ioc_enclave_create(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	struct sgx_enclave_create *createp = (struct sgx_enclave_create *)arg;
	void __user *src = (void __user *)createp->src;
	struct sgx_secs *secs;
	int ret;

	secs = kzalloc(sizeof(*secs),  GFP_KERNEL);
	if (!secs)
		return -ENOMEM;
	//将secs结构从用户空间复制到内核空间
	ret = copy_from_user(secs, src, sizeof(*secs));
	if (ret) {
		kfree(secs);
		return ret;
	}

	ret = sgx_encl_create(secs);  //创建enclave流程

	kfree(secs);
	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

驱动程序会创建一个enclave内核对象，并为secs结构申请一个epc页，然后关联一些上下文信息:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
int sgx_encl_create(struct sgx_secs *secs)
{
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl;
	struct sgx_epc_page *secs_epc;
	struct vm_area_struct *vma;
	void *secs_vaddr;
	long ret;

	encl = sgx_encl_alloc(secs);    //1. 分配一个enclave实例
	if (IS_ERR(encl))
		return PTR_ERR(encl);

	secs_epc = sgx_alloc_page(0);  //2. 分配secs epc页
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		goto out;
	}
	encl->secs.epc_page = secs_epc; //将enclave与secs页进行关联

	ret = sgx_add_to_tgid_ctx(encl);   //3. 绑定该enclave属于的线程组
	if (ret)
		goto out;

	ret = sgx_init_page(encl, &encl->secs, encl->base + encl->size, 0);  //5. 初始化epc页
	if (ret)
		goto out;

	secs_vaddr = sgx_get_page(secs_epc);  //获取epc页的虚拟地址

	pginfo.srcpge = (unsigned long)secs;
	pginfo.linaddr = 0;
	pginfo.secinfo = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));
	ret = __ecreate((void *)&pginfo, secs_vaddr);   //调用ECREATE汇编指令

	sgx_put_page(secs_vaddr);  //x86_32机器释放临时占用的虚拟地址

	if (ret) {
		sgx_dbg(encl, "ECREATE returned %ld\n", ret);
		ret = -EFAULT;
		goto out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		encl->flags |= SGX_ENCL_DEBUG;    //设置调试模式标志

	//注册进程内存操作事件回调: 当前只监听进程地址映射释放的事件(发生在进程被杀死)
	encl->mmu_notifier.ops = &sgx_mmu_notifier_ops;
	ret = mmu_notifier_register(&encl->mmu_notifier, encl->mm);
	if (ret) {
		if (ret == -EINTR)
			ret = -ERESTARTSYS;
		encl->mmu_notifier.ops = NULL;
		goto out;
	}

	down_read(&current->mm->mmap_sem);
	ret = sgx_encl_find(current->mm, secs->base, &vma);   //6. 查找enclave所有的虚拟地址区域
	if (ret != -ENOENT) {
		if (!ret)
			ret = -EINVAL;
		up_read(&current->mm->mmap_sem);
		goto out;
	}
	//校验地址一致
	if (vma->vm_start != secs->base ||
	    vma->vm_end != (secs->base + secs->size)
	    /* vma->vm_pgoff != 0 */) {
		ret = -EINVAL;
		up_read(&current->mm->mmap_sem);
		goto out;
	}

	vma->vm_private_data = encl;
	up_read(&current->mm->mmap_sem);

	mutex_lock(&sgx_tgid_ctx_mutex);
	list_add_tail(&encl->encl_list, &encl->tgid_ctx->encl_list);  //将当前enclave加入同一个线程组的enclave链表中
	mutex_unlock(&sgx_tgid_ctx_mutex);

	return 0;
out:
	if (encl)
		kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}



