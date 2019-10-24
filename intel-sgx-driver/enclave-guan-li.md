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

## 添加EPC页

在创建完Enclave内核对象以后，用户进程可以通过驱动程序向Enclave中添加EPC页:

{% code-tabs %}
{% code-tabs-item title="sgx\_ioctl.c" %}
```c
static long sgx_ioc_enclave_add_page(struct file *filep, unsigned int cmd,
				     unsigned long arg)
{
	struct sgx_enclave_add_page *addp = (void *)arg;
	unsigned long secinfop = (unsigned long)addp->secinfo;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl;
	struct page *data_page;
	void *data;
	int ret;
	//addp->addr是要添加epc页的虚拟地址
	ret = sgx_get_encl(addp->addr, &encl);   //获取要添加页的enclave内核对象
	if (ret)
		return ret;

	if (copy_from_user(&secinfo, (void __user *)secinfop,
			   sizeof(secinfo))) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EFAULT;
	}

	data_page = alloc_page(GFP_HIGHUSER);  //从高地址空间分配一个物理页
	if (!data_page) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -ENOMEM;
	}

	data = kmap(data_page);  //添加物理页虚拟地址映射

	//把用户页数据拷贝到data页
	ret = copy_from_user((void *)data, (void __user *)addp->src, PAGE_SIZE);
	if (ret)
		goto out;
	
	//向enclave分配epc页
	ret = sgx_encl_add_page(encl, addp->addr, data, &secinfo, addp->mrmask);
	if (ret)
		goto out;

out:
	kref_put(&encl->refcount, sgx_encl_release);
	kunmap(data_page);
	__free_page(data_page);
	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

向enclave添加epc页的核心流程是:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       unsigned long addr,
			       void *data,
			       struct sgx_secinfo *secinfo,
			       unsigned int mrmask)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct page *backing;
	struct sgx_add_page_req *req = NULL;
	int ret;
	int empty;
	void *backing_ptr;
	
	//1. 校验外部参数信息
	if (sgx_validate_secinfo(secinfo))
		return -EINVAL;

	if (page_type == SGX_SECINFO_TCS) {
		ret = sgx_validate_tcs(encl, data);
		if (ret)
			return ret;
	}
	
	ret = sgx_init_page(encl, encl_page, addr, 0);   //初始化epc页
	if (ret)
		return ret;

	mutex_lock(&encl->lock);

	if (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD)) {
		ret = -EINVAL;
		goto out;
	}
	//2. 查找该页是否已经添加
	if (radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT)) {
		ret = -EEXIST;
		goto out;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR((void *)backing)) {
		ret = PTR_ERR((void *)backing);
		goto out;
	}
	//将<目标虚址, epc页>加入基数树
	ret = radix_tree_insert(&encl->page_tree, encl_page->addr >> PAGE_SHIFT,
				encl_page);
	if (ret) {
		sgx_put_backing(backing, false /* write */);
		goto out;
	}

	backing_ptr = kmap(backing);
	memcpy(backing_ptr, data, PAGE_SIZE);   //将enclave源数据复制到内核页
	kunmap(backing);

	if (page_type == SGX_SECINFO_TCS)
		encl_page->flags |= SGX_ENCL_PAGE_TCS;

	memcpy(&req->secinfo, secinfo, sizeof(*secinfo));

	//创建加页请求，并提交到工作进程
	req->encl = encl;
	req->encl_page = encl_page;
	req->mrmask = mrmask;
	empty = list_empty(&encl->add_page_reqs);
	kref_get(&encl->refcount);
	list_add_tail(&req->list, &encl->add_page_reqs);
	if (empty)
		queue_work(sgx_add_page_wq, &encl->add_page_work);

	sgx_put_backing(backing, true /* write */);

	mutex_unlock(&encl->lock);
	return 0;
out:
	kfree(req);
	sgx_free_va_slot(encl_page->va_page, encl_page->va_offset);
	mutex_unlock(&encl->lock);
	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## EPC页添加工作队列

驱动程序用一个工作队列处理向enclave添加epc页的请求, 在驱动程序初始化时启动工作队列:

{% code-tabs %}
{% code-tabs-item title="sgx\_main.c" %}
```c
static int sgx_dev_init(struct device *parent)
{
    //忽略一些代码
    sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq",
					  WQ_UNBOUND | WQ_FREEZABLE, 1);
	//忽略一些代码
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

为创建enclave内核对象时，会为enclave初始化一个woker任务

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs)
{
	//忽略一些代码
	INIT_WORK(&encl->add_page_work, sgx_add_page_worker); 
	//忽略一些代码
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

在向enclave第一次添加epc页时会把enclave的worker任务放到worker queue中

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       unsigned long addr,
			       void *data,
			       struct sgx_secinfo *secinfo,
			       unsigned int mrmask)
{
	//忽略一些代码
	//创建加页请求，并提交到工作进程
	req->encl = encl;
	req->encl_page = encl_page;
	req->mrmask = mrmask;
	empty = list_empty(&encl->add_page_reqs);
	kref_get(&encl->refcount);
	list_add_tail(&req->list, &encl->add_page_reqs);
	if (empty)
		queue_work(sgx_add_page_wq, &encl->add_page_work);
	//忽略一些代码
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

具体执行添加epc页的方法:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_encl *encl;
	struct sgx_add_page_req *req;
	struct sgx_epc_page *epc_page;
	bool skip_rest = false;
	bool is_empty = false;

	//通过add_page_work地址，获取sgx_encl结构的首地址
	encl = container_of(work, struct sgx_encl, add_page_work);

	do {
		schedule();  //为什么要执行一次进程切换??

		if (encl->flags & SGX_ENCL_DEAD)
			skip_rest = true;   //enclave已经关闭，跳过

		mutex_lock(&encl->lock);
		req = list_first_entry(&encl->add_page_reqs,
				       struct sgx_add_page_req, list);    //取出第一个请求
		list_del(&req->list);
		is_empty = list_empty(&encl->add_page_reqs);  //判断队列是否是空
		mutex_unlock(&encl->lock);

		if (skip_rest)
			goto next;

		epc_page = sgx_alloc_page(0);   //分配一个epc页
		if (IS_ERR(epc_page)) {
			skip_rest = true;
			goto next;
		}

		down_read(&encl->mm->mmap_sem);
		mutex_lock(&encl->lock);

		if (!sgx_process_add_page_req(req, epc_page)) {
			sgx_free_page(epc_page, encl);
			skip_rest = true;
		}

		mutex_unlock(&encl->lock);
		up_read(&encl->mm->mmap_sem);

next:
		kfree(req);
	} while (!kref_put(&encl->refcount, sgx_encl_release) && !is_empty);
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

woker方法在执行时会先分配一个新的EPC页，然后调用`sgx_process_add_page_req`方法:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static bool sgx_process_add_page_req(struct sgx_add_page_req *req,
				     struct sgx_epc_page *epc_page)
{
	struct page *backing;
	struct sgx_encl_page *encl_page = req->encl_page;
	struct sgx_encl *encl = req->encl;
	struct vm_area_struct *vma;
	int ret;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		return false;
	//找到ELRANGE
	ret = sgx_encl_find(encl->mm, encl_page->addr, &vma);
	if (ret)
		return false;
	//找到源数据页
	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing))
		return false;

	/* Do not race with do_exit() */
	if (!atomic_read(&encl->mm->mm_users)) {
		sgx_put_backing(backing, 0);
		return false;
	}
	//添加epc页与目标虚址的页表映射
	ret = vm_insert_pfn(vma, encl_page->addr, PFN_DOWN(epc_page->pa));
	if (ret) {
		sgx_put_backing(backing, 0);
		return false;
	}
	//调用EADD指定，将EPC页添加到enclave中
	ret = sgx_eadd(encl->secs.epc_page, epc_page, encl_page->addr,
		       &req->secinfo, backing);

	sgx_put_backing(backing, 0);
	if (ret) {
		sgx_warn(encl, "EADD returned %d\n", ret);
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		return false;
	}

	encl->secs_child_cnt++;

	//调用extend指令生成EPC指纹，并更新到secs.mrenclave
	ret = sgx_measure(encl->secs.epc_page, epc_page, req->mrmask);
	if (ret) {
		sgx_warn(encl, "EEXTEND returned %d\n", ret);
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		return false;
	}

	epc_page->encl_page = encl_page;
	encl_page->epc_page = epc_page;
	sgx_test_and_clear_young(encl_page, encl);
	list_add_tail(&epc_page->list, &encl->load_list);  //将添加的页放到enclave已加载epc页列表

	return true;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 初始化Enclave

用户进程在向enclave添加完所有的EPC页后，可以向驱动程序发起初始化请求, Enclave在完成初始化不可以继续添加EPC页:

{% code-tabs %}
{% code-tabs-item title="sgx\_ioctl.c" %}
```c
static long sgx_ioc_enclave_init(struct file *filep, unsigned int cmd,
				 unsigned long arg)
{
	struct sgx_enclave_init *initp = (struct sgx_enclave_init *)arg;
	unsigned long sigstructp = (unsigned long)initp->sigstruct;    //sigstruct结构
	unsigned long einittokenp = (unsigned long)initp->einittoken;   //init token
	unsigned long encl_id = initp->addr;
	struct sgx_sigstruct *sigstruct;
	struct sgx_einittoken *einittoken;
	struct sgx_encl *encl;
	struct page *initp_page;
	int ret;

	initp_page = alloc_page(GFP_HIGHUSER);   //在高端地址申请一个页
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page); 
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);
	
	//从用户空间复制SIGSTRUCT结构数据
	ret = copy_from_user(sigstruct, (void __user *)sigstructp,
			     sizeof(*sigstruct));
	if (ret)
		goto out;
	//从用户空间复制init token数据
	ret = copy_from_user(einittoken, (void __user *)einittokenp,
			     sizeof(*einittoken));
	if (ret)
		goto out;

	ret = sgx_get_encl(encl_id, &encl);  //获取目标enclave
	if (ret)
		goto out;

	ret = sgx_encl_init(encl, sigstruct, einittoken);   //执行初始化流程

	kref_put(&encl->refcount, sgx_encl_release);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

函数调用`sgx_encl_init`方法

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		  struct sgx_einittoken *token)
{
	int ret;
	int i;
	int j;

	flush_work(&encl->add_page_work);   //确保所有添加页请求被执行完

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_INITIALIZED) {    //init不可以重复发起
		mutex_unlock(&encl->lock);
		return 0;
	}

	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			ret = sgx_einit(encl, sigstruct, token);    //调用einit汇编指令完成初始化

			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			break;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);
		if (signal_pending(current)) {
			mutex_unlock(&encl->lock);
			return -ERESTARTSYS;
		}
	}
	mutex_unlock(&encl->lock);
	if (ret) {
		if (ret > 0)
			sgx_dbg(encl, "EINIT returned %d\n", ret);
		return ret;
	}
	encl->flags |= SGX_ENCL_INITIALIZED;
	return 0;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

`sgx_encl_init`方法继续调用`sgx_einit`方法:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static int sgx_einit(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		     struct sgx_einittoken *token)
{
	struct sgx_epc_page *secs_epc = encl->secs.epc_page;
	void *secs_va;
	int ret;

	secs_va = sgx_get_page(secs_epc);
	ret = __einit(sigstruct, token, secs_va);  //调用einit指令，完成enclave初始化
	sgx_put_page(secs_va);

	return ret;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## 清理Enclave

### 进程退出

在创建Encave时，驱动程序会注册一些内存管理事件:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release	= sgx_mmu_notifier_release,   //进程被杀死后回调
};

int sgx_encl_create(struct sgx_secs *secs)
{
	//忽略一些代码
	encl->mmu_notifier.ops = &sgx_mmu_notifier_ops;
	ret = mmu_notifier_register(&encl->mmu_notifier, encl->mm); //注册内存管理事件
	//忽略一些代码
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

当前内存release事件\(进程关闭\)发生后，会调用`sgx_mmu_notifier_release`方法

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl *encl =
		container_of(mn, struct sgx_encl, mmu_notifier);

	mutex_lock(&encl->lock);
	encl->flags |= SGX_ENCL_DEAD;   //enclave被标记为DEAD状态
	mutex_unlock(&encl->lock);
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

### 引用计数

Enclave内核对象存在一个引用计数, 当计数值为0时，会完成对enclave的请理:

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
struct sgx_encl {
	//省略一些代码
	struct kref refcount;   //对象引用计数
};

kref_put(&encl->refcount, sgx_encl_release);
```
{% endcode-tabs-item %}
{% endcode-tabs %}

函数`sgx_encl_release`会完成清理

{% code-tabs %}
{% code-tabs-item title="sgx\_encl.c" %}
```c
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl_page *entry;
	struct sgx_va_page *va_page;
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);  //获取enclave内核对象
	struct radix_tree_iter iter;
	void **slot;

	mutex_lock(&sgx_tgid_ctx_mutex);
	if (!list_empty(&encl->encl_list))
		list_del(&encl->encl_list);
	mutex_unlock(&sgx_tgid_ctx_mutex);

	if (encl->mmu_notifier.ops)
		mmu_notifier_unregister(&encl->mmu_notifier, encl->mm);  //取消内存管理事件监听

	//回收EPC页
	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		if (entry->epc_page) {
			list_del(&entry->epc_page->list);
			sgx_free_page(entry->epc_page, encl);   //释放EPC页
		}
		radix_tree_delete(&encl->page_tree, entry->addr >> PAGE_SHIFT);
		kfree(entry);
	}
	//回收剩余的分配给enclave的EPC页
	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages,
					   struct sgx_va_page, list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page, encl);
		kfree(va_page);
		atomic_dec(&sgx_va_pages_cnt);
	}

	if (encl->secs.epc_page)
		sgx_free_page(encl->secs.epc_page, encl);

	if (encl->tgid_ctx)
		kref_put(&encl->tgid_ctx->refcount, sgx_tgid_ctx_release);   //解除绑定的线程组

	if (encl->backing)
		fput(encl->backing);

	if (encl->pcmd)
		fput(encl->pcmd);

	kfree(encl);  //回收内核对象
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

