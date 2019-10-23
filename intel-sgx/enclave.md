---
description: Enclave由一组EPC页组成，Intel SGX管理的基本单元。
---

# Enclave机制

## PRM

![](../.gitbook/assets/memory_mapping.png)

`PRM` 是处理器保留内存\(Processor Reserved Memory \(PRM\)\)的简称，是主内存的一部分，其它\(系统\)软件\(也包括DMA等硬件\)都无法直接访问。

Enclave的数据和代码存放在PRM中，存放这些数据和代码的内存被称为`EPC`。

### EPC

`EPC`是Enclave Page Cache的简称，是PRM的一部分，enclave本身的数据和代码存放在这些内存中。EPC由一系列内存页\(4KB\)组成，Intel SGX通过`EPCM`数据结构管理这些EPC页\(EPC Page\)，并记录这些页的属性信息。

### EPCM

`EPCM`是Enclave Page Cache Map的简称，是PRM中一个数组结构，每个EPC页在EPCM都有一项，用于记录该页的EPC信息:

| Field | Description |
| :--- | :--- |
| VALID | 0代表该页不是EPC页 |
| R | 是否可读 |
| W | 是否可写 |
| X | 是否可执行 |
| PT | 页类型 |
| ENCLAVESECS | Enclave SECS结构的内存页地址 |
| ENCLAVEADDRESS | 该页线性虚拟地址 |
| BLOCKED | block状态标识 |
| PENDING | pending状态标识 |
| MODIFIED | 修改状态标识 |

处理器根据EPCM的信息对Enclave中的数据和代码进行保护:

1. 确定将要访问的地址是否是一个EPC页
2. 确定EPC页属于的Enclave，防止被其它Enclave的代码访问
3. 确定EPC页的数据或代码是否可读、可写或可执行。
4. 确定当前EPC页的状态，保证EPC页被正常使用

### EPC页类型

EPC内存页中存放的数据有多种不同的类型，按照数据类型将EPC页分为以下类型:

| 页类型 | 数据类型和作用 |
| :--- | :--- |
| PT\_SECS | 存放一个Enclave控制结构数据\(SGX Enclave  Control Structure\) |
| PT\_TCS | 存放Enclave线程控制结构数据\(Thread Control Structure\) |
| PT\_REG | 存放常规的Enclave数据和代码 |
| PT\_VA | 存放Version Array数据 |
| PT\_TRIM | 表明正在从Enclave的EPC中移除 |

### 寄存器

处理器内部存在一些控制寄存器\(CREG\)用来存储和控制SGX的执行状态。这些寄存器软件无法访问，并且取决于具体的实现。

| 寄存器名 | 大小\(Bit\) | 作用 |
| :--- | :--- | :--- |
| CR\_ENCLAVE\_MODE | 1 | 处理器当前是否处于Encave执行模式 |

## SESC

![](../.gitbook/assets/enclave_mem_layout.png)

### SECS结构

`SECS`是`SGX EnclaveControl Structure`的缩写, 存放Enclave的元信息:

* 每个Enclave都有一个SECS结构，通过SECS结构可以唯一索引到Enclave。
* SECS结构占用一个EPC页，页类型是`PT_SECS`。EPC页在创建Enclave时被分配，内存页不需要映射为Enclave线性地址，也不需要映射到进程地址空间。

`SESC`结构包含以下Enclave元信息:

| 字段 | 偏移 | 大小\(Byte\) | 描述 |
| :--- | :--- | :--- | :--- |
| SIZE | 0 | 8 | Enclave占用的内存大小，必须是2的幂 |
| BASEADDR | 8 | 8 | Enclave的起始地址\(虚拟地址\) |
| SSAFRAMESIZE | 16 | 4 | SSA帧大小 |
| MISCSELECT | 20 | 4 | 与SSA帧相关，用于存放扩展功能的位向量 |
| RESERVED | 24 | 24 | 保留位 |
| ATTRIBUTES | 48 | 16 | Enclave属性 |
| MRENCLAVE | 64 | 32 | Enclave标识 |
| RESERVED | 96 | 32 | 保留位 |
| MRSIGNER | 128 | 32 | Enclave提供者标识 |
| RESERVED | 160 | 32 | 保留位 |
| CONFIGID | 192 | 64 | Post EINIT configuration identity |
| ISVPRODID | 256 | 2 | Product ID of Enclave |
| ISVSVN | 258 | 2 | Security version number \(SVN\) of the enclave. |
| CONFIGSVN | 260 | 2 | Post EINIT configuration security version number |
| RESERVED | 262 | 3834 | 保留位 |

### Enclave属性\(Attribute\)

SECS.ATTIBUTES按位定义一些Encave属性，这些属性会在后续操作被使用\(KEYREQUEST, REPORT等\):

| 字段 | 位置 | 作用 |
| :--- | :--- | :--- |
| INIT | 0 | 表明当前Enclave是否已经被EINIT指令初始化 |
| DEBUG | 1 | 当前Enclave是否开启调试模式 |
| MODE64BIT | 2 | 当前Enclave是否运行在64位模式 |
| RESERVED | 3 | 保留位，必须是0 |
| PROVISIONKEY | 4 | 是否可以通过EGETKEY指令获取Provisioning Key |
| EINITTOKEN\_KEY | 5 | 是否可以通过EGETKEY指令获取EINIT token key |
| RESERVED | 6 | 必须是0 |
| KSS | 7 | Key Separation and Sharing Enabled |
| RESERVED |  8-63 |  Must be zero |
|  XFRM |  64-127 |  XSAVE Feature Request Mask |

### MISCSELECT

当`AEX`发生时，指令`CPUID.(EAX=12H, ECX=0):EBX[31:0]`会枚举一些CPU扩展信息并存储在SSA帧的MISC区域。Enclave提供者可以通过指定`SECS.MISCSELECT`位向量，从而选择要添加SSA帧的CPU扩展信息:

| 字段 | 位置 | 功能 |
| :--- | :--- | :--- |
| EXINFO | 0 | 报告发生在Enclave内的页错误和GP异常信息。 |
| Reserved | 1-31 | 保留 |

### MRENCLAVE

MRENCLAVE通过计算Enclave的内容得出，可用于唯一标识一个运行中的Enclave

```bash
secs.mr_enclave = sha2.initialization();
do
   if ECREATE:
      sesc.mr_enclave=sha2.submit(ECREATE_INFO);
   else if EADD:
      sesc.mr_enclave=sha2.submit(EADD_INFO);
   else if EEXTEND:
	  sesc.mr_enclave=sha2.submit(EXTEND_INFO);
   else if EINIT:
      sesc.mr_enclave=sha2.done();
      break;
done;
```

### MRSIGNER

MRSIGNER用于标识Enclave的代码提供者, 计算方式是对代码提供者的RSA公钥Modulus参数小端序进行sha256哈希

```go
	data, _ := ioutil.ReadFile("raw/private.pem")
	block, _ := pem.Decode(data)
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("err:%v", err)
	}
	pubKey := pri.Public().(*rsa.PublicKey) //384位
	
	rbytes := []byte{}
	bytes := pubKey.N.Bytes() //大端序
	
	//大端序转小端序
	for i := len(bytes) - 1; i >= 0; i-- {
		rbytes = append(rbytes, bytes[i])
	}
    //哈希
	hash := sha256.New()
	hash.Write(rbytes)
	out := hash.Sum(nil)
```

## 创建Enclave



