---
description: Enclave由一组EPC页组成，Intel SGX管理的基本单元。
---

# Enclave保护

## 硬件结构

![](../.gitbook/assets/memory_mapping.png)

### PRM

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

EPC页类型

EPC内存页中存放的数据有多种不同的类型，按照数据类型将EPC页分为以下类型:

| 页类型 | 数据类型和作用 |
| :--- | :--- |
| PT\_SECS | 存放一个Enclave控制结构数据\(SGX Enclave  Control Structure\) |
| PT\_TCS | 存放Enclave线程控制结构数据\(Thread Control Structure\) |
| PT\_REG | 存放常规的Enclave数据和代码 |
| PT\_VA | 存放Version Array数据 |
| PT\_TRIM | 表明正在从Enclave的EPC中移除 |

## 标识

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

