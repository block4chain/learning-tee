---
description: Enclave由一组EPC页组成，Intel SGX管理的基本单元
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
| ENCLAVESECS | enclave sesc结构索引 |
| ENCLAVEADDRESS | 该页线性虚拟地址 |
| BLOCKED | block状态标识 |
| PENDING | pending状态标识 |
| MODIFIED | 修改状态标识 |

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

