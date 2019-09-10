---
description: Enclave由一组EPC页组成，Intel SGX管理的基本单元
---

# Enclave

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

