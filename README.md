> 注意⚠️：与aes不通用，此代码每1024B × 1024 - 1 进行一次 aes 加密。

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hunyxv/aesgzip"
)

func init () {
	// 修改 aes 初始化变量(16字节)
	aesgzip.IV  = []byte("90-b@de.ghi^765=")
}

func main() {
	aesKey := []byte("123abc456def7890")

	// 文件压缩加密
    plaintext, err := os.Open("input.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer plaintext.Close()
	dstPath := "output.gz.aes"

	err = aesgzip.GzipEncryption(plaintext, dstPath, aesKey)
	if err != nil {
		log.Fatalln(err)
	}

	// 解密解压缩

	ciphertext, err := os.Open("output.gz.aes")
	if err != nil {
		log.Fatalln(err)
	}
	defer ciphertext.Close()
	dstPath = "output.txt"
	
	err = aesgzip.DecryptUngzip(ciphertext, dstPath, aesKey)
	if err != nil {
		log.Fatalln(err)
	}

	// 一句话加解密
	text := []byte("How are you? I'm fine, thanks!")
	fmt.Println("aes加密前：", text)
	aesText, _ := aesgzip.Encrypt(text, aesKey)
	fmt.Println("aes加密后：", aesText)
	pText, _ := aesgzip.Decrypt(aesText, aesKey)
	fmt.Println("aes解密后：", pText)

	// 一句话加密并压缩 和 解密解压缩
	data := []byte(`{
		"version": "0.1",
		"timestamp": 1586519299,
		"param": {
			"type": 1,
			"list": [
				{"video_id": "v_19rwstgyo4", "update_time": 1586514239, "event": "Update"},
				{"video_id": "v_19rsd3g6o4", "update_time": 1586514249, "event": "Update"},
				{"video_id": "v_19rws3jjr9", "update_time": 1586514259, "event": "Update"}
			]
		}
	}`)

	xx, err := aesgzip.RowGzipEncryption(data, aesKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(xx)

	xd, err := aesgzip.RowDecryptUngzip(xx, aesKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(xd)
}
```
