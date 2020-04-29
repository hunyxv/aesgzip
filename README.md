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
}
```
