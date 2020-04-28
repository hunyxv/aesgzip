package aesgzip

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// @title	GzipEncryption
// @description	将 src 中的数据gzip压缩然后aes加密写入 dstPath 路径
// @param	src io.Reader　提供明文数据、
// @param	dstPath string 压缩加密后文件路径
// @param 	aesKey	[]byte	aes 密钥
// @return 	error
func GzipEncryption(src io.Reader, dstPath string, aesKey []byte) error {
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer dst.Close()

	encrypt, err := NewAesEncryptW(dst, aesKey)
	if err != nil {
		return err
	}
	defer encrypt.Close()
	gzipFile := gzip.NewWriter(encrypt)

	buf := make([]byte, 2048)
	for {
		n, err := src.Read(buf)
		if err == io.EOF {
			fmt.Println("压缩、加密完成！")
			gzipFile.Close()
			return nil
		}
		gzipFile.Write(buf[:n])
	}
}

// @title	DecryptUngzip
// @description	将 src 中的数据aes解密gzip解压缩然后写入 dstPath 路径
// @param	src io.Reader　提供密文数据、
// @param	dstPath string 解密解压缩后文件路径
// @param 	aesKey	[]byte	aes 密钥
// @return 	error
func DecryptUngzip(src io.Reader, dstPath string, aesKey []byte) error {
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer dst.Close()

	decrypt, err := NewAesDecryptR(src, aesKey)
	if err != nil {
		return err
	}

	gzipFile, err := gzip.NewReader(decrypt)
	if err != nil {
		return err
	}
	defer gzipFile.Close()

	buf := make([]byte, 2048)
	for {
		n, err := gzipFile.Read(buf)
		dst.Write(buf[:n])
		if err == io.EOF {
			fmt.Println("解密、解压完成!")
			return nil
		}
	}
}
