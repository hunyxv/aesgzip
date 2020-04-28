package aesgzip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// aes 初始化向量
var iv []byte = []byte("0123456789876543")

// 加密轮数据大小 1M - 1B
const roundSize int = 1024*1024 - 1

// @title	PKCS5Padding
// @description	 填充明文
// @param	origData []byte 明文数据，blockSize int aes分组长度
// @return	[]byte
func PKCS5Padding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	padOrigData := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(origData, padOrigData...)
}

// @title	PKCS5UnPadding
// @description	 去除填充
// @param	origData []byte 明文数据
// @return	[]byte
func PKCS5UnPadding(origData []byte) []byte {
	dataLen := len(origData)
	paddLen := int(origData[dataLen-1])
	return origData[:dataLen-paddLen]
}

// @title	Encrypt
// @description	 aes 加密
// @param	origData []byte 明文数据， key []byte aes密钥
// @return	[]byte 密文, error
func Encrypt(origData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, iv)

	origData = PKCS5Padding(origData, blockSize)
	ciphertxt := make([]byte, len(origData))
	blockMode.CryptBlocks(ciphertxt, origData)

	return ciphertxt, nil
}

// @title	Decrypt
// @description	 aes 解密
// @param	crypted []byte 密文数据， key []byte aes密钥
// @return	[]byte 明文数据， error
func Decrypt(crypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, iv)

	origData := make([]byte, len(crypted))

	blockMode.CryptBlocks(origData, crypted)
	return PKCS5UnPadding(origData), nil
}

// AesEncryptW 流式加密
// []byte --AES--> io.Writer
type AesEncryptW struct {
	target    io.WriteCloser
	aesKey    []byte
	block     cipher.Block
	blockSize int
	roundSize int
	buf       []byte
	tmp       []byte
}

// @title	NewAesEncryptW
// @description	创建 *AesEncryptW
// @param	f io.Writer 加密后数据写入 f
// @param	aesKey []byte aes密钥
// @return 	*NewAesEncryptW
func NewAesEncryptW(f io.WriteCloser, aesKey []byte) (*AesEncryptW, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	return &AesEncryptW{
		target:    f,
		aesKey:    aesKey,
		block:     block,
		blockSize: blockSize,
		roundSize: roundSize,
		tmp:       make([]byte, roundSize+1),
	}, nil
}

// @title		encrypt
// @description 加密数据块，每次加密 roundSize 大小数据（文件结尾除外）
// @param 		origData []byte 明文数据块
// @return 		加密后数据长度
func (e *AesEncryptW) encrypt(origData []byte) int {
	origData = PKCS5Padding(origData, e.blockSize)
	blockMode := cipher.NewCBCEncrypter(e.block, iv)
	blockMode.CryptBlocks(e.tmp, origData)
	return len(origData)
}

// @title 		Write
// @description io.Writer 接口，从上游接收数据缓存、加密 写入下游 io.Writer
// @param 		b	[]byte
// @return 		n int, 成功写入的数据， err error 异常
func (e *AesEncryptW) Write(b []byte) (n int, err error) {
	e.buf = append(e.buf, b...)
	bufLen := len(e.buf)
	if bufLen < e.roundSize {
		return len(b), nil
	}

	roundNum := bufLen / e.roundSize

	tmp := make([]byte, e.roundSize)
	for i := 0; i < roundNum; i++ {
		copy(tmp, e.buf[i*e.roundSize:(i+1)*e.roundSize])
		n := e.encrypt(tmp)
		_, err := e.target.Write(e.tmp[:n])
		if err != nil {
			return len(b), err
		}
	}
	dataBlockLen := bufLen - bufLen%e.roundSize
	e.buf = e.buf[dataBlockLen:]
	return len(b), nil
}

// Flush flush
// @description 	在最后一轮加密后，使用此函数将buf中不足 roundSize 大小的数据加密
func (e *AesEncryptW) Flush() error {
	n := e.encrypt(e.buf)
	n, err := e.target.Write(e.tmp[:n])
	return err
}

// Close 会关闭下层 io
func (e *AesEncryptW) Close() error {
	err := e.Flush()
	if err != nil {
		return err
	}
	err = e.target.Close()
	return err
}

// AesDecryptW 流式解密
// []byte --AES--> io.Writer
type AesDecryptW struct {
	target    io.WriteCloser
	aesKey    []byte
	block     cipher.Block
	blockSize int
	roundSize int
	buf       []byte
	tmp       []byte
}

// @title	NewAesDecryptW
// @description	创建 *AesDecryptW
// @param	f io.Writer 加密后数据写入 f
// @param	aesKey []byte aes密钥
// @return 	*NewAesEncryptW
func NewAesDecryptW(f io.WriteCloser, aesKey []byte) (*AesDecryptW, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	return &AesDecryptW{
		target:    f,
		aesKey:    aesKey,
		block:     block,
		blockSize: blockSize,
		roundSize: roundSize + 1,
		tmp:       make([]byte, roundSize+1),
	}, nil
}

// @title	pkcs5UnPadding
// @description	 去除填充
// @param	origData []byte 明文数据
// @return	int
func (d AesDecryptW) pkcs5UnPadding(origData []byte) int {
	dataLen := len(origData)
	paddLen := int(origData[dataLen-1])
	return dataLen - paddLen
}

// @title	decrypt
// @description	将密文解密到 d.tmp, 返回明文长度
// @param	ciphertext []byte 密文
// @return n int
func (d *AesDecryptW) decrypt(ciphertext []byte) (n int) {
	l := len(ciphertext)
	if l == 0 {
		return 0
	}
	blockMode := cipher.NewCBCDecrypter(d.block, iv)
	blockMode.CryptBlocks(d.tmp, ciphertext)
	n = d.pkcs5UnPadding(d.tmp[:l])
	return n
}

// @title Write
// @description io.Writer 接口
func (d *AesDecryptW) Write(b []byte) (n int, err error) {
	d.buf = append(d.buf, b...)
	bufLen := len(d.buf)
	if bufLen < d.roundSize {
		return len(b), nil
	}

	roundNum := bufLen / d.roundSize
	for i := 0; i < roundNum; i++ {
		n = d.decrypt(d.buf[i*d.roundSize : (i+1)*d.roundSize])
		d.target.Write(d.tmp[:n])
	}
	dataBlockLen := bufLen - bufLen%d.roundSize
	d.buf = d.buf[dataBlockLen:]
	return len(b), nil
}

// Flush flush
// @description 	在最后一轮解密后，使用此函数将buf中不足 roundSize 大小的数据解密
func (d *AesDecryptW) flush() error {
	n := d.decrypt(d.buf)
	_, err := d.target.Write(d.tmp[:n])
	return err
}

// Close 会关闭下层 io
func (d *AesDecryptW) Close() error {
	if err := d.flush(); err != nil {
		return err
	}

	err := d.target.Close()
	return err
}

// ------------------------------------------------------
// ------------------------------------------------------

// AesDecryptR 流式加密
// io.Reader --AES--> []byte
type AesEncrypt struct {
	target    io.Reader
	aesKey    []byte
	block     cipher.Block
	blockSize int
	blockMode cipher.BlockMode
	buf       []byte
	eof       bool
}

// @title	NewAesDecryptR
// @description	创建 *NewAesDecryptR
// @param	f io.Reader 提供明文数据, aesKey []byte aes密钥
// @return 	*NewAesDecryptR
func NewAesEncrypt(f io.Reader, aesKey []byte) (*AesEncrypt, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	buf := make([]byte, blockSize)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}

	return &AesEncrypt{
		target:    f,
		aesKey:    aesKey,
		block:     block,
		blockSize: blockSize,
		blockMode: cipher.NewCBCEncrypter(block, iv),
		buf:       buf[:n],
	}, nil
}

// @title	pkcs5Padding
// @description	 填充明文
// @param	origData []byte 明文数据
// @return	[]byte
func (e *AesEncrypt) pkcs5Padding(origData []byte) []byte {
	padding := e.blockSize - len(origData)%e.blockSize
	padOrigData := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(origData, padOrigData...)
}

// Read io.Reader
func (e *AesEncrypt) Read(b []byte) (n int, err error) {
	if !e.eof {
		n, err = e.target.Read(b)
		e.buf = append(e.buf, b[:n]...)
		if err == io.EOF {
			if len(e.buf) == 0 {
				return 0, io.EOF
			}
			e.eof = true
		}
	} else if len(e.buf) == 0 {
		return 0, io.EOF
	}

	var integerMultiple int
	// 如果不是读到最后一块 len(e.buf) 总是大于 len(b) 的
	if len(e.buf) > len(b) {
		integerMultiple = len(b) - len(b)%e.blockSize
	} else {
		e.buf = e.pkcs5Padding(e.buf)
		integerMultiple = len(e.buf)
	}
	e.blockMode.CryptBlocks(b, e.buf[:integerMultiple])
	e.buf = e.buf[integerMultiple:]

	return integerMultiple, nil
}

// AesDecryptW 流式解密
// io.Write --AES--> []byte
type AesDecryptR struct {
	target    io.Reader
	aesKey    []byte
	block     cipher.Block
	blockSize int
	roundSize int
	buf       []byte
	eof       bool
}

// @title	NewAesDecryptR
// @description	创建 *AesDecryptW
// @param	f io.Reader 加密后数据写入 f
// @param	aesKey []byte aes密钥
// @return 	*NewAesEncryptW
func NewAesDecryptR(f io.Reader, aesKey []byte) (*AesDecryptR, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	return &AesDecryptR{
		target:    f,
		aesKey:    aesKey,
		block:     block,
		blockSize: blockSize,
		roundSize: roundSize + 1,
	}, nil
}

// @title	pkcs5UnPadding
// @description	 去除填充
// @param	origData []byte 明文数据
// @return	int
func (d AesDecryptR) pkcs5UnPadding(origData []byte) int {
	dataLen := len(origData)
	paddLen := int(origData[dataLen-1])
	return dataLen - paddLen
}

// @title	decrypt
// @description	将密文解密到 d.tmp, 返回明文长度
// @param	ciphertext []byte 密文
// @return n int
func (d *AesDecryptR) decrypt(ciphertext, tmp []byte) (n int) {
	l := len(ciphertext)
	if l == 0 {
		return 0
	}
	blockMode := cipher.NewCBCDecrypter(d.block, iv)
	blockMode.CryptBlocks(tmp, ciphertext)
	n = d.pkcs5UnPadding(tmp[:l])
	return n
}

// @title Write
// @description io.Writer 接口
func (d *AesDecryptR) Read(b []byte) (n int, err error) {
	if len(d.buf) == 0 && d.eof {
		return 0, io.EOF
	}

	buf := make([]byte, roundSize+1)
	n, err = d.target.Read(buf)
	if err == io.EOF {
		d.eof = true
		if len(d.buf) == 0 {
			return 0, io.EOF
		}
	} else {
		tmp := make([]byte, n)
		n = d.decrypt(buf[:n], tmp)
		d.buf = append(d.buf, tmp[:n]...)
	}

	copy(b, d.buf)
	if len(d.buf) >= len(b) {
		d.buf = d.buf[len(b):]
		return len(b), nil
	}

	lbuf := len(d.buf)
	d.buf = d.buf[len(d.buf):]
	return lbuf, nil
}
