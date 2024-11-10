package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// 密钥对的生成
// openssl genrsa -out private_key.pem 1024
// openssl rsa -in private_key.pem -pubout -out public_key.pem

type Signature struct {
	pub *rsa.PublicKey  // 公钥
	pri *rsa.PrivateKey // 私钥
}

func NewSignature(c *Config) *Signature {
	var s = new(Signature)

	block, _ := pem.Decode([]byte(c.PublicKey))
	if block == nil {
		panic("解析公钥失败")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	s.pub = pub.(*rsa.PublicKey)

	block, _ = pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		panic("解析私钥失败")
	}
	pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	s.pri = pri.(*rsa.PrivateKey)

	return s
}

// 对不超过117位的内容进行加密
func (c *Signature) enc(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, c.pub, msg)
}

// 对不超过117位的内容进行揭秘啊
func (c *Signature) dec(cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, c.pri, cipher)
}

// Encrypt 分段加密
func (c *Signature) Encrypt(msg string) ([]byte, error) {
	var ss = c.split(msg, c.pub.N.BitLen()/8-11)
	var enc []byte
	for i := 0; i < len(ss); i++ {
		res, err := c.enc([]byte(ss[i]))
		if err != nil {
			return nil, err
		}
		enc = append(enc, res...)
	}
	var ret = make([]byte, base64.StdEncoding.EncodedLen(len(enc)))
	base64.StdEncoding.Encode(ret, enc)
	return ret, nil
}

// Decrypt 分段解密
func (c *Signature) Decrypt(cipher string) ([]byte, error) {
	bs, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return nil, err
	}
	var ss = c.split(string(bs), c.pri.N.BitLen()/8)
	var enc []byte
	for i := 0; i < len(ss); i++ {
		res, err := c.dec([]byte(ss[i]))
		if err != nil {
			return nil, err
		}
		enc = append(enc, res...)
	}

	return enc, nil
}

// 分段
func (c *Signature) split(s string, length int) []string {
	var result []string
	for i := 0; i < len(s); i += length {
		end := i + length
		if end > len(s) {
			end = len(s)
		}
		result = append(result, s[i:end])
	}
	return result
}
