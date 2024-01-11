package otp

import (
	"crypto/hmac"
	"fmt"
	"net/url"
)

// HOTP 基于 RFC-4266 的 HOTP 算法
type HOTP struct {
	Otp
	// base32 encoded string
	Secret string
	// base32 decoded string
	decodedSecret []byte
}

// NewHOTP 创建一个 HOTP 结构体，可以使用 option 的模式传递参数。
//
// Params:
//
//	secret       : 必传，一个 base32 编码后的字符串，建议使用 RandomSecret 方法生成的。
//	WithCounter  : 设置初始计数器，该值仅用于 KeyURI 方法。
//	WithSkew     : 是否校验相邻的窗口。
//	WithAlgorithm: 设置 hmac 算法类型。
//
// Panic:
//   - secret base32 decode error
//   - secret is an empty string
//
// 注意: Google Authenticator 可能仅支持 Counter 这一个参数
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Example:
//
//	secret := Base32Encode(RandomSecret(20))
//	hotp   := NewHOTP(secret, WithCounter(2))
func NewHOTP(secret string, options ...Option) *HOTP {
	if secret == "" {
		panic(ErrSecretCannotBeEmpty)
	}
	decodedSecret, err := Base32Decode(secret)
	if err != nil {
		panic(ErrSecretDecode)
	}
	otp := Otp{
		Skew:      0,
		Counter:   1,
		Period:    30,
		Algorithm: AlgorithmSHA1,
		Digits:    DigitsSix,
	}
	for _, opt := range options {
		opt(&otp)
	}
	return &HOTP{
		Otp:           otp,
		Secret:        secret,
		decodedSecret: decodedSecret,
	}
}

// At 通过指定的 Counter 生成一个 token。
//
// Example：
//
//	hotp  := NewHOTP(Base32Encode(RandomSecret(20)))
//	token := hotp.At(1)  	       // 使用的 1 作为counter 生成 token
//	bool  := hotp.Verify(token, 1) // 校验 token 是否有效
func (h *HOTP) At(counter int64) string {
	s := intToByte(counter)
	hashFunc := hasher(h.Algorithm)
	mac := hmac.New(hashFunc, h.decodedSecret)
	mac.Write(s)
	hex := mac.Sum(nil)
	return truncate(hex, int(h.Digits))
}

// Verify 校验token是否有效，窗口内的所有结果都认为有效。
//
// Params:
//
//	token  : 需要进行校验的参数，一个字符串，如果字符串为空将会返回 false
//	counter: 计数器
//
// Example:
//
//	hotp  := NewHOTP(Base32Encode(RandomSecret(20)), WithSkew(1))
//	token := hotp.At(2)  		   // 使用的 2 作为counter 生成 token
//	bool  := hotp.Verify(token, 2) // 通过 WithSkew 方法指定 skew 参数为1，那么这里将会校验 counter 为 1、2、3 的token
func (h *HOTP) Verify(token string, counter int64) bool {
	if token == "" {
		return false
	}
	c := counter
	for i := c - int64(h.Skew); i <= c+int64(h.Skew); i++ {
		if h.At(i) == token {
			return true
		}
	}
	return false
}

// KeyURI 返回一个 KeyURI 结构体，其包含转换至 URI 和生成二维码的方法。
func (h *HOTP) KeyURI(account, issuer string) *KeyURI {
	ret := &KeyURI{
		Type:      "hotp",
		Label:     url.PathEscape(fmt.Sprintf("%s:%s", issuer, account)),
		Counter:   h.Counter,
		Digits:    int(h.Digits),
		Algorithm: h.Algorithm.String(),
		Issuer:    url.QueryEscape(issuer),
		Secret:    h.Secret,
	}
	return ret
}
