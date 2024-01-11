package otp

import (
	"crypto/hmac"
	"fmt"
	"net/url"
	"time"
)

// TOTP 基于 RFC-6238 的 TOTP 算法
type TOTP struct {
	Otp
	// base32 encoded string
	Secret string
	// base32 decoded string
	decodedSecret []byte
}

// NewTOTP 创建一个 TOTP 结构体，可以使用 option 的模式传递参数。
//
// Params:
//
//	secret       : 必传，一个 base32 编码后的字符串，建议使用 RandomSecret 方法生成的。
//	WithPeriod   : 设置 token 有效期长度。
//	WithSkew     : 是否校验相邻的窗口。
//	WithAlgorithm: 设置 hmac 算法类型。
//
// Panic:
//   - secret base32 decode error
//   - secret is an empty string
//
// 默认参数才是 Google Authenticator 兼容的，自定义参数的话 Google Authenticator 可能不会识别。
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Example:
//
//	secret := Base32Encode(RandomSecret(20))
//	totp   := NewTOTP(secret, WithDigits(DigitsEight))
func NewTOTP(secret string, options ...Option) *TOTP {
	if secret == "" {
		panic(ErrSecretCannotBeEmpty)
	}
	decodedSecret, err := Base32Decode(secret)
	if err != nil {
		fmt.Println(err, secret)
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
	return &TOTP{
		Otp:           otp,
		Secret:        secret,
		decodedSecret: decodedSecret,
	}
}

// Now 基于当前时间点生成 token。
func (o *TOTP) Now() string {
	return o.At(time.Now())
}

// At 生成某个时间点的 token。
func (o *TOTP) At(t time.Time) string {
	key := intToByte(t.Unix() / int64(o.Period))
	hashFunc := hasher(o.Algorithm)
	mac := hmac.New(hashFunc, o.decodedSecret)
	mac.Write(key)
	h := mac.Sum(nil)
	return truncate(h, int(o.Digits))
}

// WithExpiration 获取指定时间的 token 和对应的剩余有效时间。
func (o *TOTP) WithExpiration(t time.Time) (string, int) {
	token := o.At(t)
	expiration := o.Expiration(t)
	return token, expiration
}

// Expiration 获取指定时间窗口的 token 剩余有效时间。
func (o *TOTP) Expiration(t time.Time) int {
	return int(int64(o.Period) - t.Unix()%int64(o.Period))
}

// Verify 校验 token 是否在指定的时间有效。
//
// Params:
//
//	token: 需要进行校验的参数，一个字符串，如果字符串为空将会返回 false。
//	t    : 指定的时间，用以校验 token 在这个时间点是否仍有效。
func (o *TOTP) Verify(token string, t time.Time) bool {
	if token == "" {
		return false
	}
	givenTime := t
	sec := t.Unix()
	for i := o.Skew * -1; i <= o.Skew; i++ {
		givenTime = time.Unix(sec, 0).Add(time.Second * time.Duration(o.Period*i))
		if o.At(givenTime) == token {
			return true
		}
	}
	return false
}

// KeyURI 返回一个 KeyURI 结构体，其包含转换至 URI 和生成二维码的方法。
func (o *TOTP) KeyURI(account, issuer string) *KeyURI {
	ret := &KeyURI{
		Type:      "totp",
		Label:     url.PathEscape(fmt.Sprintf("%s:%s", issuer, account)),
		Algorithm: o.Algorithm.String(),
		Digits:    int(o.Digits),
		Period:    o.Period,
		Issuer:    url.QueryEscape(issuer),
		Secret:    o.Secret,
	}
	return ret
}
