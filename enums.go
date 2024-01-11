package otp

import (
	"errors"
	"strings"
)

var (
	ErrURIFormat           = errors.New("uri format error")
	ErrSecretDecode        = errors.New("secret base32 decode error")
	ErrSecretCannotBeEmpty = errors.New("secret cannot be empty")
)

var (
	minSkewNumber   = 0
	minPeriodNumber = 10
)

// Algorithms 支持的 HMAC 类型。
//
// 默认值：HMAC_SHA1，与 Google Authenticator 兼容。
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
type Algorithms int

const (
	AlgorithmSHA1 Algorithms = iota + 1
	AlgorithmSHA256
	AlgorithmSHA512
)

// String 枚举值转换为字符串形式 - 该值可以放置在 uri 上。
func (h Algorithms) String() string {
	switch h {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		panic("unreachable")
	}
}

// from 从字符串转换至 Algorithms 枚举
func (h Algorithms) from(str string) (Algorithms, error) {
	switch strings.ToUpper(str) {
	case "":
		return AlgorithmSHA1, nil
	case "SHA1":
		return AlgorithmSHA1, nil
	case "SHA256":
		return AlgorithmSHA256, nil
	case "SHA512":
		return AlgorithmSHA512, nil
	default:
		return 0, errors.New("unknown 'algorithm' string")
	}
}

// Digits 生成出来的一次性密码的长度。6 和 8 是最常见的值。
type Digits int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// from 从 int 类型转换至 Digits 枚举
func (d Digits) from(i int) (Digits, error) {
	switch i {
	case 6:
		return DigitsSix, nil
	case 8:
		return DigitsEight, nil
	default:
		return 0, errors.New("unknown 'digits' number")
	}
}
