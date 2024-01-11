package otp

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"math"
	"strconv"
	"strings"
)

// RandomSecret 获取一个给定长度(字节数)的随机秘钥，如果生成失败将会 panic。
//
// 建议存储时将其转换至 base32 或其他的编码，直接转换成字符串可能会存在换行符等奇怪的字符。
//
// 内部使用 rand.Read 方法，如果此方法报错将会 panic
//
// rfc4266 中建议 secret 最少为 160 位也就是 20 个字节。
//
//	https://datatracker.ietf.org/doc/html/rfc4226
//
// 也可看下此文档解释自行选择合适长度：
//
//	https://github.com/darrenedale/php-totp/blob/HEAD/Secrets.md
func RandomSecret(length int) []byte {
	// 建议选择适合对应 hmac 算法的长度。
	// HMAC-SHA1   建议选择 20 字节长度
	// HMAC-SHA256 建议选择 32 字节长度
	// HMAC-SHA512 建议选择 64 字节长度
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return randomBytes
}

// Base32Decode 对一个字符串进行 base32 解码
func Base32Decode(str string) ([]byte, error) {
	// base32 只包含大小字母
	upper := strings.ToUpper(str)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
}

// Base32Encode 对一个字符串进行 base32 编码
func Base32Encode(str []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(str)
}

// padZero 在字符串的签名填充数字0
func padZero(value string, size int) string {
	if len(value) >= size {
		return value
	}
	return strings.Repeat("0", size-len(value)) + value
}

// intToByte 数字转换成二进制字节格式
func intToByte(number int64) []byte {
	result := make([]byte, 0, 8)
	shifts := []uint{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((number>>shift)&0xff))
	}
	return result
}

// truncate 计算出指定位数的数字字符串(不足位数前面补0)
func truncate(h []byte, digits int) string {
	offset := h[len(h)-1] & 0xf
	bits := uint32(h[offset]&0x7f)<<24 |
		uint32(h[offset+1]&0xff)<<16 |
		uint32(h[offset+2]&0xff)<<8 |
		uint32(h[offset+3]&0xff)
	value := bits % uint32(math.Pow10(digits))
	return padZero(strconv.Itoa(int(value)), digits)
}

func hasher(algorithm Algorithms) func() hash.Hash {
	switch algorithm {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		panic("unreachable")
	}
}

func atoi(str string, def int) (int, error) {
	if str == "" {
		return def, nil
	}
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func parseInt(str string, def int64, base int, bitSize int) (int64, error) {
	if str == "" {
		return def, nil
	}
	val, err := strconv.ParseInt(str, base, bitSize)
	if err != nil {
		return 0, err
	}
	return val, nil
}
