package otp

import (
	"fmt"
	"github.com/skip2/go-qrcode"
	"net/url"
	"strconv"
	"strings"
)

// KeyURI TOTP 或 HOTP 的 URI 包含的参数。
//
// URI 的格式可以参考：https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// 部分属性 Google Authenticator 可能不会采用仅支持默认值。具体细节可以查看上面链接的文档。
type KeyURI struct {
	// otp 算法的类型只能是 totp or hotp
	Type string
	// 标签，用于识别密钥与哪个帐户关联。它包含一个帐户名称，该名称是一个 URI 编码的字符串，可以选择以标识管理该帐户的提供商或服务的发行者字符串为前缀。
	// 发行者前缀和帐户名称应使用文字或 URL 编码的冒号分隔，并且帐户名称之前可以有可选空格。发行人或账户名称本身都不能包含冒号。
	// 根据 Google Authenticator 的建议，应该拼接发行商字符串为前缀。
	// 需要已被 url.QueryEscape 方法处理过。
	Label string
	// hotp 或 totp 采用的哈希算法类型
	// Google Authenticator 可能会忽略此参数，而采用默认值：HMAC-SHA1。
	Algorithm string
	// 向用户显示一次性密码的长度。默认值为 6。
	// Google Authenticator 可能会忽略此参数，而采用默认值 6。
	Digits int
	// 当 type 为 hotp 时必选，它将设置初始计数器值。
	Counter int64
	// 仅当 type 为 totp 时可选，该 period 参数定义 TOTP 密码的有效期限（以秒为单位）。默认值为 30。
	// Google Authenticator 可能会忽略此参数，而采用默认值 30。
	Period int
	// 发行商，使用 URL 编码进行编码的字符串
	// 需要已被 url.QueryEscape 方法处理过。
	Issuer string
	// base32 编码的任意字符，不应该填充。
	Secret string
}

// URI 生成 otpauth 的 URI 形式，可以将其作为二维码的内容供 Google Authenticator 扫码导入。
// params 顺序：secret、issuer、algorithm、digits、period、counter
func (p KeyURI) URI() *url.URL {
	u := url.URL{}
	u.Scheme = "otpauth"
	u.Host = p.Type
	u.Path = p.Label
	params := "secret=" + p.Secret
	params += "&issuer=" + p.Issuer

	if p.Algorithm != "SHA1" {
		params += "&algorithm=" + p.Algorithm
	}
	if p.Digits != 6 {
		params += "&digits=" + strconv.Itoa(p.Digits)
	}
	if p.Type == "totp" {
		if p.Period != 30 {
			params += "&period=" + strconv.Itoa(p.Period)
		}
	} else {
		params += "&counter=" + strconv.FormatInt(p.Counter, 10)
	}
	u.RawQuery = params
	return &u
}

// QRCode 将此 URI 信息生成一个二维码，可供 Google Authenticator 扫码导入。
func (p KeyURI) QRCode() ([]byte, error) {
	uri := p.URI().String()
	code, err := qrcode.New(uri, qrcode.Highest)
	if err != nil {
		return nil, err
	}
	png, err := code.PNG(256)
	if err != nil {
		return nil, err
	}
	return png, nil
}

// FromURI 解析 URI 创建一个 KeyURI 结构体。
func FromURI(uri string) (*KeyURI, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, ErrURIFormat
	}
	if u.Scheme != "otpauth" {
		return nil, ErrURIFormat
	}
	if u.Host != "hotp" && u.Host != "totp" {
		return nil, ErrURIFormat
	}
	query := u.Query()
	issuer := query.Get("issuer")
	secret := query.Get("secret")
	if secret == "" {
		return nil, ErrURIFormat
	}
	digits, err := atoi(query.Get("digits"), 6)
	if err != nil {
		return nil, ErrURIFormat
	}
	digitsEnum, err := Digits.from(DigitsSix, digits)
	if err != nil {
		return nil, ErrURIFormat
	}
	period, err := atoi(query.Get("period"), 30)
	if err != nil || period < minPeriodNumber {
		return nil, ErrURIFormat
	}
	counter, err := parseInt(query.Get("counter"), 1, 10, 64)
	if err != nil {
		return nil, ErrURIFormat
	}
	algorithm, err := Algorithms.from(AlgorithmSHA1, query.Get("algorithm"))
	if err != nil {
		return nil, ErrURIFormat
	}

	if u.Host == "hotp" {
		period = 0
	} else {
		counter = 0
	}

	// 按照规则 issuer 和 account 都不能包含 ":"
	path := strings.Split(u.Path, ":")
	// 如果 label 存在 issuer 但是 params 中不存在 issuer
	if issuer == "" {
		if len(path) > 1 {
			issuer = path[0][1:]
		}
	}
	var label = u.Path[1:]
	// 如果 label 不存在 issuer 但是 params 中存在 issuer
	if len(path) == 1 && issuer != "" {
		label = fmt.Sprintf("%s:%s", issuer, u.Path[1:])
	}

	key := &KeyURI{
		Type:      u.Host,
		Label:     label,
		Algorithm: algorithm.String(),
		Digits:    int(digitsEnum),
		Counter:   counter,
		Period:    period,
		Issuer:    issuer,
		Secret:    secret,
	}
	return key, nil
}
