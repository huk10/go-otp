// Package otp
// One-Time Password (HOTP and TOTP) library for Go. Implements RFC 4226 and RFC 6238.
//
// Support Google Authenticator.
//
// Example:
//	// 随机生成一个 20 字节的秘钥
//	secret := otp.Base32Encode(otp.RandomSecret(20))
//	totp := otp.NewTOTP(secret)
//	// 基于当前时间生成一个 token
//	token := totp.Now()
//	// 校验 token 是否在指定的时间有效
//	if totp.Verify(token, time.Now()) {
//		// token 有效
//	}
//	// 生成一个二维码，此可二维码可以使用 Google Authenticator 扫码导入。
//	png, err := totp.KeyURI("bar@foo.com", "Example").QRCode()
//	if err != nil {
//		panic(err)
//	}
//	// 将二维码写入到本地文件中
//	err = os.WriteFile("./example/qrcode.png", png, 0666)
//	if err != nil {
//		panic(err)
//	}
package otp
