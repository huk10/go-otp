package otp

type Otp struct {
	// 指定时间窗口，默认 30 秒有效期。
	// Google Authenticator 可能仅支持默认参数。
	Period int
	// 初始计数器数值，默认为 1。
	// 该参数仅用来指定 otpauth uri 上的 counter 参数，不会使用它来生成 token
	Counter int64
	// 指定一次性密码的长度，默认 6 位数字。
	// Google Authenticator 可能仅支持默认参数。
	Digits Digits
	// 是否校验相邻的时间窗口，默认为 0。
	// 有些时候服务端的时间和客户端的时间并不是同步的，存在时间误差，再加上网络延时，一次性密码的剩余有效期等等，密码刚到达服务端可能就过期了，
	// 这时候可以通过此参数为相邻几个时间窗口进行校验，加强用户体验，但是安全性降低了。
	// 如果此参数为1，那么会同时校验当前时间窗口、上个时间窗口以及下个时间窗口。如果是 HOTP 那么就是相邻的计数器。
	Skew int
	// 指定 hmac 算法，默认 hmac-sha1
	// Google Authenticator 可能仅支持默认参数。
	Algorithm Algorithms
}

type Option func(opt *Otp)

// WithSkew 配置同时校验的窗口数，默认为 0 仅校验当前时间窗口。
//
// 取值范围是：skew >=0 如果传入的值小于 0 将会设置为 0。
func WithSkew(skew int) Option {
	return func(opt *Otp) {
		if skew < minSkewNumber {
			skew = minSkewNumber
		}
		opt.Skew = skew
	}
}

// WithDigits 配置一次性密码的显示长度，默认为 6, Google Authenticator 可能不支持其他的长度。
func WithDigits(digits Digits) Option {
	return func(opt *Otp) {
		opt.Digits = digits
	}
}

// WithPeriod 配置时间一次性密码的有效期，默认 30 秒，仅支持 TOTP 类型。
//
// 取值范围是：period >=10 如果传入的值小于 10 将会设置为 10。
func WithPeriod(period int) Option {
	return func(opt *Otp) {
		if period < minPeriodNumber {
			period = minPeriodNumber
		}
		opt.Period = period
	}
}

// WithCounter 配置计数器的值，默认为 1 (Google 的默认就是 1)，仅支持 HOTP 类型。
func WithCounter(counter int64) Option {
	return func(opt *Otp) {
		opt.Counter = counter
	}
}

// WithAlgorithm 配置哈希算法类型。
func WithAlgorithm(algorithm Algorithms) Option {
	return func(opt *Otp) {
		opt.Algorithm = algorithm
	}
}
