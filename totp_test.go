package otp

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// 2024/01/01 10:10:00  1704075000000

func TestNewTOTP(t *testing.T) {
	t.Run("test default params", func(t *testing.T) {
		totp := NewTOTP(TestSecret20)
		assert.Equal(t, totp.Skew, 0)
		assert.Equal(t, totp.Period, 30)
		assert.Equal(t, totp.Digits, DigitsSix)
		assert.Equal(t, totp.Algorithm, AlgorithmSHA1)
		assert.Equal(t, totp.Secret, TestSecret20)
	})

	t.Run("test custom params", func(t *testing.T) {
		totp2 := NewTOTP(TestSecret32, WithPeriod(20), WithDigits(DigitsEight), WithAlgorithm(AlgorithmSHA256), WithSkew(1))
		assert.Equal(t, totp2.Skew, 1)
		assert.Equal(t, totp2.Period, 20)
		assert.Equal(t, totp2.Digits, DigitsEight)
		assert.Equal(t, totp2.Secret, TestSecret32)
		assert.Equal(t, totp2.Algorithm, AlgorithmSHA256)
	})

	t.Run("test error params", func(t *testing.T) {
		totp3 := NewTOTP(TestSecret20, WithPeriod(0), WithSkew(-1))
		assert.Equal(t, minPeriodNumber, totp3.Period)
		assert.Equal(t, minSkewNumber, totp3.Skew)
	})

	// test panic
	assert.PanicsWithError(t, ErrSecretCannotBeEmpty.Error(), func() {
		NewTOTP("")
	})
	assert.PanicsWithError(t, ErrSecretDecode.Error(), func() {
		NewHOTP("111111")
	})
}

func TestTOTP_Now(t *testing.T) {
	totp := NewTOTP(TestSecret20)
	token := totp.Now()
	assert.Equal(t, true, totp.Verify(token, time.Now()))
}

func TestTOTP_At(t *testing.T) {
	totp := NewTOTP(TestSecret20)
	time1 := time.Unix(1704075000000, 0)
	token := totp.At(time1)
	assert.Equal(t, "076141", token)
}

func TestTOTP_WithExpiration(t *testing.T) {
	totp := NewTOTP(TestSecret20)
	sec := int64(1704075000000)
	token, expiration := totp.WithExpiration(time.Unix(sec, 0))
	assert.Equal(t, "076141", token)
	assert.Equal(t, 30, expiration)

	token1, expiration1 := totp.WithExpiration(time.Unix(sec, 0).Add(time.Second))
	assert.Equal(t, "076141", token1)
	assert.Equal(t, 29, expiration1)

	token2, expiration2 := totp.WithExpiration(time.Unix(sec, 0).Add(time.Second * 28))
	assert.Equal(t, "076141", token2)
	assert.Equal(t, 2, expiration2)
}

func TestTOTP_Expiration(t *testing.T) {
	totp := NewTOTP(TestSecret20)
	time1 := time.Unix(1704075000000, 0)
	assert.Equal(t, 30, totp.Expiration(time1))
	assert.Equal(t, 29, totp.Expiration(time1.Add(time.Second)))
}

// online verify : https://www.verifyr.com/en/otp/check
func TestTOTP_Verify(t *testing.T) {
	sec := int64(1704075000000)
	totp := NewTOTP(TestSecret20)
	assert.Equal(t, true, totp.Verify("076141", time.Unix(sec, 0)))
	assert.Equal(t, true, totp.Verify("076141", time.Unix(sec, 0).Add(time.Second*30-time.Second)))
	assert.Equal(t, false, totp.Verify("076141", time.Unix(sec, 0).Add(time.Second*30)))
	assert.Equal(t, false, totp.Verify("076141", time.Now()))

	// test error params
	assert.Equal(t, false, totp.Verify("", time.Now()))

	// test skew param
	totp1 := NewTOTP(TestSecret20, WithSkew(1))
	// 下一个时间窗口
	assert.Equal(t, true, totp1.Verify("076141", time.Unix(sec, 0).Add(time.Second*30)))
	// 下两个时间窗口
	assert.Equal(t, false, totp1.Verify("076141", time.Unix(sec, 0).Add(time.Second*30*2)))
	// 上一个时间窗口
	assert.Equal(t, true, totp1.Verify("076141", time.Unix(sec, 0).Add(time.Second*30*-1)))
	// 上两个时间窗口
	assert.Equal(t, false, totp1.Verify("076141", time.Unix(sec, 0).Add(time.Second*30*2*-1)))

	t.Run("test sha256 algorithm", func(t *testing.T) {
		totp := NewTOTP(TestSecret32, WithAlgorithm(AlgorithmSHA256))
		assert.Equal(t, totp.Verify("558790", time.Unix(sec, 0)), true)
	})

	t.Run("test sha512 algorithm", func(t *testing.T) {
		totp := NewTOTP(TestSecret64, WithAlgorithm(AlgorithmSHA512))
		assert.Equal(t, totp.Verify("720824", time.Unix(sec, 0)), true)
	})
}

func TestTOTP_KeyURI(t *testing.T) {
	t.Run("default parameters", func(t *testing.T) {
		totp := NewTOTP(TestSecret20)
		uri := totp.KeyURI("alice@google.com", "Example")
		expected := fmt.Sprintf("otpauth://totp/Example:alice@google.com?secret=%s&issuer=Example", TestSecret20)
		expectedKeyUri := &KeyURI{
			Digits:    6,
			Period:    30,
			Type:      "totp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    TestSecret20,
		}
		assert.Equal(t, expected, uri.URI().String())
		assert.Equal(t, expectedKeyUri, uri)
	})

	t.Run("custom parameters", func(t *testing.T) {
		totp2 := NewTOTP(TestSecret32, WithPeriod(60), WithDigits(DigitsEight), WithAlgorithm(AlgorithmSHA256))
		uri2 := totp2.KeyURI("alice@google.com", "Example")
		expected2 := fmt.Sprintf("otpauth://totp/Example:alice@google.com?secret=%s&issuer=Example&algorithm=SHA256&digits=8&period=60", TestSecret32)
		expectedKeyUri2 := &KeyURI{
			Digits:    8,
			Period:    60,
			Type:      "totp",
			Algorithm: "SHA256",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    TestSecret32,
		}
		assert.Equal(t, expected2, uri2.URI().String())
		assert.Equal(t, expectedKeyUri2, uri2)
	})
}
