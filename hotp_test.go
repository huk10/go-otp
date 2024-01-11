package otp

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

const TestSecret20 = "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6"
const TestSecret32 = "K2KE5WEAW2IIASRZYEPEQI2JAR73LSRM5HQOXBAWZEIHSULURI4A"
const TestSecret64 = "RJX2JMKSDPMS6OFJTRA3TXUNYMG2VCMGO3S7DQA2I34PTPON5DFWGEI6QXEXMJYUNEXCVLR7W2AX7AO52QNTG2TK5EWJ26JROIP6GBI"

func TestNewHOTP(t *testing.T) {
	t.Run("test default params", func(t *testing.T) {
		hotp := NewHOTP(TestSecret20)
		assert.Equal(t, hotp.Skew, 0)
		assert.Equal(t, hotp.Counter, int64(1))
		assert.Equal(t, hotp.Digits, DigitsSix)
		assert.Equal(t, hotp.Algorithm, AlgorithmSHA1)
		assert.Equal(t, hotp.Secret, TestSecret20)
	})

	t.Run("test custom params", func(t *testing.T) {
		hotp2 := NewHOTP(TestSecret32, WithCounter(2), WithDigits(DigitsEight), WithAlgorithm(AlgorithmSHA256), WithSkew(1))
		assert.Equal(t, hotp2.Skew, 1)
		assert.Equal(t, hotp2.Counter, int64(2))
		assert.Equal(t, hotp2.Digits, DigitsEight)
		assert.Equal(t, hotp2.Secret, TestSecret32)
		assert.Equal(t, hotp2.Algorithm, AlgorithmSHA256)
	})

	t.Run("test error params", func(t *testing.T) {
		hotp3 := NewHOTP(TestSecret20, WithSkew(-1))
		assert.Equal(t, minSkewNumber, hotp3.Skew)
	})

	// test panic
	assert.PanicsWithError(t, ErrSecretCannotBeEmpty.Error(), func() {
		NewHOTP("")
	})
	assert.PanicsWithError(t, ErrSecretDecode.Error(), func() {
		NewHOTP("111111")
	})
}

func TestHOTP_At(t *testing.T) {
	var cases = map[int64]string{
		1: "347255",
		2: "340510",
		3: "390142",
		4: "440452",
	}
	hotp := NewHOTP(TestSecret20)
	for counter, expected := range cases {
		actual := hotp.At(counter)
		assert.Equal(t, expected, actual)
	}
}

// online verify : https://www.verifyr.com/en/otp/check
func TestHOTP_Verify(t *testing.T) {
	// test true
	var cases = map[int64]string{
		1: "347255",
		2: "340510",
		3: "390142",
		4: "440452",
	}
	hotp := NewHOTP(TestSecret20)
	for counter, token := range cases {
		actual := hotp.Verify(token, counter)
		assert.Equal(t, true, actual)
	}

	// test false
	var cases2 = map[int64]string{
		0: "347255",
		1: "340510",
		2: "390142",
		3: "440452",
	}
	hotp2 := NewHOTP(TestSecret20)
	for counter, token := range cases2 {
		actual := hotp2.Verify(token, counter)
		assert.Equal(t, false, actual)
	}

	// test error params
	assert.Equal(t, hotp2.Verify("", 1), false)

	t.Run("test skew param 1", func(t *testing.T) {
		hotp3 := NewHOTP(TestSecret20, WithSkew(1))
		for counter, token := range cases2 {
			actual := hotp3.Verify(token, counter)
			assert.Equal(t, true, actual)
		}
	})

	t.Run("test skew param 2", func(t *testing.T) {
		//  1: "347255",
		//	2: "340510",
		//	3: "390142",
		//	4: "440452",
		//	5: "307530",
		//	6: "863952",
		//	7: "740274",
		hotp4 := NewHOTP(TestSecret20, WithSkew(2))
		assert.Equal(t, hotp4.Verify("440452", 4), true)
		assert.Equal(t, hotp4.Verify("440452", 2), true)
		assert.Equal(t, hotp4.Verify("440452", 6), true)
		assert.Equal(t, hotp4.Verify("440452", 1), false)
		assert.Equal(t, hotp4.Verify("440452", 7), false)
	})

	t.Run("test sha256 algorithm", func(t *testing.T) {
		hotp := NewHOTP(TestSecret32, WithAlgorithm(AlgorithmSHA256))
		assert.Equal(t, hotp.Verify("508563", 1), true)
	})

	t.Run("test sha512 algorithm", func(t *testing.T) {
		hotp := NewHOTP(TestSecret64, WithAlgorithm(AlgorithmSHA512))
		assert.Equal(t, hotp.Verify("777051", 1), true)
	})
}

func TestHOTP_KeyURI(t *testing.T) {
	t.Run("default parameters", func(t *testing.T) {
		hotp := NewHOTP(TestSecret20)
		uri := hotp.KeyURI("alice@google.com", "Example")
		expected := fmt.Sprintf("otpauth://hotp/Example:alice@google.com?secret=%s&issuer=Example&counter=1", TestSecret20)
		expectedKeyUri := &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    TestSecret20,
		}
		assert.Equal(t, expected, uri.URI().String())
		assert.Equal(t, expectedKeyUri, uri)
	})

	t.Run("custom parameters", func(t *testing.T) {
		hotp2 := NewHOTP(TestSecret32, WithCounter(2), WithDigits(DigitsEight), WithAlgorithm(AlgorithmSHA256))
		uri2 := hotp2.KeyURI("alice@google.com", "Example")
		expected2 := fmt.Sprintf("otpauth://hotp/Example:alice@google.com?secret=%s&issuer=Example&algorithm=SHA256&digits=8&counter=2", TestSecret32)
		expectedKeyUri2 := &KeyURI{
			Digits:    8,
			Counter:   2,
			Type:      "hotp",
			Algorithm: "SHA256",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    TestSecret32,
		}
		assert.Equal(t, expected2, uri2.URI().String())
		assert.Equal(t, expectedKeyUri2, uri2)
	})
}
