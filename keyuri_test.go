package otp

import (
	"bytes"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/stretchr/testify/assert"
	"image"
	"testing"
)

// J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6
func TestFromURI(t *testing.T) {
	t.Run("case1: default params", func(t *testing.T) {
		// hotp
		expected := "otpauth://hotp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1&issuer=Example"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)

		// totp
		expected2 := "otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example"
		uri2, err := FromURI(expected2)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Period:    30,
			Type:      "totp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri2)
	})

	t.Run("case2: complete parameters including optional parameters", func(t *testing.T) {
		expected := "otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&algorithm=SHA256&digits=8&period=60"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    8,
			Period:    60,
			Type:      "totp",
			Algorithm: "SHA256",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)
	})

	t.Run("case3: different algorithm parameter values", func(t *testing.T) {
		expected := "otpauth://hotp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&algorithm=SHA1"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)

		expected2 := "otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&algorithm=SHA512"
		uri2, err := FromURI(expected2)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Period:    30,
			Type:      "totp",
			Algorithm: "SHA512",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri2)
	})

	t.Run("case4: bad uris and uris that don t support parameters", func(t *testing.T) {
		var errorUris = []string{
			// 缺参数，无法识别等。
			"otpauth1://to1tp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example",
			"otpauth://totp1/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example",
			"otpauth://xxxx/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example",
			"otpauth://totp/Example:alice@google.com?counter=1&issuer=Example",
			// 不支持的参数
			// algorithm 不支持 md5
			"otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1&issuer=Example&algorithm=md5",
			// Digits 只支持 6 和 8
			"otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1&issuer=Example&digits=4",
			// period 不能小于 minPeriodNumber
			"otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1&issuer=Example&period=4",
		}
		for _, uri := range errorUris {
			_, err := FromURI(uri)
			assert.Error(t, ErrURIFormat, err)
		}
	})

	t.Run("case5: label 存在 issuer 值，URI 不存在 issuer 参数", func(t *testing.T) {
		expected := "otpauth://hotp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)
	})

	t.Run("case6: label 不存在 issuer 值，但是 URI 存在 issuer 参数", func(t *testing.T) {
		expected := "otpauth://hotp/alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&counter=1"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)
	})

	t.Run("case7: label 中没有 issuer 值，URI 中也没有 issuer 参数", func(t *testing.T) {
		expected := "otpauth://hotp/alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&counter=1"
		uri, err := FromURI(expected)
		assert.Nil(t, err)
		assert.Equal(t, &KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "",
			Label:     "alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}, uri)
	})
}

func TestKeyURI_URI(t *testing.T) {
	t.Run("uri for default parameters", func(t *testing.T) {
		expected := "otpauth://hotp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&counter=1"
		assert.Equal(t, expected, KeyURI{
			Digits:    6,
			Counter:   1,
			Type:      "hotp",
			Algorithm: "SHA1",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}.URI().String())
	})

	t.Run("fully parameterized uri", func(t *testing.T) {
		expected := "otpauth://totp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&algorithm=SHA256&digits=8&period=60"
		assert.Equal(t, expected, KeyURI{
			Digits:    8,
			Period:    60,
			Type:      "totp",
			Algorithm: "SHA256",
			Issuer:    "Example",
			Label:     "Example:alice@google.com",
			Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
		}.URI().String())
	})
}

func TestKeyURI_QRCode(t *testing.T) {
	expected := "otpauth://hotp/Example:alice@google.com?secret=J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6&issuer=Example&counter=1"
	key := KeyURI{
		Digits:    6,
		Counter:   1,
		Type:      "hotp",
		Algorithm: "SHA1",
		Issuer:    "Example",
		Label:     "Example:alice@google.com",
		Secret:    "J3W2XPZP5HDYXYRB4HS6ZLU6M6VBO6C6",
	}
	png, err := key.QRCode()
	assert.Nil(t, err)
	img, _, err := image.Decode(bytes.NewReader(png))
	assert.Nil(t, err)
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	assert.Nil(t, err)
	qrReader := qrcode.NewQRCodeReader()
	result, err := qrReader.Decode(bmp, nil)
	assert.Nil(t, err)
	assert.Equal(t, expected, result.String())
}
