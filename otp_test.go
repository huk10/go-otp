package otp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBase32Encode(t *testing.T) {
	for i := 0; i < 100; i++ {
		expected := RandomSecret(20)
		base32 := Base32Encode(expected)
		actual, err := Base32Decode(base32)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestRandomSecret(t *testing.T) {
	result := RandomSecret(20)
	assert.Equal(t, 20, len(result))
}
