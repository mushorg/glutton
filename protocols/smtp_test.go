package protocols

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateMail(t *testing.T) {
	require.True(t, validateMail("MAIL FROM:<example@example.com>"), "email regex validation failed")
	require.False(t, validateMail("MAIL FROM:<example.com>"), "email regex validation failed")
}

func TestValidateRCPT(t *testing.T) {
	require.True(t, validateRCPT("RCPT TO:<example@example.com>"), "validate rcpt regex failed")
	require.False(t, validateRCPT("RCPT TO:<example.com>"), "validate rcpt regex failed")
}
