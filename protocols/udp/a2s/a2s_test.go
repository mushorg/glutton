package a2s

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// Captured A2S_INFO probe (Ochi event 30663010-330d-4591-a029-ed39571b919d).
const capturedInfo = "ffffffff54536f7572636520456e67696e6520517565727900"

func TestParseInfoWithoutChallenge(t *testing.T) {
	req, err := Parse(mustHex(t, capturedInfo))
	require.NoError(t, err)
	require.Equal(t, TypeInfo, req.Type)
	require.Equal(t, InfoQuery, req.Query)
	require.Nil(t, req.Challenge)
	require.Empty(t, req.ChallengeHex())
	require.True(t, req.WantsChallenge())
}

func TestParseInfoWithChallenge(t *testing.T) {
	req, err := Parse(mustHex(t, capturedInfo+"0a0b0c0d"))
	require.NoError(t, err)
	require.Equal(t, "0a0b0c0d", req.ChallengeHex())
	require.False(t, req.WantsChallenge())
}

func TestParseInfoUnterminated(t *testing.T) {
	req, err := Parse(mustHex(t, "ffffffff54536f75726365"))
	require.Error(t, err)
	require.Equal(t, TypeInfo, req.Type)
	require.Equal(t, "Source", req.Query)
}

// Captured unterminated A2S_INFO probe (Ochi event 04a9a553-2ae9-4615-8167-e930548cc021).
const capturedInfoNoNUL = "ffffffff54536f7572636520456e67696e65205175657279"

func TestParseInfoWithoutNUL(t *testing.T) {
	req, err := Parse(mustHex(t, capturedInfoNoNUL))
	require.NoError(t, err)
	require.Equal(t, TypeInfo, req.Type)
	require.Equal(t, InfoQuery, req.Query)
	require.Nil(t, req.Challenge)
	require.True(t, req.WantsChallenge())

	req, err = Parse(mustHex(t, capturedInfoNoNUL+"0a0b0c0d"))
	require.NoError(t, err)
	require.Equal(t, "0a0b0c0d", req.ChallengeHex())
	require.False(t, req.WantsChallenge())

	req, err = Parse(mustHex(t, capturedInfoNoNUL+"0a0b"))
	require.Error(t, err)
	require.Equal(t, TypeInfo, req.Type)
}

func TestParsePlayerAndRules(t *testing.T) {
	req, err := Parse(mustHex(t, "ffffffff55ffffffff"))
	require.NoError(t, err)
	require.Equal(t, TypePlayer, req.Type)
	require.Equal(t, "ffffffff", req.ChallengeHex())
	require.True(t, req.WantsChallenge())

	req, err = Parse(mustHex(t, "ffffffff5601020304"))
	require.NoError(t, err)
	require.Equal(t, TypeRules, req.Type)
	require.False(t, req.WantsChallenge())

	req, err = Parse(mustHex(t, "ffffffff55ffff"))
	require.Error(t, err)
	require.Equal(t, TypePlayer, req.Type)
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(nil)
	require.Error(t, err)
	_, err = Parse(mustHex(t, "fffffffe54"))
	require.Error(t, err)
	req, err := Parse(mustHex(t, "ffffffff7a"))
	require.Error(t, err)
	require.Equal(t, "UNKNOWN", Name(req.Type))
}

func TestLooksLikeA2S(t *testing.T) {
	require.True(t, LooksLikeA2S(mustHex(t, capturedInfo)))
	require.True(t, LooksLikeA2S(mustHex(t, "ffffffff57")))
	require.True(t, LooksLikeA2S(mustHex(t, "ffffffff69")))
	require.False(t, LooksLikeA2S(nil))
	require.False(t, LooksLikeA2S(mustHex(t, "ffffffff")))
	require.False(t, LooksLikeA2S(mustHex(t, "ffffffff41")))               // server reply
	require.False(t, LooksLikeA2S([]byte("\xff\xff\xff\xffgetstatus\n")))  // Quake 3
	require.False(t, LooksLikeA2S(mustHex(t, "feffffff54536f7572636520"))) // split packet
}

func TestBuildChallenge(t *testing.T) {
	require.Equal(t, mustHex(t, "ffffffff4178563412"), BuildChallenge(0x12345678))
}
