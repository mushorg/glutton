package rdp

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func testSubjectPublicKey(t *testing.T) []byte {
	t.Helper()
	cert, err := helpers.SelfSignedCertificateRDP("WIN-NLATEST")
	require.NoError(t, err)
	c, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	pub := SubjectPublicKey(c)
	require.NotEmpty(t, pub)
	require.Equal(t, byte(0x00), pub[0], "BIT STRING unused-bits prefix")
	return pub
}

func TestAcceptNLARoundTrip(t *testing.T) {
	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{
		Computer: "WIN-TEST",
		Domain:   "WORKGROUP",
		Now:      fixedNow,
	})
	require.NoError(t, err)

	req, client, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)
	require.Equal(t, NTLMMsgAuthenticate, parsed.NTLMType)
	require.Equal(t, "administrator", parsed.Username)
	require.Equal(t, "WORKGROUP", parsed.Domain)
	require.Equal(t, "NTLMv2", parsed.NTLMVersion)
	require.Greater(t, parsed.NTResponseLen, 24)
	require.Len(t, parsed.NtChallengeResponse, parsed.NTResponseLen)
	require.NotEmpty(t, parsed.EncryptedRandomSessionKey)
	require.NotZero(t, parsed.NegotiateFlags)
	require.Equal(t, 6, parsed.CredSSPVersion)
	require.Len(t, parsed.ClientNonce, 16)
	require.NotEmpty(t, parsed.PubKeyAuth)

	out, ok := AcceptNLA(NLAInput{
		Parsed:           parsed,
		Password:         "Password1",
		ServerChallenge:  nonce,
		SubjectPublicKey: pub,
	})
	require.True(t, ok)
	require.NotNil(t, out)
	require.True(t, IsTSRequest(out.Reply))
	require.Empty(t, ParseCredSSP(out.Reply).AuthInfo)
	require.NotEmpty(t, ParseCredSSP(out.Reply).PubKeyAuth)

	info := client.ClientAuthInfo("WORKGROUP", "administrator", "Password1")
	got := ParseCredSSP(info)
	domain, user, password, ok := out.Session.OpenAuthInfo(got.AuthInfo)
	require.True(t, ok)
	require.Equal(t, "WORKGROUP", domain)
	require.Equal(t, "administrator", user)
	require.Equal(t, "Password1", password)
}

func TestAcceptNLAWrongPassword(t *testing.T) {
	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	_, ok := AcceptNLA(NLAInput{
		Parsed:           ParseCredSSP(req),
		Password:         "wrong",
		ServerChallenge:  nonce,
		SubjectPublicKey: pub,
	})
	require.False(t, ok)
}

func TestAcceptNLARequiresPubKeyAuth(t *testing.T) {
	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)
	parsed.PubKeyAuth = nil
	_, ok := AcceptNLA(NLAInput{Parsed: parsed, Password: "Password1", ServerChallenge: nonce, SubjectPublicKey: pub})
	require.False(t, ok)
}

func TestAcceptNLARejectsNTLMv1(t *testing.T) {
	parsed := ParsedCredSSP{
		NTResponseLen:       24,
		NtChallengeResponse: make([]byte, 24),
		PubKeyAuth:          []byte{1},
	}
	_, ok := AcceptNLA(NLAInput{Parsed: parsed, Password: "Password1", ServerChallenge: make([]byte, 8), SubjectPublicKey: []byte{1}})
	require.False(t, ok)
}

func TestMatchAccountAcceptList(t *testing.T) {
	viper.Set("rdp.credentials", []Account{{Username: "Administrator", Password: "Password1"}})
	t.Cleanup(func() { viper.Set("rdp.credentials", nil) })

	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)

	out, user, ok := MatchAccount(parsed, nonce, pub)
	require.True(t, ok)
	require.Equal(t, "administrator", user, "account used is the Type 3 username, not the config key")
	require.NotNil(t, out)

	req2, _, err := BuildClientAuthenticate(challenge, "guest", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	_, user, ok = MatchAccount(ParseCredSSP(req2), nonce, pub)
	require.True(t, ok, "a listed password matches any username")
	require.Equal(t, "guest", user)

	viper.Set("rdp.credentials", nil)
	_, _, ok = MatchAccount(parsed, nonce, pub)
	require.False(t, ok)
}

func TestAccountsEmptyDefault(t *testing.T) {
	viper.Set("rdp.credentials", nil)
	require.Empty(t, Accounts())
}

func TestMatchAccountGuessPasswords(t *testing.T) {
	viper.Set("rdp.credentials", nil)
	viper.Set("rdp.guess_passwords", []string{"nope", "Password1"})
	t.Cleanup(func() {
		viper.Set("rdp.credentials", nil)
		viper.Set("rdp.guess_passwords", nil)
	})

	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)

	out, user, ok := MatchAccount(parsed, nonce, pub)
	require.True(t, ok)
	require.Equal(t, "administrator", user)
	require.NotNil(t, out)

	reqWrong, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "other", pub)
	require.NoError(t, err)
	_, _, ok = MatchAccount(ParseCredSSP(reqWrong), nonce, pub)
	require.False(t, ok)
}

func TestGuessPasswordsCap(t *testing.T) {
	passwords := make([]string, maxGuessPasswords+1)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("pw-%d", i)
	}
	passwords[maxGuessPasswords] = "Password1"
	viper.Set("rdp.credentials", nil)
	viper.Set("rdp.guess_passwords", passwords)
	t.Cleanup(func() {
		viper.Set("rdp.credentials", nil)
		viper.Set("rdp.guess_passwords", nil)
	})

	require.Len(t, GuessPasswords(), maxGuessPasswords)
	require.NotContains(t, GuessPasswords(), "Password1")

	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)

	_, _, ok := MatchAccount(parsed, nonce, pub)
	require.False(t, ok, "the password past the cap is not tried")

	passwords[maxGuessPasswords-1] = "Password1"
	passwords[maxGuessPasswords] = "unused"
	viper.Set("rdp.guess_passwords", passwords)
	_, user, ok := MatchAccount(parsed, nonce, pub)
	require.True(t, ok, "the last entry inside the cap is tried")
	require.Equal(t, "administrator", user)
}

func TestNetNTLMv2(t *testing.T) {
	pub := testSubjectPublicKey(t)
	challenge, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	req, _, err := BuildClientAuthenticate(challenge, "administrator", "WORKGROUP", "Password1", pub)
	require.NoError(t, err)
	parsed := ParseCredSSP(req)

	got := NetNTLMv2(parsed.Username, parsed.Domain, nonce, parsed.NtChallengeResponse)
	want := fmt.Sprintf("administrator::WORKGROUP:%s:%s:%s",
		hex.EncodeToString(nonce),
		hex.EncodeToString(parsed.NtChallengeResponse[:16]),
		hex.EncodeToString(parsed.NtChallengeResponse[16:]),
	)
	require.Equal(t, want, got)

	require.Empty(t, NetNTLMv2(parsed.Username, parsed.Domain, nonce[:7], parsed.NtChallengeResponse))
	require.Empty(t, NetNTLMv2(parsed.Username, parsed.Domain, nonce, parsed.NtChallengeResponse[:24]), "NTLMv1 length")
	require.Empty(t, NetNTLMv2(parsed.Username, parsed.Domain, nonce, nil))
}
