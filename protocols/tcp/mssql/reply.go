package mssql

import (
	"encoding/binary"
	"time"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
)

// Token types (MS-TDS 2.2.7).
const (
	tokenError = 0xaa
	tokenSSPI  = 0xed
	tokenDone  = 0xfd
)

const doneError = 0x0002

// Login failure numbers and their messages (sys.messages).
const (
	ErrLoginFailed       = 18456
	ErrUntrustedDomain   = 18452
	loginFailedClass     = 14
	loginFailedState     = 1
	untrustedDomainState = 1
)

// ChallengeOptions configures the NTLM CHALLENGE sent in the SSPI token.
type ChallengeOptions struct {
	ServerChallenge []byte
	Computer        string
	Domain          string
	// ClientFlags are the client NEGOTIATE flags; NEGOTIATE_VERSION adds the
	// VERSION block.
	ClientFlags uint32
	Now         time.Time
}

// BuildSSPIChallenge answers an integrated-auth LOGIN7 (or SSPI message) whose
// blob holds an NTLM NEGOTIATE. A raw NTLMSSP blob gets a raw CHALLENGE and a
// SPNEGO blob gets a SPNEGO NegTokenResp, as SQL Server answers in kind. It
// returns nil when the CHALLENGE cannot be built.
func BuildSSPIChallenge(clientBlob []byte, opts ChallengeOptions) []byte {
	challenge := ntlm.BuildChallenge(ntlm.ChallengeOptions{
		ServerChallenge: opts.ServerChallenge,
		Domain:          opts.Domain,
		Computer:        opts.Computer,
		ClientFlags:     opts.ClientFlags,
		Now:             opts.Now,
		RichTargetInfo:  true,
	})
	if challenge == nil {
		return nil
	}
	if _, wrapped := ntlm.UnwrapSPNEGO(clientBlob); wrapped {
		challenge = ntlm.NegTokenChallenge(challenge)
	}
	tok := []byte{tokenSSPI}
	tok = binary.LittleEndian.AppendUint16(tok, uint16(len(challenge)))
	return packet(TypeTabular, append(tok, challenge...))
}

// LoginError describes the ERROR token of a failed login.
type LoginError struct {
	Number  uint32
	State   byte
	Class   byte
	Message string
	Server  string
	// Legacy selects the pre-TDS 7.2 ERROR line number and DONE row count widths.
	Legacy bool
}

// LoginFailed is the SQL Server reply to a login for user: error 18456.
func LoginFailed(user, server string, legacy bool) LoginError {
	return LoginError{
		Number:  ErrLoginFailed,
		State:   loginFailedState,
		Class:   loginFailedClass,
		Message: "Login failed for user '" + user + "'.",
		Server:  server,
		Legacy:  legacy,
	}
}

// UntrustedDomain is the reply to an anonymous or non-NTLM integrated login:
// error 18452.
func UntrustedDomain(server string, legacy bool) LoginError {
	return LoginError{
		Number:  ErrUntrustedDomain,
		State:   untrustedDomainState,
		Class:   loginFailedClass,
		Message: "Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.",
		Server:  server,
		Legacy:  legacy,
	}
}

// BuildLoginError builds the tabular result of a failed login: ERROR then a
// DONE with the error bit.
func BuildLoginError(e LoginError) []byte {
	w := &tokenWriter{legacy: e.Legacy}
	w.message(tokenError, e.Number, e.State, e.Class, e.Message, e.Server)
	w.done(tokenDone, doneError, 0, 0)
	return packet(TypeTabular, w.b)
}
