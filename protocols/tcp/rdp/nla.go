package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/spf13/viper"
	"golang.org/x/crypto/md4"
)

// Account is one entry of rdp.credentials. Read per session so tests can set it.
type Account struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// Accounts returns the configured NLA accept-list. Empty (the default) means
// every Authenticate gets STATUS_LOGON_FAILURE, as before this feature.
func Accounts() []Account {
	var acc []Account
	_ = viper.UnmarshalKey("rdp.credentials", &acc)
	return acc
}

// NLAInput is the Type 3 plus the values AcceptNLA needs to prove and seal.
type NLAInput struct {
	Parsed           ParsedCredSSP
	Password         string
	ServerChallenge  []byte
	SubjectPublicKey []byte
}

// NLAResult is a completed accept-list match: the TSRequest to send next,
// and the session used to open the follow-up authInfo.
type NLAResult struct {
	Reply   []byte
	Session *NLASession
}

// NLASession holds NTLM session security after a successful accept-list match.
type NLASession struct {
	clientSeal *rc4cipher
	serverSeal *rc4cipher
	clientSign []byte
	serverSign []byte
	clientSeq  uint32
	serverSeq  uint32
	keyExch    bool
}

const (
	ntlmFlagKeyExch = 0x40000000

	nlaClientBind = "CredSSP Client-To-Server Binding Hash\x00"
	nlaServerBind = "CredSSP Server-To-Client Binding Hash\x00"

	nlaClientSignMagic = "session key to client-to-server signing key magic constant\x00"
	nlaServerSignMagic = "session key to server-to-client signing key magic constant\x00"
	nlaClientSealMagic = "session key to client-to-server sealing key magic constant\x00"
	nlaServerSealMagic = "session key to server-to-client sealing key magic constant\x00"
)

// AcceptNLA checks one configured password against a parsed Authenticate
// (MS-NLMP 3.3.2) and, on a match, builds the sealed pubKeyAuth confirmation
// (MS-CSSP 3.1.5). It returns false when the proof does not match, the
// message is not NTLMv2, or there is nothing to seal against.
func AcceptNLA(in NLAInput) (*NLAResult, bool) {
	p := in.Parsed
	if len(p.NtChallengeResponse) < 16 || ntlmVersion(p.NTResponseLen) != "NTLMv2" {
		return nil, false
	}
	if len(in.Password) == 0 || len(in.ServerChallenge) != 8 || len(in.SubjectPublicKey) == 0 || len(p.PubKeyAuth) == 0 {
		return nil, false
	}
	proof := p.NtChallengeResponse[:16]
	blob := p.NtChallengeResponse[16:]
	responseKey := ntlmv2ResponseKey(in.Password, p.Username, p.Domain)
	expected := hmacMD5(responseKey, append(append([]byte{}, in.ServerChallenge...), blob...))
	if !hmac.Equal(proof, expected) {
		return nil, false
	}
	sessionBase := hmacMD5(responseKey, proof)
	exported, keyExch := exportedSessionKey(sessionBase, p)
	if exported == nil {
		return nil, false
	}
	sess, ok := newNLASession(exported, keyExch)
	if !ok {
		return nil, false
	}
	plain, ok := sess.openClient(p.PubKeyAuth)
	if !ok || !bytes.Equal(plain, credsspBindHash(true, p.CredSSPVersion, p.ClientNonce, in.SubjectPublicKey)) {
		return nil, false
	}
	confirm := credsspBindHash(false, p.CredSSPVersion, p.ClientNonce, in.SubjectPublicKey)
	reply := BuildTSRequestPubKeyAuth(p.CredSSPVersion, sess.sealServer(confirm))
	return &NLAResult{Reply: reply, Session: sess}, true
}

func exportedSessionKey(sessionBase []byte, p ParsedCredSSP) (exported []byte, keyExch bool) {
	if p.NegotiateFlags&ntlmFlagKeyExch != 0 && len(p.EncryptedRandomSessionKey) > 0 {
		return rc4XOR(sessionBase, p.EncryptedRandomSessionKey), true
	}
	return append([]byte(nil), sessionBase...), false
}

func newNLASession(exported []byte, keyExch bool) (*NLASession, bool) {
	if len(exported) == 0 {
		return nil, false
	}
	return &NLASession{
		clientSeal: newRC4(md5Sum(exported, nlaClientSealMagic)),
		serverSeal: newRC4(md5Sum(exported, nlaServerSealMagic)),
		clientSign: md5Sum(exported, nlaClientSignMagic),
		serverSign: md5Sum(exported, nlaServerSignMagic),
		keyExch:    keyExch,
	}, true
}

// OpenAuthInfo decrypts a client authInfo OCTET STRING and returns the
// domain and username from TSPasswordCreds. The password is discarded.
func (s *NLASession) OpenAuthInfo(authInfo []byte) (domain, user string, ok bool) {
	plain, ok := s.openClient(authInfo)
	if !ok {
		return "", "", false
	}
	return parseTSPasswordCreds(plain)
}

func (s *NLASession) sealServer(plain []byte) []byte {
	return s.seal(plain, s.serverSign, s.serverSeal, &s.serverSeq)
}

func (s *NLASession) sealClient(plain []byte) []byte {
	return s.seal(plain, s.clientSign, s.clientSeal, &s.clientSeq)
}

func (s *NLASession) seal(plain, sign []byte, cipher *rc4cipher, seq *uint32) []byte {
	seqb := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqb, *seq)
	*seq++
	mac := hmacMD5(sign, append(seqb, plain...))[:8]
	if s.keyExch {
		enc := make([]byte, 8)
		cipher.XORKeyStream(enc, mac)
		mac = enc
	}
	ct := make([]byte, len(plain))
	cipher.XORKeyStream(ct, plain)
	out := make([]byte, 16+len(ct))
	binary.LittleEndian.PutUint32(out[0:4], 1)
	copy(out[4:12], mac)
	copy(out[12:16], seqb)
	copy(out[16:], ct)
	return out
}

func (s *NLASession) openClient(msg []byte) ([]byte, bool) {
	if s == nil || len(msg) < 16 {
		return nil, false
	}
	mac := append([]byte(nil), msg[4:12]...)
	seq := msg[12:16]
	if s.keyExch {
		dec := make([]byte, 8)
		s.clientSeal.XORKeyStream(dec, mac)
		mac = dec
	}
	plain := make([]byte, len(msg)-16)
	s.clientSeal.XORKeyStream(plain, msg[16:])
	if !hmac.Equal(mac, hmacMD5(s.clientSign, append(append([]byte{}, seq...), plain...))[:8]) {
		return nil, false
	}
	return plain, true
}

func ntlmv2ResponseKey(password, user, domain string) []byte {
	h := md4.New()
	h.Write(utf16LE(password))
	return hmacMD5(h.Sum(nil), utf16LE(strings.ToUpper(user)+domain))
}

func credsspBindHash(client bool, version int, nonce, pubKey []byte) []byte {
	if version >= 5 && len(nonce) > 0 {
		magic := nlaServerBind
		if client {
			magic = nlaClientBind
		}
		sum := sha256.New()
		sum.Write([]byte(magic))
		sum.Write(nonce)
		sum.Write(pubKey)
		return sum.Sum(nil)
	}
	out := append([]byte(nil), pubKey...)
	if !client && len(out) > 0 {
		out[0]++
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func md5Sum(key []byte, magic string) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

func rc4XOR(key, src []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	newRC4(key).XORKeyStream(dst, src)
	return dst
}

// rc4cipher is the stream cipher NTLM session security uses (MS-NLMP 3.4).
type rc4cipher struct {
	s    [256]byte
	i, j uint8
}

func newRC4(key []byte) *rc4cipher {
	var c rc4cipher
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	var j uint8
	for i := 0; i < 256; i++ {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return &c
}

func (c *rc4cipher) XORKeyStream(dst, src []byte) {
	i, j := c.i, c.j
	for k, v := range src {
		i++
		j += c.s[i]
		c.s[i], c.s[j] = c.s[j], c.s[i]
		dst[k] = v ^ c.s[c.s[i]+c.s[j]]
	}
	c.i, c.j = i, j
}

// SubjectPublicKey returns the subjectPublicKey BIT STRING of cert, including
// the unused-bits prefix, as CredSSP uses it (MS-CSSP / RFC 3280 §4.1).
func SubjectPublicKey(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	return bitStringFromSPKI(cert.RawSubjectPublicKeyInfo)
}

func bitStringFromSPKI(spki []byte) []byte {
	inner := derValue(spki, 0x30)
	_, _, rest := derNext(inner)
	tag, val, _ := derNext(rest)
	if tag != 0x03 {
		return nil
	}
	return append([]byte(nil), val...)
}

// MatchAccount tries each configured password against the Type 3 (any
// username). The NTLM proof is bound to the password the client used, so a
// listed password that is not that one cannot match.
func MatchAccount(parsed ParsedCredSSP, serverChallenge, subjectPublicKey []byte) (*NLAResult, string, bool) {
	for _, acc := range Accounts() {
		if acc.Password == "" {
			continue
		}
		out, ok := AcceptNLA(NLAInput{
			Parsed:           parsed,
			Password:         acc.Password,
			ServerChallenge:  serverChallenge,
			SubjectPublicKey: subjectPublicKey,
		})
		if ok {
			user := parsed.Username
			if user == "" {
				user = acc.Username
			}
			return out, user, true
		}
	}
	return nil, "", false
}

func parseTSPasswordCreds(data []byte) (domain, user string, ok bool) {
	inner := derValue(data, 0x30)
	var creds []byte
	for len(inner) > 0 {
		var tag byte
		var val []byte
		tag, val, inner = derNext(inner)
		if tag == 0xa1 {
			creds = derValue(val, 0x04)
		}
	}
	if len(creds) == 0 {
		return "", "", false
	}
	inner = derValue(creds, 0x30)
	for len(inner) > 0 {
		var tag byte
		var val []byte
		tag, val, inner = derNext(inner)
		switch tag {
		case 0xa0:
			domain = utf16LEString(derValue(val, 0x04))
		case 0xa1:
			user = utf16LEString(derValue(val, 0x04))
		}
	}
	return domain, user, user != "" || domain != ""
}

func utf16LEString(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u16))
}

// BuildClientAuthenticate builds a Type 3 TSRequest for tests: a known
// password against the Challenge the handler just sent.
func BuildClientAuthenticate(challengeTS []byte, username, domain, password string, subjectPublicKey []byte) ([]byte, *NLASession, error) {
	ntlm, _ := unwrapSPNEGO(negoTokenFromTSRequest(challengeTS))
	if len(ntlm) < 48 || string(ntlm[:8]) != ntlmSig {
		return nil, nil, errNLAChallenge
	}
	serverChallenge := append([]byte(nil), ntlm[24:32]...)
	targetInfo := readNTLMField(ntlm, 40)
	flags := binary.LittleEndian.Uint32(ntlm[20:24])
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	msg, exported, keyExch := buildNTLMv2Authenticate(username, domain, password, serverChallenge, targetInfo, flags)
	sess, ok := newNLASession(exported, keyExch)
	if !ok {
		return nil, nil, errNLAChallenge
	}
	pub := sess.sealClient(credsspBindHash(true, 6, nonce, subjectPublicKey))
	return wrapTSRequest(6, msg, pub, nil, nonce), sess, nil
}

// ClientAuthInfo seals TSCredentials for a test client. password is placed
// only in the ciphertext; decoded frames must not carry it.
func (s *NLASession) ClientAuthInfo(domain, user, password string) []byte {
	return wrapTSRequest(6, nil, nil, s.sealClient(buildTSPasswordCreds(domain, user, password)), nil)
}

var errNLAChallenge = errString("rdp: malformed NTLM Challenge")

type errString string

func (e errString) Error() string { return string(e) }

func buildNTLMv2Authenticate(user, domain, password string, serverChallenge, targetInfo []byte, flags uint32) (msg, exported []byte, keyExch bool) {
	clientChal := make([]byte, 8)
	_, _ = rand.Read(clientChal)
	blob := make([]byte, 28+len(targetInfo)+4)
	blob[0], blob[1] = 1, 1
	binary.LittleEndian.PutUint64(blob[8:16], toFILETIME(time.Now()))
	copy(blob[16:24], clientChal)
	copy(blob[28:], targetInfo)

	responseKey := ntlmv2ResponseKey(password, user, domain)
	proof := hmacMD5(responseKey, append(append([]byte{}, serverChallenge...), blob...))
	ntResp := append(proof, blob...)
	sessionBase := hmacMD5(responseKey, proof)

	exported = make([]byte, 16)
	_, _ = rand.Read(exported)
	keyExch = flags&ntlmFlagKeyExch != 0
	var encKey []byte
	if keyExch {
		encKey = rc4XOR(sessionBase, exported)
	} else {
		exported = sessionBase
	}

	dom := utf16LE(domain)
	usr := utf16LE(user)
	payloadOff := 64
	ntOff := payloadOff
	domOff := ntOff + len(ntResp)
	usrOff := domOff + len(dom)
	keyOff := usrOff + len(usr)
	total := keyOff + len(encKey)
	msg = make([]byte, total)
	copy(msg[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgAuthenticate)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(payloadOff))
	binary.LittleEndian.PutUint16(msg[20:22], uint16(len(ntResp)))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(msg[24:28], uint32(ntOff))
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(dom)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(dom)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domOff))
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(usr)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(usr)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(usrOff))
	binary.LittleEndian.PutUint32(msg[48:52], uint32(keyOff))
	if len(encKey) > 0 {
		binary.LittleEndian.PutUint16(msg[52:54], uint16(len(encKey)))
		binary.LittleEndian.PutUint16(msg[54:56], uint16(len(encKey)))
		binary.LittleEndian.PutUint32(msg[56:60], uint32(keyOff))
		copy(msg[keyOff:], encKey)
	}
	binary.LittleEndian.PutUint32(msg[60:64], flags)
	copy(msg[ntOff:], ntResp)
	copy(msg[domOff:], dom)
	copy(msg[usrOff:], usr)
	return msg, exported, keyExch
}

func buildTSPasswordCreds(domain, user, password string) []byte {
	var inner []byte
	inner = append(inner, derTLV(0xa0, derTLV(0x04, utf16LE(domain)))...)
	inner = append(inner, derTLV(0xa1, derTLV(0x04, utf16LE(user)))...)
	inner = append(inner, derTLV(0xa2, derTLV(0x04, utf16LE(password)))...)
	pwd := derTLV(0x30, inner)
	var cred []byte
	cred = append(cred, derTLV(0xa0, derTLV(0x02, []byte{1}))...)
	cred = append(cred, derTLV(0xa1, derTLV(0x04, pwd))...)
	return derTLV(0x30, cred)
}
