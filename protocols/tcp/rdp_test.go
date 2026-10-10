package tcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
	"github.com/stretchr/testify/require"
)

// 43-byte Connection Request with Cookie: mstshash=hello and RDP_NEG_REQ TLS|CredSSP
var rdpCRHello = mustDecodeHex("0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHandleRDPNegotiationAndTLSStub(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := client.Write(rdpCRHello)
	require.NoError(t, err)

	cc := make([]byte, 19)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)
	require.Equal(t, byte(0x03), cc[0])
	require.Equal(t, byte(0xd0), cc[5])

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "rdp",
	})
	require.NoError(t, tlsClient.Handshake())
	_ = tlsClient.Close()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedRDP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 4)

	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, rdpCRHello, events[0].Payload, "first payload must stay the CR (no buffer reuse)")
	require.Equal(t, byte(3), events[0].Header.Version)
	require.Equal(t, "ConnectionRequest", events[0].Command)
	require.Equal(t, "hello", events[0].Cookie)
	require.Equal(t, "TLS|CredSSP", events[0].Protocols)

	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, cc, events[1].Payload)
	require.Equal(t, "ConnectionConfirm", events[1].Command)

	require.Equal(t, "read", events[2].Direction)
	require.Equal(t, byte(0x16), events[2].Payload[0], "ClientHello")
	require.Nil(t, events[2].Header, "TLS frames have no TPKT header")
	require.Equal(t, "TLSClientHello", events[2].Command)

	require.Equal(t, "write", events[3].Direction)
	require.Equal(t, byte(0x16), events[3].Payload[0], "TLS stub ServerHello flight")
	require.Equal(t, "TLSHandshake", events[3].Command)
	require.NotEqual(t, events[1].Payload, events[3].Payload, "must not re-send Connection Confirm")
}

// 11-byte X.224 CR from ochi.mushmush.org/events/b4baa7aa-2d18-4e6e-83db-847c038a993e
var rdpCRStandard = mustDecodeHex("0300000b06e00000000000")

// TPKT + X.224 DT + MCS Connect-Initial (412 bytes) from the same event.
var rdpMCSConnectInitial = mustDecodeHex("0300019c02f0807f658201900401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201020482012f000500147c00018126000800100001c00044756361811801c0d400040008000005200301ca03aa09080000280a000045004d0050002d004c00410050002d003000300031003400000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca010000000000100007000100370036003400380037002d004f0045004d002d0030003000310031003900300033002d0030003000310030003700000000000000000000000000000000000000000004c00c00090000000000000002c00c00100000000000000003c02c0003000000726470647200000000008080636c6970726472000000a0c0726470736e640000000000c0")

func TestHandleRDPStandardCRNoNegRsp(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(rdpCRStandard)
	require.NoError(t, err)

	cc := make([]byte, 11)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)
	require.Equal(t, byte(0x03), cc[0])
	require.Equal(t, byte(0x0b), cc[3])
	require.Equal(t, byte(0x06), cc[4], "X.224 LI=6, no rdpNegData")
	require.Equal(t, byte(0xd0), cc[5])
	require.Equal(t, 11, len(cc))
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events := produced.decoded.([]parsedRDP)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "ConnectionRequest", events[0].Command)
	require.Equal(t, rdpCRStandard, events[0].Payload)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "ConnectionConfirm", events[1].Command)
	require.Equal(t, cc, events[1].Payload)
	require.NotContains(t, events[1].Payload, []byte{0x02, 0x00, 0x08, 0x00})
}

func TestHandleRDPMCSConnectInitialNoSecondCC(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(rdpCRStandard)
	require.NoError(t, err)

	cc := make([]byte, 11)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)
	require.Equal(t, byte(0xd0), cc[5])
	require.Equal(t, 11, len(cc))

	require.Len(t, rdpMCSConnectInitial, 412)
	_, err = client.Write(rdpMCSConnectInitial)
	require.NoError(t, err)

	mcsBuf := make([]byte, 512)
	n, err := client.Read(mcsBuf)
	require.NoError(t, err)
	mcsResp := mcsBuf[:n]
	require.Greater(t, len(mcsResp), 11)
	require.Equal(t, byte(0xf0), mcsResp[5], "MCS reply is X.224 DT, not a second CC")
	require.NotEqual(t, byte(0xd0), mcsResp[5])
	require.True(t, bytes.Contains(mcsResp, []byte{0x7f, 0x66}))
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events := produced.decoded.([]parsedRDP)
	require.Len(t, events, 4)
	require.Equal(t, rdpCRStandard, events[0].Payload)
	require.Equal(t, cc, events[1].Payload)
	require.Equal(t, "read", events[2].Direction)
	require.Equal(t, "MCSConnectInitial", events[2].Command)
	require.Equal(t, rdpMCSConnectInitial, events[2].Payload)
	require.Equal(t, byte(3), events[2].Header.Version)
	require.Equal(t, "write", events[3].Direction)
	require.Equal(t, "MCSConnectResponse", events[3].Command)
	require.Equal(t, byte(0xf0), events[3].Payload[5])
	require.NotEqual(t, byte(0xd0), events[3].Payload[5])
}

func TestHandleRDPPayloadNotOverwritten(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()

	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(rdpCRHello)
	require.NoError(t, err)

	cc := make([]byte, 19)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)

	// Second read overwrites the shared buffer; copied payloads must stay intact.
	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "rdp",
	})
	_ = tlsClient.Handshake()
	_ = client.Close()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedRDP)
	require.Equal(t, rdpCRHello, events[0].Payload)
}

func TestHandleRDPEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	events, ok := produced.decoded.([]parsedRDP)
	require.True(t, ok)
	require.Empty(t, events)
}

// rdpCRTLSOnly is rdpCRHello requesting only PROTOCOL_SSL.
var rdpCRTLSOnly = func() []byte {
	b := append([]byte(nil), rdpCRHello...)
	b[len(b)-4] = 0x01
	return b
}()

func startRDPTLS(t *testing.T, cr []byte) (*tls.Conn, []byte, <-chan error, *fakeHoneypot) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(cr)
	require.NoError(t, err)
	cc := make([]byte, 19)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)

	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: "rdp"})
	require.NoError(t, tlsClient.Handshake())
	return tlsClient, cc, done, hp
}

func TestHandleRDPSelectsSingleProtocol(t *testing.T) {
	tlsClient, cc, _, _ := startRDPTLS(t, rdpCRHello)
	_ = tlsClient.Close()
	require.Equal(t, byte(0x02), cc[11], "RDP_NEG_RSP")
	require.Equal(t, []byte{0x02, 0x00, 0x00, 0x00}, cc[15:19], "HYBRID only, not TLS|CredSSP")

	_, cc, _, _ = startRDPTLS(t, rdpCRTLSOnly)
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x00}, cc[15:19])
}

func TestHandleRDPRecordsTSRequestAfterTLS(t *testing.T) {
	tlsClient, _, done, hp := startRDPTLS(t, rdpCRHello)
	tsRequest := []byte{0x30, 0x03, 0x02, 0x01, 0x06}
	_, err := tlsClient.Write(tsRequest)
	require.NoError(t, err)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedRDP)
	require.Len(t, events, 5)
	require.Equal(t, "TLSClientHello", events[2].Command)
	require.Equal(t, "TLSHandshake", events[3].Command)
	require.Equal(t, "read", events[4].Direction)
	require.Equal(t, "TSRequest", events[4].Command)
	require.Equal(t, tsRequest, events[4].Payload)
	require.Nil(t, events[4].Header, "CredSSP frames have no TPKT header")
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
}

func TestHandleRDPMCSOverTLS(t *testing.T) {
	tlsClient, _, done, hp := startRDPTLS(t, rdpCRTLSOnly)
	_, err := tlsClient.Write(rdpMCSConnectInitial)
	require.NoError(t, err)

	buf := make([]byte, 512)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err)
	require.True(t, bytes.Contains(buf[:n], []byte{0x7f, 0x66}))
	require.NoError(t, tlsClient.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	events := waitProduced(t, hp).decoded.([]parsedRDP)
	require.Equal(t, "MCSConnectInitial", events[4].Command)
	require.Equal(t, "MCSConnectResponse", events[5].Command)
}

func TestHandleRDPCredSSPExchange(t *testing.T) {
	tlsClient, _, done, hp := startRDPTLS(t, rdpCRHello)

	// Send NTLM Negotiate inside a TSRequest.
	_, err := tlsClient.Write(rdp.WrapTSRequest(makeNTLMNegotiate()))
	require.NoError(t, err)

	// Read the NTLM Challenge TSRequest reply.
	buf := make([]byte, 512)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err)
	challengeResp := buf[:n]
	require.Equal(t, byte(0x30), challengeResp[0], "challenge must be a DER SEQUENCE")

	// Send NTLM Authenticate inside a TSRequest.
	_, err = tlsClient.Write(rdp.WrapTSRequest(makeNTLMAuthenticate("ACME", "jsmith")))
	require.NoError(t, err)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedRDP)
	// CR, CC, TLSClientHello, TLSHandshake, NTLMNegotiate, NTLMChallenge, NTLMAuthenticate
	require.Len(t, events, 7)

	require.Equal(t, "NTLMNegotiate", events[4].Command)
	require.Equal(t, "read", events[4].Direction)
	require.Nil(t, events[4].Header, "no TPKT header on CredSSP frames")

	require.Equal(t, "NTLMChallenge", events[5].Command)
	require.Equal(t, "write", events[5].Direction)
	require.Equal(t, byte(0x30), events[5].Payload[0])

	require.Equal(t, "NTLMAuthenticate", events[6].Command)
	require.Equal(t, "read", events[6].Direction)
	require.Equal(t, "ACME", events[6].NTLMDomain)
	require.Equal(t, "jsmith", events[6].NTLMUser)

	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
}

// makeNTLMNegotiate builds a minimal NTLM Type 1 Negotiate message.
func makeNTLMNegotiate() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], 0x00003207)
	return msg
}

// makeNTLMAuthenticate builds a minimal NTLM Type 3 Authenticate with domain and username.
func makeNTLMAuthenticate(domain, username string) []byte {
	domBytes := rdpUTF16LE(domain)
	userBytes := rdpUTF16LE(username)
	// Minimal header without EncryptedRandomSessionKey or Version: 56 bytes.
	payloadOff := 56
	domOff := payloadOff
	userOff := payloadOff + len(domBytes)
	total := userOff + len(userBytes)
	msg := make([]byte, total)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3)
	// LmChallengeResponse: empty at payloadOff
	binary.LittleEndian.PutUint32(msg[16:20], uint32(payloadOff))
	// NtChallengeResponse: empty at payloadOff
	binary.LittleEndian.PutUint32(msg[24:28], uint32(payloadOff))
	// DomainNameFields at 28
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domOff))
	// UserNameFields at 36
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(userOff))
	// WorkstationFields: empty at total
	binary.LittleEndian.PutUint32(msg[48:52], uint32(total))
	// NegotiateFlags
	binary.LittleEndian.PutUint32(msg[52:56], 0x00000207)
	copy(msg[domOff:], domBytes)
	copy(msg[userOff:], userBytes)
	return msg
}

func rdpUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return b
}

func TestHandleRDPTLSDisconnectAfterClientHello(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(rdpCRHello)
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 19))
	require.NoError(t, err)

	// Send a short ClientHello, wait briefly for any reply, then drop the connection.
	hello := mustDecodeHex("160301003d0100003903030000000000000000000000000000000000000000000000000000000000000000000002c02f01000000")
	_, err = client.Write(hello)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _ = client.Read(make([]byte, 4096))
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	events := waitProduced(t, hp).decoded.([]parsedRDP)
	require.GreaterOrEqual(t, len(events), 3)
	require.Equal(t, "TLSClientHello", events[2].Command)
}

// rdpX224DT wraps an MCS PDU in TPKT + X.224 Data.
func rdpX224DT(mcs []byte) []byte {
	out := []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x80}
	out = append(out, mcs...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// rdpClientInfoPDU builds a synthetic Client Info PDU (MCS Send Data Request
// on the I/O channel, SEC_INFO_PKT, Unicode TS_INFO_PACKET) as mstsc sends it
// on a TLS session with ENCRYPTION_LEVEL_NONE.
func rdpClientInfoPDU(domain, user, password string) []byte {
	fields := [][]byte{rdpUTF16LE(domain), rdpUTF16LE(user), rdpUTF16LE(password), nil, nil}
	info := []byte{0x40, 0x00, 0x00, 0x00}
	hdr := make([]byte, 18)
	binary.LittleEndian.PutUint32(hdr[4:8], 0x10) // INFO_UNICODE
	for i, f := range fields {
		binary.LittleEndian.PutUint16(hdr[8+2*i:], uint16(len(f)))
	}
	info = append(info, hdr...)
	for _, f := range fields {
		info = append(append(info, f...), 0, 0)
	}
	mcs := []byte{0x64, 0x00, 0x06, 0x03, 0xeb, 0x70}
	if len(info) < 0x80 {
		mcs = append(mcs, byte(len(info)))
	} else {
		mcs = append(mcs, 0x80|byte(len(info)>>8), byte(len(info)))
	}
	return rdpX224DT(append(mcs, info...))
}

var (
	rdpErectDomain = rdpX224DT([]byte{0x04, 0x01, 0x00, 0x01, 0x00})
	rdpAttachUser  = rdpX224DT([]byte{0x28})
)

func rdpChannelJoin(channel uint16) []byte {
	return rdpX224DT([]byte{0x38, 0x00, 0x06, byte(channel >> 8), byte(channel)})
}

func waitRDPDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
}

func rdpCommands(events []parsedRDP) []string {
	cmds := make([]string, len(events))
	for i, e := range events {
		cmds[i] = e.Direction + ":" + e.Command
	}
	return cmds
}

func TestHandleRDPClientInfoOverTLS(t *testing.T) {
	tlsClient, _, done, hp := startRDPTLS(t, rdpCRTLSOnly)

	_, err := tlsClient.Write(rdpMCSConnectInitial)
	require.NoError(t, err)
	buf := make([]byte, 512)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err)
	require.True(t, bytes.Contains(buf[:n], mustDecodeHex("030c1000eb030300ec03ed03ee030000")), "SC_NET assigns the three requested channels")

	// Erect Domain and Attach User arrive in one record, as mstsc sends them.
	_, err = tlsClient.Write(append(append([]byte{}, rdpErectDomain...), rdpAttachUser...))
	require.NoError(t, err)
	auc := make([]byte, 11)
	_, err = io.ReadFull(tlsClient, auc)
	require.NoError(t, err)
	require.Equal(t, mustDecodeHex("0300000b02f0802e000006"), auc)

	channels := []uint16{1007, 1003, 1004, 1005, 1006}
	for _, ch := range channels {
		_, err = tlsClient.Write(rdpChannelJoin(ch))
		require.NoError(t, err)
		cjc := make([]byte, 15)
		_, err = io.ReadFull(tlsClient, cjc)
		require.NoError(t, err)
		require.Equal(t, byte(0x3e), cjc[7])
		require.Equal(t, ch, binary.BigEndian.Uint16(cjc[13:15]))
	}

	info := rdpClientInfoPDU("CORP", "administrator", "Winter2024!")
	_, err = tlsClient.Write(info)
	require.NoError(t, err)
	tail, err := io.ReadAll(tlsClient)
	require.NoError(t, err)
	require.Equal(t, 34+36+9, len(tail), "license alert, set error info, disconnect ultimatum")
	waitRDPDone(t, done)

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events := produced.decoded.([]parsedRDP)

	want := []string{
		"read:ConnectionRequest", "write:ConnectionConfirm", "read:TLSClientHello", "write:TLSHandshake",
		"read:MCSConnectInitial", "write:MCSConnectResponse",
		"read:ErectDomainRequest", "read:AttachUserRequest", "write:AttachUserConfirm",
	}
	for range channels {
		want = append(want, "read:ChannelJoinRequest", "write:ChannelJoinConfirm")
	}
	want = append(want, "read:ClientInfo", "write:LicenseErrorAlert", "write:SetErrorInfo", "write:DisconnectProviderUltimatum")
	require.Equal(t, want, rdpCommands(events))

	require.Equal(t, &rdp.ClientData{
		ClientName:        "EMP-LAP-0014",
		ClientBuild:       2600,
		DesktopWidth:      1280,
		DesktopHeight:     800,
		KeyboardLayout:    0x0809,
		HighColorDepth:    16,
		EncryptionMethods: 0x10,
		Channels:          []string{"rdpdr", "cliprdr", "rdpsnd"},
	}, events[4].ClientData)
	require.Equal(t, rdpErectDomain, events[6].Payload)
	require.Equal(t, rdpAttachUser, events[7].Payload)
	require.Equal(t, uint16(1007), events[9].ChannelID)
	require.Equal(t, uint16(1007), events[10].ChannelID)
	require.Equal(t, uint16(1006), events[18].ChannelID)

	ci := events[19]
	require.Equal(t, info, ci.Payload)
	require.Equal(t, uint16(1003), ci.ChannelID)
	require.Equal(t, &rdp.ClientInfo{Domain: "CORP", Username: "administrator", PasswordLen: 11}, ci.ClientInfo)

	require.Equal(t, "STATUS_VALID_CLIENT", events[20].Status)
	require.Equal(t, "ERRINFO_SERVER_DENIED_CONNECTION", events[21].Status)
	require.Equal(t, tail, append(append(append([]byte{}, events[20].Payload...), events[21].Payload...), events[22].Payload...))

	// The password only exists inside the raw payload; no decoded field names it.
	for _, e := range events {
		e.Payload = nil
		js, err := json.Marshal(e)
		require.NoError(t, err)
		require.NotContains(t, string(js), "Winter2024!")
		require.NotContains(t, string(js), `"password"`)
	}
}

func TestHandleRDPReassemblesSplitPDUs(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := client.Write(rdpCRStandard)
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 11))
	require.NoError(t, err)

	// Connect-Initial split mid-PDU across two writes.
	_, err = client.Write(rdpMCSConnectInitial[:100])
	require.NoError(t, err)
	_, err = client.Write(rdpMCSConnectInitial[100:])
	require.NoError(t, err)
	n, err := client.Read(make([]byte, 512))
	require.NoError(t, err)
	require.Greater(t, n, 11)

	_, err = client.Write(rdpAttachUser)
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 11))
	require.NoError(t, err)

	_, err = client.Write(rdpClientInfoPDU("", "guest", ""))
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 34+36+9))
	require.NoError(t, err)
	waitRDPDone(t, done)

	events := waitProduced(t, hp).decoded.([]parsedRDP)
	require.Equal(t, []string{
		"read:ConnectionRequest", "write:ConnectionConfirm",
		"read:MCSConnectInitial", "write:MCSConnectResponse",
		"read:AttachUserRequest", "write:AttachUserConfirm",
		"read:ClientInfo", "write:LicenseErrorAlert", "write:SetErrorInfo", "write:DisconnectProviderUltimatum",
	}, rdpCommands(events))
	require.Equal(t, rdpMCSConnectInitial, events[2].Payload, "reassembled PDU is one frame")
	require.Equal(t, "guest", events[6].ClientInfo.Username)
	require.Zero(t, events[6].ClientInfo.PasswordLen)
}

func TestHandleRDPPartialTPKTAtDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := client.Write(rdpCRStandard)
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 11))
	require.NoError(t, err)
	partial := rdpMCSConnectInitial[:40]
	_, err = client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	waitRDPDone(t, done)

	events := waitProduced(t, hp).decoded.([]parsedRDP)
	require.Len(t, events, 3)
	require.Equal(t, "read", events[2].Direction)
	require.Equal(t, partial, events[2].Payload)
	require.True(t, events[2].Truncated)
}

func TestHandleRDPNTLMVersion(t *testing.T) {
	tlsClient, _, done, hp := startRDPTLS(t, rdpCRHello)
	_, err := tlsClient.Write(rdp.WrapTSRequest(makeNTLMNegotiate()))
	require.NoError(t, err)
	_, err = tlsClient.Read(make([]byte, 512))
	require.NoError(t, err)
	_, err = tlsClient.Write(rdp.WrapTSRequest(makeNTLMAuthenticate("ACME", "jsmith")))
	require.NoError(t, err)
	waitRDPDone(t, done)

	events := waitProduced(t, hp).decoded.([]parsedRDP)
	require.Equal(t, "anonymous", events[6].NTLMVersion, "empty NtChallengeResponse")
}
