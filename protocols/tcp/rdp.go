package tcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
)

// parsedRDP is one frame of an RDP session. Header is nil for TLS and CredSSP
// frames (they carry no TPKT framing); it is set for all X.224/TPKT PDUs.
type parsedRDP struct {
	Direction       string          `json:"direction,omitempty"`
	Command         string          `json:"command,omitempty"`
	Cookie          string          `json:"cookie,omitempty"`
	Protocols       string          `json:"protocols,omitempty"`
	NTLMDomain      string          `json:"ntlm_domain,omitempty"`
	NTLMUser        string          `json:"ntlm_user,omitempty"`
	NTLMWorkstation string          `json:"ntlm_workstation,omitempty"`
	Header          *rdp.TKIPHeader `json:"header,omitempty"`
	Payload         []byte          `json:"payload,omitempty"`
	Truncated       bool            `json:"truncated,omitempty"`
}

// rdpMaxReceive is larger than maxBufferSize: modern TLS ClientHellos often
// exceed 1KiB, and truncating them caused leftover bytes to be misparsed as TPKT.
const rdpMaxReceive = 16 << 10

type rdpServer struct {
	events []parsedRDP
	conn   net.Conn
}

// rdpWriteRecorder copies what is written to the connection while on is set,
// so the server's side of the TLS handshake can be stored as one frame.
type rdpWriteRecorder struct {
	net.Conn
	buf bytes.Buffer
	on  bool
}

func (c *rdpWriteRecorder) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.on && n > 0 {
		c.buf.Write(b[:n])
	}
	return n, err
}

// write appends a write frame and sends data on the connection.
// header is nil for TLS/CredSSP frames that carry no TPKT framing.
func (rs *rdpServer) write(header *rdp.TKIPHeader, data []byte) error {
	rs.events = append(rs.events, parsedRDP{
		Header:    header,
		Direction: "write",
		Command:   rdpWriteCommand(data),
		Protocols: rdp.SelectedProtocols(data),
		Payload:   data,
	})
	_, err := rs.conn.Write(data)
	return err
}

func rdpWriteCommand(data []byte) string {
	if rdp.IsTLSRecord(data) {
		return rdp.CmdTLSHandshake
	}
	if rdp.IsTSRequest(data) {
		return rdp.CmdNTLMChallenge
	}
	if bytes.Contains(data, []byte{0x7f, 0x66}) {
		return rdp.CmdMCSConnectResponse
	}
	if rdp.TPDUType(data)&0xf0 == rdp.TPDUConnectionConfirm {
		return rdp.CmdConnectionConfirm
	}
	return rdp.FrameCommand(data)
}

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rdpServer{
		events: []parsedRDP{},
		conn:   conn,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rdp", conn, md, helpers.FirstOrEmpty[parsedRDP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rdp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RDP connection", slog.String("protocol", "rdp"), producer.ErrAttr(err))
		}
	}()

	// Obtain the sensor's stable identity once per handler invocation.
	rdpComputer, _ := rdp.Identity()
	rdpCert, certErr := helpers.SelfSignedCertificateRDP(rdpComputer)
	if certErr != nil {
		logger.Error("Failed to get RDP TLS certificate", slog.String("protocol", "rdp"), producer.ErrAttr(certErr))
		endReason = connection.EndHandlerClose
		return certErr
	}

	buffer := make([]byte, rdpMaxReceive)
	// rd is the raw connection until the client starts TLS, then the decrypted one.
	rd := conn
	var requested, selected uint32
	var ntlmNegotiateFlags uint32
	tlsDone := false
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		n, err := rd.Read(buffer)
		if err != nil && n <= 0 {
			logger.Debug("Failed to read from connection", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if n <= 0 {
			continue
		}

		raw := make([]byte, n)
		copy(raw, buffer[:n])

		header := rdp.ParseTKIPHeader(raw)

		// The client starts TLS on the same TCP connection after the Connection
		// Confirm. Terminate it using the RDP-specific certificate and keep
		// reading the decrypted stream.
		if !tlsDone && rdp.IsTLSRecord(raw) {
			rec := &rdpWriteRecorder{Conn: conn, on: true}
			tlsConn, info, hsErr := helpers.TerminateTLSFromWith(rdpCert, rec, io.MultiReader(bytes.NewReader(raw), conn))
			rec.on = false
			md.TLS = info
			server.events = append(server.events, parsedRDP{
				Direction: "read",
				Command:   rdp.CmdTLSClientHello,
				Payload:   info.Hello,
				Truncated: info.Truncated,
			})
			if rec.buf.Len() > 0 {
				server.events = append(server.events, parsedRDP{
					Direction: "write",
					Command:   rdp.CmdTLSHandshake,
					Payload:   append([]byte(nil), rec.buf.Bytes()...),
				})
			}
			if hsErr != nil {
				logger.Debug("RDP TLS handshake failed", slog.String("protocol", "rdp"), producer.ErrAttr(hsErr))
				endReason = connection.EndClientClose
				return nil
			}
			tlsDone = true
			rd = tlsConn
			server.conn = tlsConn
			continue
		}

		fr := parsedRDP{
			Direction: "read",
			Command:   rdp.FrameCommand(raw),
			Header:    &header,
			Payload:   raw,
		}

		switch {
		case rdp.IsConnectionRequest(raw):
			pdu, err := rdp.ParseCRPDU(raw)
			if err != nil {
				endReason = connection.EndReadError
				return err
			}
			fr.Cookie = rdp.MSTSHASH(raw)
			fr.Protocols = rdp.RequestedProtocols(pdu)
			requested = rdp.RequestedMask(pdu)
			selected = rdp.SelectProtocol(requested)
			server.events = append(server.events, fr)
			logger.Debug(fmt.Sprintf("rdp req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				logger.Debug(fmt.Sprintf("rdp data: %s", string(pdu.Data)))
			}
			ccHeader, resp, err := rdp.ConnectionConfirm(pdu.TPDU, rdp.HasRDPNegReq(pdu), selected)
			if err != nil {
				endReason = connection.EndWriteError
				return err
			}
			logger.Debug(fmt.Sprintf("rdp resp pdu: %+v", resp))
			if err := server.write(&ccHeader, resp); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case rdp.IsMCSConnectInitial(raw):
			server.events = append(server.events, fr)
			logger.Debug("rdp MCS Connect-Initial", slog.String("protocol", "rdp"), slog.Int("bytes", len(raw)))
			mcsHeader, resp := rdp.MCSConnectResponse(selected)
			if err := server.write(&mcsHeader, resp); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case tlsDone && rdp.IsTSRequest(raw):
			parsed := rdp.ParseCredSSP(raw)
			// CredSSP frames carry no TPKT framing — omit the header.
			fr.Header = nil
			switch parsed.NTLMType {
			case rdp.NTLMMsgNegotiate:
				fr.Command = rdp.CmdNTLMNegotiate
				ntlmNegotiateFlags = parsed.NegotiateFlags
				server.events = append(server.events, fr)
				logger.Debug("rdp CredSSP NTLM Negotiate", slog.String("protocol", "rdp"), slog.Int("bytes", len(raw)))
				computer, domain := rdp.Identity()
				resp, err := rdp.BuildTSRequestChallengeWith(rdp.NTLMChallengeOptions{
					Computer:    computer,
					Domain:      domain,
					ClientFlags: ntlmNegotiateFlags,
				})
				if err != nil {
					endReason = connection.EndWriteError
					return err
				}
				if err := server.write(nil, resp); err != nil {
					endReason = connection.EndWriteError
					return err
				}
			case rdp.NTLMMsgAuthenticate:
				fr.Command = rdp.CmdNTLMAuthenticate
				fr.NTLMDomain = parsed.Domain
				fr.NTLMUser = parsed.Username
				fr.NTLMWorkstation = parsed.Workstation
				server.events = append(server.events, fr)
				logger.Debug("rdp CredSSP NTLM Authenticate",
					slog.String("protocol", "rdp"),
					slog.String("domain", parsed.Domain),
					slog.String("user", parsed.Username),
				)
				return nil
			default:
				fr.Command = rdp.CmdTSRequest
				server.events = append(server.events, fr)
				logger.Debug("rdp CredSSP TSRequest", slog.String("protocol", "rdp"), slog.Int("bytes", len(raw)))
				return nil
			}
		default:
			server.events = append(server.events, fr)
			logger.Debug("rdp ignoring non-CR TPDU", slog.String("protocol", "rdp"), slog.Int("tpdu", int(rdp.TPDUType(raw))))
		}
	}
}
