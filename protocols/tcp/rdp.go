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
	Status          string          `json:"status,omitempty"`
	Cookie          string          `json:"cookie,omitempty"`
	Protocols       string          `json:"protocols,omitempty"`
	NTLMDomain      string          `json:"ntlm_domain,omitempty"`
	NTLMUser        string          `json:"ntlm_user,omitempty"`
	NTLMWorkstation string          `json:"ntlm_workstation,omitempty"`
	NTLMVersion     string          `json:"ntlm_version,omitempty"`
	ChannelID       uint16          `json:"channel_id,omitempty"`
	ClientData      *rdp.ClientData `json:"client_data,omitempty"`
	ClientInfo      *rdp.ClientInfo `json:"client_info,omitempty"`
	Header          *rdp.TKIPHeader `json:"header,omitempty"`
	Payload         []byte          `json:"payload,omitempty"`
	Truncated       bool            `json:"truncated,omitempty"`
}

const (
	// rdpMaxReceive is larger than maxBufferSize: modern TLS ClientHellos often
	// exceed 1KiB, and truncating them caused leftover bytes to be misparsed as TPKT.
	rdpMaxReceive = 16 << 10
	// rdpMaxPending bounds TPKT reassembly; a TPKT is at most 65535 bytes.
	rdpMaxPending = 1 << 16
	// rdpMaxFrames bounds the session so a client looping on unknown PDUs
	// cannot grow the event without limit.
	rdpMaxFrames = 128
)

type rdpServer struct {
	events []parsedRDP
	conn   net.Conn
	// pending holds a partial TPKT PDU until the rest arrives.
	pending  []byte
	selected uint32
	logger   interfaces.Logger
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
	return rs.writeFrame(parsedRDP{
		Header:    header,
		Command:   rdpWriteCommand(data),
		Protocols: rdp.SelectedProtocols(data),
		Payload:   data,
	})
}

// writeFrame sends fr.Payload and records fr as a write frame.
func (rs *rdpServer) writeFrame(fr parsedRDP) error {
	fr.Direction = "write"
	rs.events = append(rs.events, fr)
	_, err := rs.conn.Write(fr.Payload)
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

// handleTPKT processes one complete TPKT PDU. done is set once the session
// has reached its end (the Client Info PDU was answered).
func (rs *rdpServer) handleTPKT(raw []byte) (done bool, endReason string, err error) {
	header := rdp.ParseTKIPHeader(raw)
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
			return true, connection.EndReadError, err
		}
		fr.Cookie = rdp.MSTSHASH(raw)
		fr.Protocols = rdp.RequestedProtocols(pdu)
		rs.selected = rdp.SelectProtocol(rdp.RequestedMask(pdu))
		rs.events = append(rs.events, fr)
		rs.logger.Debug(fmt.Sprintf("rdp req pdu: %+v", pdu))
		if len(pdu.Data) > 0 {
			rs.logger.Debug(fmt.Sprintf("rdp data: %s", string(pdu.Data)))
		}
		ccHeader, resp, err := rdp.ConnectionConfirm(pdu.TPDU, rdp.HasRDPNegReq(pdu), rs.selected)
		if err != nil {
			return true, connection.EndWriteError, err
		}
		rs.logger.Debug(fmt.Sprintf("rdp resp pdu: %+v", resp))
		if err := rs.write(&ccHeader, resp); err != nil {
			return true, connection.EndWriteError, err
		}
	case rdp.IsMCSConnectInitial(raw):
		fr.ClientData = rdp.ParseClientData(raw)
		rs.events = append(rs.events, fr)
		rs.logger.Debug("rdp MCS Connect-Initial", slog.String("protocol", "rdp"), slog.Int("bytes", len(raw)))
		channels := 0
		if fr.ClientData != nil {
			channels = len(fr.ClientData.Channels)
		}
		mcsHeader, resp := rdp.MCSConnectResponse(rs.selected, channels)
		if err := rs.write(&mcsHeader, resp); err != nil {
			return true, connection.EndWriteError, err
		}
	case fr.Command == rdp.CmdAttachUserRequest:
		rs.events = append(rs.events, fr)
		h, resp := rdp.AttachUserConfirm()
		if err := rs.writeFrame(parsedRDP{Header: &h, Command: rdp.CmdAttachUserConfirm, Payload: resp}); err != nil {
			return true, connection.EndWriteError, err
		}
	case fr.Command == rdp.CmdChannelJoinRequest:
		initiator, channel, ok := rdp.ChannelJoinRequest(raw)
		fr.ChannelID = channel
		rs.events = append(rs.events, fr)
		if !ok {
			break
		}
		h, resp := rdp.ChannelJoinConfirm(initiator, channel)
		if err := rs.writeFrame(parsedRDP{Header: &h, Command: rdp.CmdChannelJoinConfirm, ChannelID: channel, Payload: resp}); err != nil {
			return true, connection.EndWriteError, err
		}
	case fr.Command == rdp.CmdSendDataRequest:
		channel, payload, _ := rdp.SendDataRequest(raw)
		fr.ChannelID = channel
		if rdp.IsSecurityExchange(payload) {
			fr.Command = rdp.CmdSecurityExchange
		}
		ci, ok := rdp.ParseClientInfo(payload)
		if !ok {
			rs.events = append(rs.events, fr)
			break
		}
		fr.Command = rdp.CmdClientInfo
		fr.ClientInfo = &ci
		rs.events = append(rs.events, fr)
		rs.logger.Debug("rdp Client Info",
			slog.String("protocol", "rdp"),
			slog.String("domain", ci.Domain),
			slog.String("user", ci.Username),
		)
		return true, connection.EndHandlerClose, rs.denyLogon()
	default:
		rs.events = append(rs.events, fr)
		rs.logger.Debug("rdp unhandled TPDU", slog.String("protocol", "rdp"), slog.String("command", fr.Command))
	}
	return false, connection.EndHandlerClose, nil
}

// denyLogon answers a Client Info PDU the way a server that refuses the
// session does: skip licensing, report an error, then drop the MCS domain.
func (rs *rdpServer) denyLogon() error {
	lh, lic := rdp.LicenseValidClient()
	eh, errInfo := rdp.SetErrorInfo(rdp.ErrInfoServerDeniedConnection)
	dh, dpu := rdp.DisconnectProviderUltimatum()
	for _, fr := range []parsedRDP{
		{Header: &lh, Command: rdp.CmdLicenseErrorAlert, Status: rdp.StatusValidClient, Payload: lic},
		{Header: &eh, Command: rdp.CmdSetErrorInfo, Status: rdp.StatusServerDeniedConnection, Payload: errInfo},
		{Header: &dh, Command: rdp.CmdDisconnectProviderUltimatum, Payload: dpu},
	} {
		if err := rs.writeFrame(fr); err != nil {
			return err
		}
	}
	return nil
}

// flushPending records a partial TPKT left when the connection ends.
func (rs *rdpServer) flushPending() {
	if len(rs.pending) == 0 {
		return
	}
	header := rdp.ParseTKIPHeader(rs.pending)
	rs.events = append(rs.events, parsedRDP{
		Direction: "read",
		Command:   rdp.FrameCommand(rs.pending),
		Header:    &header,
		Payload:   rs.pending,
		Truncated: true,
	})
	rs.pending = nil
}

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rdpServer{
		events: []parsedRDP{},
		conn:   conn,
		logger: logger,
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
	var ntlmNegotiateFlags uint32
	tlsDone := false
	for {
		if len(server.events) >= rdpMaxFrames {
			logger.Debug("RDP frame limit reached", slog.String("protocol", "rdp"))
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			server.flushPending()
			endReason = connection.EndTimeout
			return nil
		}
		n, err := rd.Read(buffer)
		if err != nil && n <= 0 {
			logger.Debug("Failed to read from connection", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			server.flushPending()
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if n <= 0 {
			continue
		}

		raw := make([]byte, n)
		copy(raw, buffer[:n])

		// The client starts TLS on the same TCP connection after the Connection
		// Confirm. Terminate it using the RDP-specific certificate and keep
		// reading the decrypted stream.
		if !tlsDone && len(server.pending) == 0 && rdp.IsTLSRecord(raw) {
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

		// CredSSP frames are DER, not TPKT; they never share a read with TPKT.
		if tlsDone && len(server.pending) == 0 && rdp.IsTSRequest(raw) {
			fr := parsedRDP{Direction: "read", Payload: raw}
			parsed := rdp.ParseCredSSP(raw)
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
				fr.NTLMVersion = parsed.NTLMVersion
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
			continue
		}

		// X.224 traffic: a read can hold several TPKT PDUs (Erect Domain and
		// Attach User usually arrive together) or only part of one.
		server.pending = append(server.pending, raw...)
		pdus, rest := rdp.SplitTPKT(server.pending)
		server.pending = append([]byte(nil), rest...)
		if len(server.pending) > rdpMaxPending {
			server.flushPending()
		}
		for _, pdu := range pdus {
			done, reason, err := server.handleTPKT(append([]byte(nil), pdu...))
			if done || err != nil {
				endReason = reason
				return err
			}
		}
	}
}
