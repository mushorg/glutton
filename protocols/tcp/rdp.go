package tcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
)

type parsedRDP struct {
	Direction string         `json:"direction,omitempty"`
	Command   string         `json:"command,omitempty"`
	Cookie    string         `json:"cookie,omitempty"`
	Protocols string         `json:"protocols,omitempty"`
	Header    rdp.TKIPHeader `json:"header,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
}

// rdpMaxReceive is larger than maxBufferSize: modern TLS ClientHellos often
// exceed 1KiB, and truncating them caused leftover bytes to be misparsed as TPKT.
const rdpMaxReceive = 16 << 10

type rdpServer struct {
	events []parsedRDP
	conn   net.Conn
}

func (rs *rdpServer) write(header rdp.TKIPHeader, data []byte) error {
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

	buffer := make([]byte, rdpMaxReceive)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		n, err := conn.Read(buffer)
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
		logger.Debug(fmt.Sprintf("rdp \n%s", hex.Dump(raw)))

		header := rdp.ParseTKIPHeader(raw)

		// After Connection Confirm selects TLS|CredSSP, the client speaks TLS on
		// the same TCP connection. Answer with a stub handshake instead of another X.224 CC.
		if rdp.IsTLSRecord(raw) {
			server.events = append(server.events, parsedRDP{
				Direction: "read",
				Command:   rdp.CmdTLSClientHello,
				Payload:   raw,
			})
			resp, hsErr := rdp.StubTLSHandshake(conn, raw)
			if len(resp) > 0 {
				server.events = append(server.events, parsedRDP{
					Direction: "write",
					Command:   rdp.CmdTLSHandshake,
					Payload:   resp,
				})
			}
			if hsErr != nil {
				logger.Debug("RDP TLS stub handshake ended", slog.String("protocol", "rdp"), producer.ErrAttr(hsErr))
				endReason = connection.EndClientClose
			}
			return nil
		}

		fr := parsedRDP{
			Direction: "read",
			Command:   rdp.FrameCommand(raw),
			Header:    header,
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
			server.events = append(server.events, fr)
			logger.Debug(fmt.Sprintf("rdp req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				logger.Debug(fmt.Sprintf("rdp data: %s", string(pdu.Data)))
			}
			ccHeader, resp, err := rdp.ConnectionConfirm(pdu.TPDU, rdp.HasRDPNegReq(pdu))
			if err != nil {
				endReason = connection.EndWriteError
				return err
			}
			logger.Debug(fmt.Sprintf("rdp resp pdu: %+v", resp))
			if err := server.write(ccHeader, resp); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case rdp.IsMCSConnectInitial(raw):
			server.events = append(server.events, fr)
			logger.Debug("rdp MCS Connect-Initial", slog.String("protocol", "rdp"), slog.Int("bytes", len(raw)))
			mcsHeader, resp := rdp.MCSConnectResponse()
			if err := server.write(mcsHeader, resp); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			return nil
		default:
			server.events = append(server.events, fr)
			logger.Debug("rdp ignoring non-CR TPDU", slog.String("protocol", "rdp"), slog.Int("tpdu", int(rdp.TPDUType(raw))))
		}
	}
}
