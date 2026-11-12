package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
	"github.com/mushorg/glutton/protocols/udp/mssqlbrowser"
)

const maxMSSQLBrowserPayload = 1024

type parsedMSSQLBrowser struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`  // CLNT_BCAST_EX, CLNT_UCAST_EX, CLNT_UCAST_INST, CLNT_UCAST_DAC
	Instance  string `json:"instance,omitempty"` // requested instance name
	Status    string `json:"status,omitempty"`   // write: SVR_RESP
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// mssqlBrowserPersona describes the instance the Browser advertises: the
// default instance on tcp/1433 (served by the mssql handler), with the host
// name the mssql and rdp handlers report and the product version of the
// mssql handler's @@version. Tests may swap it.
var mssqlBrowserPersona = func() mssqlbrowser.Persona {
	computer, _ := rdp.Identity()
	return mssqlbrowser.Persona{
		Server:   computer,
		Instance: "MSSQLSERVER",
		Version:  "15.0.2000.5",
		TCPPort:  1433,
	}
}

// HandleMSSQLBrowser answers SQL Server Browser (MC-SQLR) instance
// enumeration on udp/1434. Broadcast/unicast enumeration and a unicast query
// for the default instance get an SVR_RESP advertising tcp/1433; other
// datagrams are recorded only.
func HandleMSSQLBrowser(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxMSSQLBrowserPayload))
	copy(payload, data[:len(payload)])

	events := []parsedMSSQLBrowser{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("mssql_browser", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedMSSQLBrowser](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mssql_browser"), producer.ErrAttr(err))
		}
	}()

	req := mssqlbrowser.Parse(data)
	events = append(events, parsedMSSQLBrowser{
		Direction: "read",
		Command:   req.Command,
		Instance:  req.Instance,
		Payload:   payload,
		Truncated: len(data) > maxMSSQLBrowserPayload,
	})

	logger.Info("mssql_browser request received",
		slog.String("handler", "mssql_browser"),
		slog.String("protocol", "mssql_browser"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", req.Command),
	)

	body, status := mssqlbrowser.Reply(req, mssqlBrowserPersona())
	if body == nil {
		return nil
	}
	events = append(events, parsedMSSQLBrowser{Direction: "write", Command: req.Command, Status: status, Payload: body})
	if err := h.ReplyUDP(srcAddr, dstAddr, body); err != nil {
		logger.Error("Failed to send mssql_browser reply", slog.String("protocol", "mssql_browser"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
