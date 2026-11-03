package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/cassandra"
)

// cassandraMaxFrames bounds the Thrift frames read on one connection.
const cassandraMaxFrames = 32

// cassandraStringResults are the string-returning describe_* calls answered
// with the defaults of a stock Cassandra 3.11 node.
var cassandraStringResults = map[string]string{
	"describe_cluster_name": "Test Cluster",
	"describe_version":      "20.1.0",
	"describe_partitioner":  "org.apache.cassandra.dht.Murmur3Partitioner",
	"describe_snitch":       "org.apache.cassandra.locator.SimpleSnitch",
}

type parsedCassandra struct {
	Direction string             `json:"direction,omitempty"`
	Command   string             `json:"command,omitempty"` // Thrift method name
	Message   *cassandra.Message `json:"message,omitempty"` // read: parsed message header and args
	Path      string             `json:"path,omitempty"`    // set_keyspace keyspace
	Query     string             `json:"query,omitempty"`   // CQL text of execute/prepare_cql*_query
	Username  string             `json:"username,omitempty"`
	Password  string             `json:"password,omitempty"`
	Status    string             `json:"status,omitempty"` // write: reply, exception
	Payload   []byte             `json:"payload,omitempty"`
}

type cassandraServer struct {
	events []parsedCassandra
	conn   net.Conn
}

func (s *cassandraServer) write(command, status string, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedCassandra{Direction: "write", Command: command, Status: status, Payload: data})
	return nil
}

func cassandraArgString(args map[string]any, id string) string {
	s, _ := args[id].(string)
	return s
}

// annotateCassandraCall copies the interesting arguments of well-known calls
// into the frame's top-level fields.
func annotateCassandraCall(frame *parsedCassandra, msg *cassandra.Message) {
	switch msg.Name {
	case "set_keyspace":
		frame.Path = cassandraArgString(msg.Args, "1")
	case "execute_cql_query", "execute_cql3_query", "prepare_cql_query", "prepare_cql3_query":
		frame.Query = cassandraArgString(msg.Args, "1")
	case "login":
		// login(1: AuthenticationRequest{1: map<string,string> credentials})
		if req, ok := msg.Args["1"].(map[string]any); ok {
			if creds, ok := req["1"].(map[string]any); ok {
				frame.Username, _ = creds["username"].(string)
				frame.Password, _ = creds["password"].(string)
			}
		}
	}
}

// cassandraResponse builds the reply to a CALL: a REPLY for the describe_*
// strings and the void login/set_keyspace, else a TApplicationException.
func cassandraResponse(msg *cassandra.Message) (string, []byte) {
	if s, ok := cassandraStringResults[msg.Name]; ok {
		return "reply", cassandra.BuildReply(msg.Name, msg.SeqID, cassandra.StringResult(s))
	}
	switch msg.Name {
	case "login", "set_keyspace":
		return "reply", cassandra.BuildReply(msg.Name, msg.SeqID, cassandra.VoidResult())
	}
	return "exception", cassandra.BuildException(msg.Name, msg.SeqID,
		fmt.Sprintf("Invalid method name: '%s'", msg.Name), cassandra.ExceptionUnknownMethod)
}

// HandleCassandra takes a net.Conn and answers Cassandra's legacy Thrift RPC
// (framed binary protocol) on tcp/9160. describe_cluster_name and the other
// string describe_* calls get stock-node answers, login and set_keyspace
// succeed, and every other method gets an UNKNOWN_METHOD exception.
func HandleCassandra(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &cassandraServer{events: []parsedCassandra{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("cassandra", conn, md, helpers.FirstOrEmpty[parsedCassandra](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Cassandra connection", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < cassandraMaxFrames; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		raw, err := cassandra.ReadFrame(conn)
		if len(raw) > 0 {
			server.events = append(server.events, parsedCassandra{Direction: "read", Payload: raw})
		}
		if err != nil {
			var frameErr *cassandra.FrameError
			if errors.As(err, &frameErr) {
				logger.Debug("Invalid Thrift frame", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return nil
			}
			logger.Debug("Failed to read data", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}

		frame := &server.events[len(server.events)-1]
		msg, err := cassandra.ParseMessage(raw[cassandra.FrameHeaderLen:])
		if err != nil {
			// Cassandra drops the connection on an undecodable message.
			logger.Debug("Invalid Thrift message", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
			endReason = connection.EndReadError
			return nil
		}
		frame.Command = msg.Name
		frame.Message = &msg
		annotateCassandraCall(frame, &msg)

		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("Cassandra Thrift call received",
				slog.String("handler", "cassandra"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", msg.Name),
			)
		}

		switch msg.Type {
		case cassandra.TypeCall:
			status, resp := cassandraResponse(&msg)
			if err := server.write(msg.Name, status, resp); err != nil {
				logger.Debug("Failed to write Thrift reply", slog.String("protocol", "cassandra"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		case cassandra.TypeOneway:
			// no reply by definition
		default:
			// A client never sends REPLY/EXCEPTION; drop the connection.
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
