package tcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/xiegeo/modbusone"
)

type parsedModbus struct {
	Direction string         `json:"direction,omitempty"`
	Header    mongoMsgHeader `json:"header,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
	OpCodeStr string         `json:"opcode_str,omitempty"`
}

type modbusServer struct {
	events  []parsedModbus
	conn    net.Conn
	logger  interfaces.Logger
	handler modbusone.ProtocolHandler
}

func (s *modbusServer) read() ([]byte, error) {
	data := make([]byte, modbusone.MBAPHeaderLength+modbusone.MaxPDUSize)
	n, err := io.ReadFull(s.conn, data[:modbusone.TCPHeaderLength])
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}

	if data[2] != 0 || data[3] != 0 {
		return nil, fmt.Errorf("MBAP protocol of %X %X is unknown", data[2], data[3])
	}

	l := int(data[4])*256 + int(data[5])
	if l <= 2 {
		return nil, fmt.Errorf("MBAP data length of %v is too short", l)
	}
	if len(data) < l+modbusone.TCPHeaderLength {
		return nil, fmt.Errorf("MBAP data length of %v is too long", l)
	}
	n, err = io.ReadFull(s.conn, data[modbusone.TCPHeaderLength:l+modbusone.TCPHeaderLength])
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}

	s.events = append(s.events, parsedModbus{
		Direction: "read",
		Payload:   data[:n+modbusone.TCPHeaderLength],
	})
	return data[:n+modbusone.TCPHeaderLength], nil
}

func (s *modbusServer) write(data []byte) error {
	l := len(data) + 1 // PDU + byte of slaveID
	bs := make([]byte, modbusone.TCPHeaderLength+l)
	bs[4] = byte(l / 256)
	bs[5] = byte(l)
	copy(bs[modbusone.MBAPHeaderLength:], data)
	if _, err := s.conn.Write(bs); err != nil {
		return err
	}
	s.events = append(s.events, parsedModbus{
		Direction: "write",
		Payload:   data,
	})
	return nil
}

func (s *modbusServer) writeError(req modbusone.PDU, err error) {
	if err := s.write(modbusone.ExceptionReplyPacket(req, modbusone.ToExceptionCode(err))); err != nil {
		s.logger.Error("Error writing Modbus exception reply", slog.String("protocol", "modbus"), producer.ErrAttr(err))
	}

}

const size = 0x10000

var (
	discretes        [size]bool
	coils            [size]bool
	inputRegisters   [size]uint16
	holdingRegisters [size]uint16
)

func HandleModbus(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &modbusServer{
		conn:   conn,
		logger: logger,
		handler: &modbusone.SimpleHandler{
			ReadDiscreteInputs: func(address, quantity uint16) ([]bool, error) {
				fmt.Printf("ReadDiscreteInputs from %v, quantity %v\n", address, quantity)
				return discretes[address : address+quantity], nil
			},
			WriteDiscreteInputs: func(address uint16, values []bool) error {
				fmt.Printf("WriteDiscreteInputs from %v, quantity %v\n", address, len(values))
				for i, v := range values {
					discretes[address+uint16(i)] = v
				}
				return nil
			},

			ReadCoils: func(address, quantity uint16) ([]bool, error) {
				fmt.Printf("ReadCoils from %v, quantity %v\n", address, quantity)
				return coils[address : address+quantity], nil
			},
			WriteCoils: func(address uint16, values []bool) error {
				fmt.Printf("WriteCoils from %v, quantity %v\n", address, len(values))
				for i, v := range values {
					coils[address+uint16(i)] = v
				}
				return nil
			},

			ReadInputRegisters: func(address, quantity uint16) ([]uint16, error) {
				fmt.Printf("ReadInputRegisters from %v, quantity %v\n", address, quantity)
				return inputRegisters[address : address+quantity], nil
			},
			WriteInputRegisters: func(address uint16, values []uint16) error {
				fmt.Printf("WriteInputRegisters from %v, quantity %v\n", address, len(values))
				for i, v := range values {
					inputRegisters[address+uint16(i)] = v
				}
				return nil
			},

			ReadHoldingRegisters: func(address, quantity uint16) ([]uint16, error) {
				fmt.Printf("ReadHoldingRegisters from %v, quantity %v\n", address, quantity)
				return holdingRegisters[address : address+quantity], nil
			},
			WriteHoldingRegisters: func(address uint16, values []uint16) error {
				fmt.Printf("WriteHoldingRegisters from %v, quantity %v\n", address, len(values))
				for i, v := range values {
					holdingRegisters[address+uint16(i)] = v
				}
				return nil
			},

			OnErrorImp: func(req modbusone.PDU, errRep modbusone.PDU) {
				fmt.Printf("error received: %v from req: %v\n", errRep, req)
			},
		},
	}

	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
		}
	}()

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "modbus"), producer.ErrAttr(err))
			return nil
		}
		data, err := server.read()
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading from connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
			}
			break
		}

		if len(data) == 0 {
			continue
		}

		p := modbusone.PDU(data[modbusone.MBAPHeaderLength:])
		if err := p.ValidateRequest(); err != nil {
			return fmt.Errorf("invalid modbus request: %w", err)
		}

		fc := p.GetFunctionCode()
		switch {
		case fc.IsReadToServer():
			data, err := server.handler.OnRead(p)
			if err != nil {
				server.writeError(p, err)
				continue
			}
			if err := server.write(p.MakeReadReply(data)); err != nil {
				logger.Error("Error writing to connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
				continue
			}
		case fc.IsWriteToServer():
			data, err := p.GetRequestValues()
			if err != nil {
				server.writeError(p, err)
				continue
			}
			err = server.handler.OnWrite(p, data)
			if err != nil {
				server.writeError(p, err)
				continue
			}
			if err := server.write(p.MakeWriteReply()); err != nil {
				logger.Error("Error writing to connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
				continue
			}
		default:
			logger.Warn("Unsupported Modbus function code", slog.String("protocol", "modbus"), slog.String("function_code", fmt.Sprintf("ExceptionCode:0x%02X", byte(fc))))
		}
	}

	return nil
}
