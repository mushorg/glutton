package tcp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/mocks"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xiegeo/modbusone"
)

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

func TestModbusServer(t *testing.T) {
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	clientConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	serverConn, ok := <-accepted
	require.True(t, ok, "failed to accept connection")
	require.NotNil(t, serverConn)

	h := &mocks.MockHoneypot{}
	h.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)

	done := make(chan error, 1)
	go func() {
		done <- HandleModbus(ctx, serverConn, connection.Metadata{}, nopLogger{}, h)
	}()

	client := modbusone.NewTCPClient(clientConn, 0)
	go client.Serve(&modbusone.SimpleHandler{
		WriteCoils:            func(uint16, []bool) error { return nil },
		WriteDiscreteInputs:   func(uint16, []bool) error { return nil },
		WriteHoldingRegisters: func(uint16, []uint16) error { return nil },
		WriteInputRegisters:   func(uint16, []uint16) error { return nil },
	})
	defer client.Close()

	tests := []struct {
		name     string
		fc       modbusone.FunctionCode
		address  uint16
		quantity uint16
	}{
		{"ReadCoils", modbusone.FcReadCoils, 0, 1},
		{"ReadDiscreteInputs", modbusone.FcReadDiscreteInputs, 0, 1},
		{"ReadHoldingRegisters", modbusone.FcReadHoldingRegisters, 0, 1},
		{"ReadInputRegisters", modbusone.FcReadInputRegisters, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdu, err := tt.fc.MakeRequestHeader(tt.address, tt.quantity)
			require.NoError(t, err)
			require.NoError(t, client.DoTransaction(pdu))
		})
	}

	require.NoError(t, clientConn.Close())
	require.NoError(t, <-done)
	h.AssertExpectations(t)
}
