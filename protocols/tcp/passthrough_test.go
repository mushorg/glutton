package tcp

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, attrs ...interface{}) {
	m.Called(msg, attrs)
}

func (m *MockLogger) Debug(msg string, attrs ...interface{}) {
	m.Called(msg, attrs)
}

func (m *MockLogger) Error(msg string, attrs ...interface{}) {
	m.Called(msg, attrs)
}

func (m *MockLogger) Warn(msg string, attrs ...interface{}) {
	m.Called(msg, attrs)
}

func TestIsLikelyText(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Empty input",
			input:    []byte(""),
			expected: false,
		},
		{
			name:     "Simple ASCII text",
			input:    []byte("This is plain text"),
			expected: true,
		},
		{
			name:     "Text with whitespace",
			input:    []byte("Text with\nnewlines\tand tabs\r\n"),
			expected: true,
		},
		{
			name:     "Binary data",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: false,
		},
		{
			name:     "Mixed content with few non-printable",
			input:    []byte("Text\x00with\x01binary"),
			expected: true, // checking threshold at 85.7%
		},
		{
			name:     "Exactly 80% printable",
			input:    []byte("AAAA\x01"), // 4/5 = 80%
			expected: false,
		},
		{
			name:     "Just below 80% printable",
			input:    []byte("AAA\x01\x02"), // 3/5 = 60%
			expected: false,
		},
	}

	srv := &passThroughServer{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := srv.isLikelyText(test.input)
			require.Equal(t, test.expected, result, "unexpected result for test case: %s", test.name)
		})
	}
}

func TestRecording(t *testing.T) {
	s := &passThroughServer{}
	s.recordEvent("test", []byte("data"), true)
	assert.Len(t, s.events, 1)
}

func TestPipeBidirectional(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	mockServer := &passThroughServer{
		events: make([]parsedPassThrough, 0),
		conn:   nil,
		target: "test-target:1234",
		source: "test-source:5678",
	}

	type args struct {
		ctx     context.Context
		src     net.Conn
		dst     net.Conn
		server  *passThroughServer
		logger  interfaces.Logger
		capture bool
		errChan chan error
	}
	tests := []struct {
		name        string
		args        args
		setup       func() (net.Conn, net.Conn)
		wantErr     bool
		wantErrType error
		verify      func(t *testing.T, args args)
	}{
		{
			name: "successful data transfer with capture",
			args: args{
				ctx:     context.Background(),
				server:  mockServer,
				logger:  mockLogger,
				capture: true,
				errChan: make(chan error, 1),
			},

			setup: func() (net.Conn, net.Conn) {
				client, server := net.Pipe()
				go func() {
					client.Write([]byte("test data"))
					client.Close()
				}()
				return client, server
			},
			verify: func(t *testing.T, args args) {
				buf := make([]byte, 1024)
				n, err := args.dst.Read(buf)

				require.NoError(t, err)
				assert.Equal(t, "test data", string(buf[:n]))

				require.True(t, args.capture, "Capture should be enabled")
			},
		},
		{
			name: "read error from source",
			args: args{
				ctx:     context.Background(),
				server:  mockServer,
				logger:  mockLogger,
				capture: false,
				errChan: make(chan error, 1),
			},
			setup: func() (net.Conn, net.Conn) {
				client, server := net.Pipe()
				client.Close()
				return client, server
			},
			wantErr:     true,
			wantErrType: io.EOF,
		},
		{
			name: "write error to destination",
			args: args{
				ctx:     context.Background(),
				server:  mockServer,
				logger:  mockLogger,
				capture: false,
				errChan: make(chan error, 1),
			},
			setup: func() (net.Conn, net.Conn) {
				client, server := net.Pipe()
				server.Close()
				return client, server
			},
			wantErr: true,
		},
		{
			name: "zero byte read",
			args: args{
				ctx:     context.Background(),
				server:  mockServer,
				logger:  mockLogger,
				capture: true,
				errChan: make(chan error, 1),
			},
			setup: func() (net.Conn, net.Conn) {
				client, server := net.Pipe()
				go func() {
					client.Write([]byte{})
					client.Close()
				}()
				return client, server
			},
			verify: func(t *testing.T, args args) {
				assert.Empty(t, args.server.events)
			},
		},
		{
			name: "large data transfer",
			args: args{
				ctx:     context.Background(),
				server:  mockServer,
				logger:  mockLogger,
				capture: true,
				errChan: make(chan error, 1),
			},
			setup: func() (net.Conn, net.Conn) {
				client, server := net.Pipe()
				largeData := make([]byte, 8192)
				rand.Read(largeData)
				go func() {
					client.Write(largeData)
					client.Close()
				}()
				return client, server
			},
			verify: func(t *testing.T, args args) {
				buf := make([]byte, 8192)
				n, err := io.ReadFull(args.dst, buf)
				require.NoError(t, err)
				assert.Equal(t, 8192, n)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.args.src, tt.args.dst = tt.setup()
				defer tt.args.src.Close()
				defer tt.args.dst.Close()
			}

			go pipeBidirectional(
				tt.args.src,
				tt.args.dst,
				tt.args.server,
				tt.args.logger,
				tt.args.capture,
				tt.args.errChan,
			)

			if tt.verify != nil {
				tt.verify(t, tt.args)
			}
		})
	}
}
