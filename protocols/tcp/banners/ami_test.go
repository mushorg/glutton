package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAMIFollowUp(t *testing.T) {
	orig := amiChallenge
	amiChallenge = func() int64 { return 1234567890 }
	t.Cleanup(func() { amiChallenge = orig })

	missing := []byte("Response: Error\r\nMessage: Missing action in request\r\n\r\n")
	for _, tc := range []struct {
		name string
		in   string
		want Response
	}{
		{"blank line", "\r\n", Response{Name: "ami-error", Data: missing}},
		{"bare LF", "\n", Response{Name: "ami-error", Data: missing}},
		{"crlf crlf", "\r\n\r\n", Response{Name: "ami-error", Data: append(append([]byte(nil), missing...), missing...)}},
		{"unterminated", "Action: Ping\r\n", Response{Name: "ami", NoReply: true}},
		{"partial line", "Act", Response{Name: "ami", NoReply: true}},
		{"permission denied", "Action: CoreSettings\r\nActionID: abc\r\n\r\n",
			Response{Name: "ami-error", Data: []byte("Response: Error\r\nActionID: abc\r\nMessage: Permission denied\r\n\r\n")}},
		{"login", "action: login\r\nusername: admin\r\nsecret: amp111\r\n\r\nAction: Ping\r\n\r\n",
			Response{Name: "ami-auth-failed", Username: "admin", Password: "amp111", Close: true,
				Data: []byte("Response: Error\r\nMessage: Authentication failed\r\n\r\n")}},
		{"logoff", "Action: Logoff\r\n\r\n",
			Response{Name: "ami-goodbye", Close: true, Data: []byte("Response: Goodbye\r\nMessage: Thanks for all the fish.\r\n\r\n")}},
		{"challenge md5", "Action: Challenge\r\nAuthType: MD5\r\nActionID: 7\r\n\r\n",
			Response{Name: "ami-challenge", Data: []byte("Response: Success\r\nActionID: 7\r\nChallenge: 1234567890\r\n\r\n")}},
		{"challenge without type", "Action: Challenge\r\n\r\n",
			Response{Name: "ami-error", Data: []byte("Response: Error\r\nMessage: Must specify AuthType\r\n\r\n")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AMIFollowUp([]byte(tc.in))
			require.True(t, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
