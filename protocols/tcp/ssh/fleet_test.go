package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAuthorizedKeys(t *testing.T) {
	require.True(t, IsAuthorizedKeys("/root/.ssh/authorized_keys"))
	require.True(t, IsAuthorizedKeys("/home/simo/.ssh/authorized_keys"))
	require.True(t, IsAuthorizedKeys("/home/simo/.ssh/authorized_keys2"))
	require.False(t, IsAuthorizedKeys("/home/simo/authorized_keys"))
	require.False(t, IsAuthorizedKeys("/tmp/.ssh/known_hosts"))
	require.False(t, IsAuthorizedKeys(""))
}
