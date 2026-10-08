package rdp

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestIdentityDefaults(t *testing.T) {
	resetIdentity()
	t.Cleanup(resetIdentity)

	computer, domain := Identity()
	require.True(t, strings.HasPrefix(computer, "WIN-"), "default computer name must start with WIN-: %s", computer)
	require.Len(t, computer, 15, "WIN- + 11 chars")
	require.Equal(t, "WORKGROUP", domain)

	// Second call must return the same values (stable identity).
	computer2, domain2 := Identity()
	require.Equal(t, computer, computer2)
	require.Equal(t, domain, domain2)
}

func TestIdentityFromViper(t *testing.T) {
	resetIdentity()
	t.Cleanup(func() {
		resetIdentity()
		viper.Set("rdp.computer_name", nil)
		viper.Set("rdp.domain_name", nil)
	})

	viper.Set("rdp.computer_name", "MYSERVER")
	viper.Set("rdp.domain_name", "CORP")

	computer, domain := Identity()
	require.Equal(t, "MYSERVER", computer)
	require.Equal(t, "CORP", domain)
}
