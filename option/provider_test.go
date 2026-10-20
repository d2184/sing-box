package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestProviderRemotePath(t *testing.T) {
	for _, content := range []string{
		`{"url":"https://example.com/provider.json"}`,
		`{"url":"https://example.com/provider.json","path":"provider.json"}`,
	} {
		var options ProviderRemoteOptions
		require.NoError(t, json.Unmarshal([]byte(content), &options))
	}
}
