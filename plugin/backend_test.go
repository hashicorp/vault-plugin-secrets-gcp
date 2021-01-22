package gcpsecrets

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

func getTestBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	if os.Getenv("VAULT_LOG") == "" {
		config.Logger = hclog.NewNullLogger()
	}
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
		MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*backend), config.StorageView
}
