package gcpsecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/helper/logging"
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

func getTestBackend(tb testing.TB) (logical.Backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	logLevel := os.Getenv("VAULT_LOG")
	if logLevel == "" {
		config.Logger = hclog.NewNullLogger()
	} else {
		config.Logger = logging.NewVaultLogger(hclog.LevelFromString(logLevel))
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
