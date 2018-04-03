package gcpsecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/logformat"
	"github.com/hashicorp/vault/logical"
	"github.com/mgutz/logxi/v1"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logformat.NewVaultLogger(log.LevelTrace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
			MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
