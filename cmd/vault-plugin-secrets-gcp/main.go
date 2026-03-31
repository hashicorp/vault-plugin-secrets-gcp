// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"os"

	gcpsecrets "github.com/hashicorp/vault-plugin-secrets-gcp/plugin"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	// serve the metrics endpoint in a goroutine to not block plugin
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		_ = http.ListenAndServe("127.0.0.1:9090", nil)
	}()

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: gcpsecrets.Factory,
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
