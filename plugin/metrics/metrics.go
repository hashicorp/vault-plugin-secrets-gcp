package metrics

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
)

// OperationFunc is a function type that defines the signature for operations taken from the Vault SDK.
// @TODO this can be removed when this is moved to the Vault SDK
type OperationFunc func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error)

// PluginMetrics holds the Prometheus metrics for the plugin.
type PluginMetrics struct {
	TotalRequests prometheus.Counter
	TotalErrors   prometheus.Counter
}

// NewCounter creates a new Prometheus counter with the given name and help text.
func NewCounter(name string, help string) prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
	)
}

func GetBasicCounters(plugin string) map[string]prometheus.Counter {
	// Create counters for total requests and errors for the plugin
	requests := NewCounter(plugin+"_total_requests", "Number of requests made to the plugin")
	errors := NewCounter(plugin+"_total_errors", "Number of failing requests")

	// Register the counters with Prometheus
	prometheus.MustRegister(requests)
	prometheus.MustRegister(errors)

	// Return a map of counters for easy access
	return map[string]prometheus.Counter{
		plugin + "_total_requests": requests,
		plugin + "_total_errors":   errors,
	}
}

func (p *PluginMetrics) MetricsCallbackRequestWrapper(f OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Increment the total requests counter
		p.TotalRequests.Inc()

		// Call the original function
		resp, err := f(ctx, req, data)

		// If there is an error, increment the total errors counter
		if err != nil {
			p.TotalErrors.Inc()
		}

		return resp, err
	}

}
