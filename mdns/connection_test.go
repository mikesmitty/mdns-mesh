package mdns

import (
	"net/url"
	"testing"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func TestCreateClientOptions(t *testing.T) {
	uri, _ := url.Parse("tcp://localhost:1883")
	clientId := "test-client"

	onConnect := func(c mqtt.Client) {}

	onLost := func(c mqtt.Client, err error) {}

	opts := createClientOptions(clientId, uri, onConnect, onLost)

	if opts.ClientID != clientId {
		t.Errorf("Expected ClientID %s, got %s", clientId, opts.ClientID)
	}

	// We can't directly inspect OnConnect/OnConnectionLost from ClientOptions easily
	// as the fields might be private or not exposed in a way we can check equality directly for functions.
	// However, we can verify that the options are set by the fact that the code compiles
	// and we passed them in.
	// Actually, paho mqtt ClientOptions struct fields OnConnect and OnConnectionLost are public.

	if opts.OnConnect == nil {
		t.Error("OnConnect handler is nil")
	}

	if opts.OnConnectionLost == nil {
		t.Error("OnConnectionLost handler is nil")
	}

	// We can simulate calling them to ensure they are the ones we passed
	// but strict function equality in Go is not possible.
	// This is a basic sanity check that we are setting them.
}
