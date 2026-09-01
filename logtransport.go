package documentstore

import (
	"context"

	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// logTransport is a broker.Transport that writes published events to the service
// logger. It lets the document-domain-event publisher emit without a hard broker
// dependency in development; the platform's Transport is service-provided, so a
// real NATS/Kafka transport is injected in production with no code change here.
// PII/secret redaction still applies (platform.Setup); the broker envelope strips
// token-shaped attributes. (Mirrors eparaksts-signer/logtransport.go.)
type logTransport struct{ log *zap.Logger }

// newLogTransport returns a logging broker transport.
func newLogTransport(log *zap.Logger) broker.Transport {
	if log == nil {
		log = zap.NewNop()
	}

	return &logTransport{log: log}
}

// Publish writes the event payload to the logger as a document_event line.
func (t *logTransport) Publish(_ context.Context, topic, key string, payload []byte) error {
	t.log.Info("document_event",
		zap.String("topic", topic),
		zap.String("key", key),
		zap.ByteString("event", payload),
	)

	return nil
}
