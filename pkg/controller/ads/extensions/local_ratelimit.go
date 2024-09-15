package extensions

import (
	"fmt"
	"time"

	v1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"kmesh.net/kmesh/api/v2/filter"
	"kmesh.net/kmesh/api/v2/listener"
)

const LocalRateLimit = "envoy.filters.tcp.local_ratelimit"

// NewLocalRateLimit constructs a new LocalRateLimit filter wrapper.
func NewLocalRateLimit(filter *listenerv3.Filter) (*listener.Filter_LocalRateLimit, error) {
	localRateLimit, err := newLocalRateLimit(filter)
	if err != nil {
		return nil, err
	}

	return &listener.Filter_LocalRateLimit{
		LocalRateLimit: localRateLimit,
	}, nil
}

// newLocalRateLimit creates a new LocalRateLimit filter.
func newLocalRateLimit(Filter *listenerv3.Filter) (*filter.LocalRateLimit, error) {
	unstructured, err := unmarshalToTypedStruct(Filter)
	if err != nil {
		return nil, err
	}

	bucket := unstructured.GetValue().GetFields()["token_bucket"].GetStructValue().GetFields()
	interval, err := time.ParseDuration(bucket["fill_interval"].GetStringValue())
	if err != nil {
		return nil, fmt.Errorf("failed to convert fill_interval")
	}
	return &filter.LocalRateLimit{TokenBucket: &filter.TokenBucket{
		MaxTokens:     int64(bucket["max_tokens"].GetNumberValue()),
		TokensPerFill: int64(bucket["tokens_per_fill"].GetNumberValue()),
		FillInterval:  interval.Nanoseconds(),
	}}, nil
}

// unmarshalToTypedStruct unmarshal a protobuf Any message to a TypedStruct.
func unmarshalToTypedStruct(filter *listenerv3.Filter) (*v1.TypedStruct, error) {
	typed := &v1.TypedStruct{}
	if err := anypb.UnmarshalTo(filter.GetTypedConfig(), typed, proto.UnmarshalOptions{}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TypedConfig %w", err)
	}
	return typed, nil
}
