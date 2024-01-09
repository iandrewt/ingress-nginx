/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package opentelemetry

import (
	"regexp"

	networking "k8s.io/api/networking/v1"
	"k8s.io/klog/v2"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

const (
	enableOpenTelemetryAnnotation = "enable-opentelemetry"
	otelTrustSpanAnnotation       = "opentelemetry-trust-incoming-span"
	otelOperationNameAnnotation   = "opentelemetry-operation-name"
	otelPropagationTypeAnnotation = "opentelemetry-propagation-type"
)

var regexOperationName = regexp.MustCompile(`^[A-Za-z0-9_\-]*$`)

var otelAnnotations = parser.Annotation{
	Group: "opentelemetry",
	Annotations: parser.AnnotationFields{
		enableOpenTelemetryAnnotation: {
			Validator: parser.ValidateBool,
			Scope:     parser.AnnotationScopeLocation,
			Risk:      parser.AnnotationRiskLow,
			Documentation: `This annotation defines if Open Telemetry collector should be enable for this location. OpenTelemetry should 
			already be configured by Ingress administrator`,
		},
		otelTrustSpanAnnotation: {
			Validator:     parser.ValidateBool,
			Scope:         parser.AnnotationScopeLocation,
			Risk:          parser.AnnotationRiskLow,
			Documentation: `This annotation enables or disables using spans from incoming requests as parent for created ones`,
		},
		otelOperationNameAnnotation: {
			Validator:     parser.ValidateRegex(regexOperationName, true),
			Scope:         parser.AnnotationScopeLocation,
			Risk:          parser.AnnotationRiskMedium,
			Documentation: `This annotation defines what operation name should be added to the span`,
		},
		otelPropagationTypeAnnotation: {
			Validator:     parser.ValidateOptions([]string{"w3c", "b3"}, false, true),
			Scope:         parser.AnnotationScopeLocation,
			Risk:          parser.AnnotationRiskLow,
			Documentation: `This annotation defines what propagation type should be used for the span`,
		},
	},
}

type opentelemetry struct {
	r                resolver.Resolver
	annotationConfig parser.Annotation
}

// Config contains the configuration to be used in the Ingress
type Config struct {
	Enabled         bool   `json:"enabled"`
	Set             bool   `json:"set"`
	TrustEnabled    bool   `json:"trust-enabled"`
	TrustSet        bool   `json:"trust-set"`
	OperationName   string `json:"operation-name"`
	PropagationType string `json:"propagation-type"`
}

// Equal tests for equality between two Config types
func (bd1 *Config) Equal(bd2 *Config) bool {
	if bd1.Set != bd2.Set {
		return false
	}

	if bd1.Enabled != bd2.Enabled {
		return false
	}

	if bd1.TrustSet != bd2.TrustSet {
		return false
	}

	if bd1.TrustEnabled != bd2.TrustEnabled {
		return false
	}

	if bd1.OperationName != bd2.OperationName {
		return false
	}

	if bd1.PropagationType != bd2.PropagationType {
		return false
	}

	return true
}

// NewParser creates a new serviceUpstream annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return opentelemetry{
		r:                r,
		annotationConfig: otelAnnotations,
	}
}

// Parse parses the annotations to look for opentelemetry configurations
func (c opentelemetry) Parse(ing *networking.Ingress) (interface{}, error) {
	var err error
	config := &Config{}

	config.Set = true
	config.Enabled, err = parser.GetBoolAnnotation(enableOpenTelemetryAnnotation, ing, c.annotationConfig.Annotations)
	if err != nil {
		if errors.IsInvalidContent(err) {
			klog.Warningf("annotation %s contains invalid directive, defaulting to false", enableOpenTelemetryAnnotation)
		}
		config.Enabled = false
		config.Set = false
	}

	config.TrustSet = true
	config.TrustEnabled, err = parser.GetBoolAnnotation(otelTrustSpanAnnotation, ing, c.annotationConfig.Annotations)
	if err != nil {
		if errors.IsInvalidContent(err) {
			klog.Warningf("annotation %s contains invalid directive, defaulting to false", otelTrustSpanAnnotation)
		}
		config.TrustSet = false
		config.TrustEnabled = false
	}

	config.OperationName, err = parser.GetStringAnnotation(otelOperationNameAnnotation, ing, c.annotationConfig.Annotations)
	if err != nil {
		if errors.IsInvalidContent(err) {
			klog.Warningf("annotation %s contains invalid directive, defaulting", otelOperationNameAnnotation)
		}
		config.OperationName = ""
	}

	config.PropagationType, err = parser.GetStringAnnotation(otelPropagationTypeAnnotation, ing, c.annotationConfig.Annotations)
	if err != nil {
		if errors.IsInvalidContent(err) {
			klog.Warningf("annotation %s contains invalid directive, defaulting", otelPropagationTypeAnnotation)
		}
		config.PropagationType = ""
	}

	return config, nil
}

func (c opentelemetry) GetDocumentation() parser.AnnotationFields {
	return c.annotationConfig.Annotations
}

func (c opentelemetry) Validate(anns map[string]string) error {
	maxrisk := parser.StringRiskToRisk(c.r.GetSecurityConfiguration().AnnotationsRiskLevel)
	return parser.CheckAnnotationRisk(anns, maxrisk, otelAnnotations.Annotations)
}
