package model

import (
	"encoding/json"
	"io"
	"time"
)

type Confidence string

const (
	Informational Confidence = "informational"
	Potential     Confidence = "potential"
	Confirmed     Confidence = "confirmed"
	Critical      Confidence = "critical"
)

// AuthResult holds authentication attempt outcomes.
type AuthResult struct {
	Attempted bool   `json:"attempted"`
	Method    string `json:"method,omitempty"`
	Status    string `json:"status,omitempty"`
}

// Finding represents a single verified finding.
type Finding struct {
	Target     string     `json:"target"`
	Port       int        `json:"port"`
	Protocol   string     `json:"protocol"`
	Service    string     `json:"service,omitempty"`
	Version    string     `json:"version,omitempty"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Auth       AuthResult `json:"authentication,omitempty"`
	Evidence   []string   `json:"evidence,omitempty"`
	Timestamp  time.Time  `json:"timestamp"`
}

// WriteFinding serializes a finding as a single JSON line.
func WriteFinding(w io.Writer, f Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}
