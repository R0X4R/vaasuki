package model

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestFindingJSONSerialization(t *testing.T) {
	f := Finding{
		Target:     "127.0.0.1",
		Port:       21,
		Protocol:   "ftp",
		Title:      "FTP anonymous authentication enabled",
		Severity:   "medium",
		Confidence: Confirmed,
		Timestamp:  time.Now().UTC(),
		Evidence:   []string{"230 Login successful"},
	}

	var buf bytes.Buffer
	if err := WriteFinding(&buf, f); err != nil {
		t.Fatalf("failed to write finding: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode finding json: %v", err)
	}

	if decoded.Confidence != Confirmed {
		t.Errorf("expected confidence %s, got %s", Confirmed, decoded.Confidence)
	}
	if decoded.Port != 21 {
		t.Errorf("expected port 21, got %d", decoded.Port)
	}
}
