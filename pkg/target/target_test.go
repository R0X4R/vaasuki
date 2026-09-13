package target

import (
	"reflect"
	"testing"
)

func TestParsePortList(t *testing.T) {
	ports, err := ParsePortList("21, 22, 80-82, 443")
	if err != nil {
		t.Fatalf("unexpected error parsing port list: %v", err)
	}

	expected := []int{21, 22, 80, 81, 82, 443}
	if !reflect.DeepEqual(ports, expected) {
		t.Errorf("expected %v, got %v", expected, ports)
	}

	// Test invalid port range
	_, err = ParsePortList("90-80")
	if err == nil {
		t.Errorf("expected error on inverted port range")
	}

	// Test invalid port number
	_, err = ParsePortList("70000")
	if err == nil {
		t.Errorf("expected error on out of range port")
	}
}
