package main

import (
	"testing"
)

func TestServerCreation(t *testing.T) {
	s, err := NewServer(":3478")
	if err != nil {
		t.Error(err)
	}
	s.Close()
}
