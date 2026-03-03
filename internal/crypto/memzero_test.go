package crypto

import "testing"

func TestZeroClears(t *testing.T) {
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d not zero: got 0x%02x", i, v)
		}
	}
}

func TestZeroEmptySlice(t *testing.T) {
	b := []byte{}
	Zero(b) // should not panic
}

func TestZeroNilSlice(t *testing.T) {
	var b []byte
	Zero(b) // should not panic
}
