package crypto

import "runtime"

// Zero overwrites b with zeros to prevent sensitive data from lingering
// in memory. Uses runtime.KeepAlive to prevent the compiler from eliding
// the zeroing as a dead store.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
