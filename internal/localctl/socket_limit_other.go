//go:build !windows && !linux && !darwin

package localctl

// Keep a conservative portable limit for Unix targets whose sockaddr_un
// layout is not part of the supported client matrix.
const unixSocketPathLimit = 104
