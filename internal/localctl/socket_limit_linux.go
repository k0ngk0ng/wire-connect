//go:build linux

package localctl

// Linux sockaddr_un.sun_path is 108 bytes including the terminating NUL.
const unixSocketPathLimit = 108
