//go:build darwin

package localctl

// Darwin sockaddr_un.sun_path is 104 bytes including the terminating NUL.
const unixSocketPathLimit = 104
