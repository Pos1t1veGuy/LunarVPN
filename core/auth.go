package core

import (
	"strings"
)

type Authenticator interface {
	Authenticate(clientHello *ClientHello) bool
}

type StaticAuth struct {
	Allowed map[string]string // login => password
}

func (st *StaticAuth) Authenticate(clientHello *ClientHello) bool {
	if len(clientHello.AuthData) == 0 {
		return false
	}

	// clientHello.AuthData = "login:password"
	parts := strings.SplitN(string(clientHello.AuthData), ":", 2)
	if len(parts) != 2 {
		return false
	}
	login, password := parts[0], parts[1]
	expected, ok := st.Allowed[login]
	if !ok || expected != password {
		return false
	}
	return true
}
