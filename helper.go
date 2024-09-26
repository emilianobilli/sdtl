package sdtl

import (
	"crypto/rand"
)

func createRandomSession() [8]byte {
	var session [8]byte
	rand.Read(session[:])
	return session
}
