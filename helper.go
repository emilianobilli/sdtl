package sdtl

import (
	"crypto/rand"
)

func createRandomSession() [8]byte {
	var session [8]byte
	rand.Read(session[:]) // Llenamos el array de 8 bytes con valores aleatorios
	return session
}
