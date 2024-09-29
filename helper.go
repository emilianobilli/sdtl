package sdtl

import (
	"crypto/rand"
	"net"
)

func packIPinSession(ip string) [8]byte {
	var ses [8]byte
	i := net.ParseIP(ip)
	copy(ses[0:], i.To4()) // Copiamos los primeros 4 bytes de la IP
	rand.Read(ses[4:])     // Los últimos 4 bytes son generados aleatoriamente
	return ses
}

func unpackIPfromSession(session [8]byte) net.IP {
	// Extraemos los primeros 4 bytes como dirección IP
	ip := net.IPv4(session[0], session[1], session[2], session[3])
	return ip
}
