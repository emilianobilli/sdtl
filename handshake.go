package sdtl

import (
	"crypto/ecdsa"
	"fmt"
	"net"
)

const (
	ProtocolVer = 0xDF

	msgSTR = 0x01
	msgSHS = 0x02
	msgCHS = 0x03
	msgDFE = 0xaa

	sizeXHS      = 8 + 65 + 64
	xhsEPKOffset = 8
	xhsSigOffset = 73
	sizeSTR      = 76
	strSesOffset = 4
	strSigOffset = 12
)

type handShakeInterface interface {
	dump(*ecdsa.PrivateKey) ([]byte, error)
	load(*ecdsa.PublicKey, []byte) error
	size() int
}

type startHandShake struct {
	ip        [4]byte
	session   [8]byte
	signature [64]byte
}

type handShake struct {
	session   [8]byte
	epk       [65]byte
	signature [64]byte
}

func extractIP(buf []byte) net.IP {
	return net.IPv4(buf[0], buf[1], buf[2], buf[3])
}

func (hs *startHandShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, sizeSTR)

	copy(buf[0:strSesOffset], hs.ip[:])
	copy(buf[strSesOffset:strSigOffset], hs.session[:])
	hs.signature, e = signMessage(pk, buf[0:strSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing start handshake %w", e)
	}
	copy(buf[strSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *startHandShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < sizeSTR {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.ip[:], data[:strSesOffset])
	copy(hs.session[:], data[strSesOffset:strSigOffset])
	copy(hs.signature[:], data[strSigOffset:sizeSTR])
	valid := verifySignature(pk, data[0:strSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *startHandShake) size() int {
	return sizeSTR
}

func (hs *handShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, sizeXHS)
	copy(buf, hs.session[:])
	copy(buf[xhsEPKOffset:], hs.epk[:])
	hs.signature, e = signMessage(pk, buf[0:xhsSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing handshake %w", e)
	}
	copy(buf[xhsSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *handShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < sizeXHS {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.session[:], data[:xhsEPKOffset])
	copy(hs.epk[:], data[xhsEPKOffset:xhsSigOffset])
	copy(hs.signature[:], data[xhsSigOffset:sizeXHS])
	valid := verifySignature(pk, data[0:xhsSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *handShake) size() int {
	return sizeXHS
}
