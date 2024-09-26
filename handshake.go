package sdtl

import (
	"crypto/ecdsa"
	"fmt"
)

const (
	ProtocolVer = 0xDF

	StartHandShakeMsg  = 0x01
	ServerHandShakeMsg = 0x02
	ClientHandShakeMsg = 0x03

	HandShakeSize           = 8 + 64 + 64
	HandShakeEPKOffset      = 8
	HandShakeSigOffset      = 72
	StartHandShakeSize      = 72
	StartHandShakeSigOffset = 8
)

type HandShakeInterface interface {
	dump(*ecdsa.PrivateKey) ([]byte, error)
	load(*ecdsa.PublicKey, []byte) error
	size() int
}

type StartHandShake struct {
	session   [8]byte
	signature [64]byte
}

type HandShake struct {
	session   [8]byte
	epk       [64]byte
	signature [64]byte
}

func (hs *StartHandShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, StartHandShakeSize)
	copy(buf, hs.session[:])
	hs.signature, e = signMessage(pk, buf[0:StartHandShakeSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing start handshake %w", e)
	}
	copy(buf[StartHandShakeSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *StartHandShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < HandShakeSize {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.session[:], data[:StartHandShakeSigOffset])
	copy(hs.signature[:], data[StartHandShakeSigOffset:StartHandShakeSize])
	valid := verifySignature(pk, data[0:HandShakeSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *StartHandShake) size() int {
	return StartHandShakeSize
}

func (hs *HandShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, HandShakeSize)
	copy(buf, hs.session[:])
	copy(buf[HandShakeEPKOffset:], hs.epk[:])
	hs.signature, e = signMessage(pk, buf[0:HandShakeSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing handshake %w", e)
	}
	copy(buf[HandShakeSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *HandShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < HandShakeSize {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.session[:], data[:HandShakeEPKOffset])
	copy(hs.epk[:], data[HandShakeEPKOffset:HandShakeSigOffset])
	copy(hs.signature[:], data[HandShakeSigOffset:HandShakeSize])
	valid := verifySignature(pk, data[0:HandShakeSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *HandShake) size() int {
	return HandShakeSize
}
