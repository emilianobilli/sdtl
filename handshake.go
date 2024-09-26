package sdtl

import (
	"crypto/ecdsa"
	"fmt"
)

const (
	ProtocolVer = 0xDF

	startHandShakeMsg  = 0x01
	serverHandShakeMsg = 0x02
	clientHandShakeMsg = 0x03

	handShakeSize           = 8 + 65 + 64
	handShakeEPKOffset      = 8
	handShakeSigOffset      = 73
	startHandShakeSize      = 73
	startHandShakeSigOffset = 8
)

type handShakeInterface interface {
	dump(*ecdsa.PrivateKey) ([]byte, error)
	load(*ecdsa.PublicKey, []byte) error
	size() int
}

type startHandShake struct {
	session   [8]byte
	signature [64]byte
}

type handShake struct {
	session   [8]byte
	epk       [65]byte
	signature [64]byte
}

func (hs *startHandShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, startHandShakeSize)
	copy(buf, hs.session[:])
	hs.signature, e = signMessage(pk, buf[0:startHandShakeSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing start handshake %w", e)
	}
	copy(buf[startHandShakeSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *startHandShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < startHandShakeSize {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.session[:], data[:startHandShakeSigOffset])
	copy(hs.signature[:], data[startHandShakeSigOffset:startHandShakeSize])
	valid := verifySignature(pk, data[0:startHandShakeSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *startHandShake) size() int {
	return startHandShakeSize
}

func (hs *handShake) dump(pk *ecdsa.PrivateKey) ([]byte, error) {
	var e error
	buf := make([]byte, handShakeSize)
	copy(buf, hs.session[:])
	copy(buf[handShakeEPKOffset:], hs.epk[:])
	hs.signature, e = signMessage(pk, buf[0:handShakeSigOffset])
	if e != nil {
		return nil, fmt.Errorf("at signing handshake %w", e)
	}
	copy(buf[handShakeSigOffset:], hs.signature[:])
	return buf, nil
}

func (hs *handShake) load(pk *ecdsa.PublicKey, data []byte) error {

	if len(data) < handShakeSize {
		return fmt.Errorf("invalid data size")
	}
	copy(hs.session[:], data[:handShakeEPKOffset])
	copy(hs.epk[:], data[handShakeEPKOffset:handShakeSigOffset])
	copy(hs.signature[:], data[handShakeSigOffset:handShakeSize])
	valid := verifySignature(pk, data[0:handShakeSigOffset], hs.signature)
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (hs *handShake) size() int {
	return handShakeSize
}
