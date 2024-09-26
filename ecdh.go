package sdtl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

type Cipher struct {
	curve  ecdh.Curve
	pk     *ecdh.PrivateKey
	shared []byte
}

type AESCrypted struct {
	ciphertext []byte
	nonce      []byte
	tagOffset  int
}

func NewCipher() (*Cipher, error) {
	var (
		c Cipher
		e error
	)
	c.curve = ecdh.P256()
	c.pk, e = c.curve.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	return &c, nil
}

func (c *Cipher) PublicKey() []byte {
	return c.pk.PublicKey().Bytes()
}

func (c *Cipher) SharedSecret(remote []byte) error {
	pb, e := c.curve.NewPublicKey(remote)
	if e != nil {
		return e
	}
	c.shared, e = c.pk.ECDH(pb)
	if e != nil {
		return e
	}
	return nil
}

func (c *Cipher) Encrypt(data []byte) (AESCrypted, error) {
	block, err := aes.NewCipher(c.shared)
	if err != nil {
		return AESCrypted{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return AESCrypted{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return AESCrypted{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return AESCrypted{
		ciphertext: ciphertext,
		nonce:      nonce,
		tagOffset:  len(ciphertext) - gcm.Overhead(),
	}, nil
}

func (c *Cipher) Decrypt(ctext AESCrypted) ([]byte, error) {
	block, err := aes.NewCipher(c.shared)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ctext.nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	plaintext, err := gcm.Open(nil, ctext.nonce, ctext.ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
