package sdtl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

type aesCipher struct {
	curve  ecdh.Curve
	pk     *ecdh.PrivateKey
	shared []byte
}

type aesCrypted struct {
	ciphertext []byte
	nonce      []byte
	tagOffset  int
}

func newCipher() (*aesCipher, error) {
	var (
		c aesCipher
		e error
	)
	c.curve = ecdh.P256()
	c.pk, e = c.curve.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	return &c, nil
}

func (c *aesCipher) PublicKey() []byte {
	return c.pk.PublicKey().Bytes()
}

func (c *aesCipher) SharedSecret(remote []byte) error {
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

func (c *aesCipher) Encrypt(data []byte) (aesCrypted, error) {
	block, err := aes.NewCipher(c.shared)
	if err != nil {
		return aesCrypted{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return aesCrypted{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return aesCrypted{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return aesCrypted{
		ciphertext: ciphertext,
		nonce:      nonce,
		tagOffset:  len(ciphertext) - gcm.Overhead(),
	}, nil
}

func (c *aesCipher) Decrypt(ctext aesCrypted) ([]byte, error) {
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
