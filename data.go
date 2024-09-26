package sdtl

import "fmt"

const (
	dataFrameMsg              = 0xaa
	dataFrameTagSize          = 16
	dataFrameNonceSize        = 12
	dataFrameNonceOffset      = 0
	dataFrameTagOffset        = 12
	dataFrameCipherTextOffset = 12 + 16
)

func loadDataFrame(c *aesCipher, buffer []byte) ([]byte, error) {
	if len(buffer) < dataFrameCipherTextOffset {
		return nil, fmt.Errorf("buffer too small")
	}

	nonce := buffer[:dataFrameTagOffset]
	tag := buffer[dataFrameTagOffset:dataFrameCipherTextOffset]
	ciphertext := append(buffer[dataFrameCipherTextOffset:], tag...)

	return c.Decrypt(
		aesCrypted{
			ciphertext: ciphertext,                         // Texto cifrado + tag
			nonce:      nonce,                              // Nonce
			tagOffset:  len(ciphertext) - dataFrameTagSize, // Tag está al final del ciphertext
		},
	)
}

func dumpDataFrame(c *aesCipher, buffer []byte) ([]byte, error) {
	a, e := c.Encrypt(buffer)
	if e != nil {
		return nil, e
	}
	data := make([]byte, len(a.ciphertext)+dataFrameNonceSize)
	copy(data[0:dataFrameNonceSize], a.nonce)
	copy(data[dataFrameTagOffset:dataFrameTagOffset+dataFrameTagSize], a.ciphertext[a.tagOffset:])
	copy(data[dataFrameCipherTextOffset:], a.ciphertext[:a.tagOffset])
	return data, nil
}
