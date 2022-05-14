package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	gcmTagLength   = 16
	gcmNonceLength = 12
	headerSize     = 13
)

type GCM struct {
	localGCM, remoteGCM         cipher.AEAD
	localWriteIV, remoteWriteIV []byte
}

// NewGCM creates a DTLS GCM Cipher
func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*GCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localGCM, err := cipher.NewGCM(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteGCM, err := cipher.NewGCM(remoteBlock)
	if err != nil {
		return nil, err
	}

	return &GCM{
		localGCM:      localGCM,
		localWriteIV:  localWriteIV,
		remoteGCM:     remoteGCM,
		remoteWriteIV: remoteWriteIV,
	}, nil
}

// Encrypts a DTLS RecordLayer message
func (g *GCM) Encrypt(header *RecordHeader, raw []byte) ([]byte, error) {
	nonce := make([]byte, gcmNonceLength)
	copy(nonce, g.localWriteIV[:4])
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
	}

	additionalData := generateAEADAdditionalData(header, len(raw))
	encryptedPayload := g.localGCM.Seal(nil, nonce, raw, additionalData)
	r := make([]byte, len(nonce[4:])+len(encryptedPayload))
	copy(r, nonce[4:])
	copy(r[len(nonce[4:]):], encryptedPayload)
	return r, nil
}

// Decrypts a DTLS RecordLayer message
func (g *GCM) Decrypt(h *RecordHeader, in []byte) ([]byte, error) {
	switch {
	case h.ContentType == ContentTypeChangeCipherSpec:
		// Nothing to encrypt with ChangeCipherSpec
		return in, nil
	}

	nonce := make([]byte, 0, gcmNonceLength)
	nonce = append(append(nonce, g.remoteWriteIV[:4]...), in[0:8]...)
	out := in[8:]

	additionalData := generateAEADAdditionalData(h, len(out)-gcmTagLength)
	var err error
	out, err = g.remoteGCM.Open(out[:0], nonce, out, additionalData)
	if err != nil {
		return nil, fmt.Errorf("error on decrypting packet: %v", err)
	}
	return out, nil
}
