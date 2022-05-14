package dtls

import "fmt"

type AlgoPair struct {
	HashAlgorithm      HashAlgorithm
	SignatureAlgorithm SignatureAlgorithm
}

func (m AlgoPair) String() string {
	return fmt.Sprintf("{HashAlg: %s Signature Alg: %s}", m.HashAlgorithm, m.SignatureAlgorithm)
}

func (m *AlgoPair) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.HashAlgorithm = HashAlgorithm(buf[offset])
	offset += 1
	m.SignatureAlgorithm = SignatureAlgorithm(buf[offset])
	offset += 1
	return offset, nil
}

func (m *AlgoPair) Encode() []byte {
	result := []byte{
		byte(m.HashAlgorithm),
		byte(m.SignatureAlgorithm),
	}
	return result
}
