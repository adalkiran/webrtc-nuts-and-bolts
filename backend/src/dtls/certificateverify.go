package dtls

import (
	"encoding/binary"
	"fmt"
)

type CertificateVerify struct {
	AlgoPair  AlgoPair
	Signature []byte
}

func (m *CertificateVerify) String() string {
	return fmt.Sprintf("[CertificateVerify] AlgoPair: <u>%s</u>, Signature: <u>0x%x</u>", m.AlgoPair, m.Signature)
}

func (m *CertificateVerify) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *CertificateVerify) GetHandshakeType() HandshakeType {
	return HandshakeTypeCertificateVerify
}

func (m *CertificateVerify) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.AlgoPair = AlgoPair{}
	offset, err := m.AlgoPair.Decode(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	signatureLength := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	m.Signature = make([]byte, signatureLength)
	copy(m.Signature, buf[offset:offset+int(signatureLength)])
	offset += int(signatureLength)
	return offset, nil
}

func (m *CertificateVerify) Encode() []byte {
	result := make([]byte, 0)
	result = append(result, m.AlgoPair.Encode()...)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(m.Signature)))
	result = append(result, b...)
	result = append(result, m.Signature...)
	return result
}
