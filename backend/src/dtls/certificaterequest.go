package dtls

import (
	"encoding/binary"
	"fmt"
)

type CertificateRequest struct {
	CertificateTypes []CertificateType
	AlgoPairs        []AlgoPair
}

func (m *CertificateRequest) String() string {
	return fmt.Sprintf("[CertificateRequest] CertificateTypes: <u>%s</u>, AlgoPair: <u>%s</u>", m.CertificateTypes, m.AlgoPairs)
}

func (m *CertificateRequest) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *CertificateRequest) GetHandshakeType() HandshakeType {
	return HandshakeTypeCertificateRequest
}

func (m *CertificateRequest) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	certificateTypeCount := buf[offset]
	offset++
	m.CertificateTypes = make([]CertificateType, int(certificateTypeCount))
	for i := 0; i < int(certificateTypeCount); i++ {
		m.CertificateTypes[i] = CertificateType(buf[offset+i])
	}
	offset += int(certificateTypeCount)
	algoPairLength := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	algoPairCount := algoPairLength / 2
	m.AlgoPairs = make([]AlgoPair, algoPairCount)
	for i := 0; i < int(algoPairCount); i++ {
		m.AlgoPairs[i] = AlgoPair{}
		lastOffset, err := m.AlgoPairs[i].Decode(buf, offset, arrayLen)
		if err != nil {
			return offset, err
		}
		offset = lastOffset
	}
	offset += 2 // Distinguished Names Length

	return offset, nil
}

func (m *CertificateRequest) Encode() []byte {
	result := make([]byte, 0)
	result = append(result, byte(len(m.CertificateTypes)))
	encodedCertificateTypes := make([]byte, 0)
	for i := 0; i < len(m.CertificateTypes); i++ {
		encodedCertificateTypes = append(encodedCertificateTypes, byte(m.CertificateTypes[i]))
	}
	result = append(result, encodedCertificateTypes...)

	encodedAlgoPairs := make([]byte, 0)
	for i := 0; i < len(m.AlgoPairs); i++ {
		encodedAlgoPairs = append(encodedAlgoPairs, m.AlgoPairs[i].Encode()...)
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(encodedAlgoPairs)))
	result = append(result, b...)
	result = append(result, encodedAlgoPairs...)
	result = append(result, []byte{0x00, 0x00}...) // Distinguished Names Length

	return result
}
