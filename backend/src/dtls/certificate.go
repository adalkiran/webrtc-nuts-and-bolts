package dtls

import "fmt"

type Certificate struct {
	Certificates [][]byte
}

func (m *Certificate) String() string {
	return fmt.Sprintf("[Certificate] Certificates: <u>%d bytes</u>", len(m.Certificates[0]))
}

func (m *Certificate) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *Certificate) GetHandshakeType() HandshakeType {
	return HandshakeTypeCertificate
}

func (m *Certificate) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.Certificates = make([][]byte, 0)
	length := NewUint24FromBytes(buf[offset : offset+3])
	lengthInt := int(length.ToUint32())
	offset += 3
	offsetBackup := offset
	for offset < offsetBackup+int(lengthInt) {
		certificateLength := NewUint24FromBytes(buf[offset : offset+3])
		certificateLengthInt := int(certificateLength.ToUint32())
		offset += 3

		certificateBytes := make([]byte, certificateLengthInt)
		copy(certificateBytes, buf[offset:offset+certificateLengthInt])
		offset += certificateLengthInt
		m.Certificates = append(m.Certificates, certificateBytes)
	}
	return offset, nil
}

func (m *Certificate) Encode() []byte {
	encodedCertificates := make([]byte, 0)
	for _, certificate := range m.Certificates {
		certificateLength := NewUint24FromUInt32(uint32(len(certificate)))
		encodedCertificates = append(encodedCertificates, certificateLength[:]...)
		encodedCertificates = append(encodedCertificates, certificate...)
	}
	length := NewUint24FromUInt32(uint32(len(encodedCertificates)))
	result := append(length[:], encodedCertificates...)
	return result
}
