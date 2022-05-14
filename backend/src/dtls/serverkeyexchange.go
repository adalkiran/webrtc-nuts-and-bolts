package dtls

import (
	"encoding/binary"
	"fmt"
)

type ServerKeyExchange struct {
	EllipticCurveType CurveType
	NamedCurve        Curve
	PublicKey         []byte
	AlgoPair          AlgoPair
	Signature         []byte
}

func (m *ServerKeyExchange) String() string {
	return fmt.Sprintf("[ServerKeyExchange] EllipticCurveType: <u>%s</u>, NamedCurve: <u>%s</u>, AlgoPair: <u>%s</u>, PublicKey: <u>0x%x</u>", m.EllipticCurveType, m.NamedCurve, m.AlgoPair, m.PublicKey)
}

func (m *ServerKeyExchange) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *ServerKeyExchange) GetHandshakeType() HandshakeType {
	return HandshakeTypeServerKeyExchange
}

func (m *ServerKeyExchange) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.EllipticCurveType = CurveType(buf[offset])
	offset++
	m.NamedCurve = Curve(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	publicKeyLength := buf[offset]
	offset++
	m.PublicKey = make([]byte, publicKeyLength)
	copy(m.PublicKey, buf[offset:offset+int(publicKeyLength)])
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

func (m *ServerKeyExchange) Encode() []byte {
	result := make([]byte, 4)
	result[0] = byte(m.EllipticCurveType)
	binary.BigEndian.PutUint16(result[1:], uint16(m.NamedCurve))
	result[3] = byte(len(m.PublicKey))
	result = append(result, m.PublicKey...)
	result = append(result, m.AlgoPair.Encode()...)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(m.Signature)))
	result = append(result, b...)
	result = append(result, m.Signature...)
	return result
}
