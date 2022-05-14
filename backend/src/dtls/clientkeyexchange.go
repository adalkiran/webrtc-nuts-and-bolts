package dtls

import "fmt"

type ClientKeyExchange struct {
	PublicKey []byte
}

func (m *ClientKeyExchange) String() string {
	return fmt.Sprintf("[ClientKeyExchange] PublicKey: <u>0x%x</u>", m.PublicKey)
}

func (m *ClientKeyExchange) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *ClientKeyExchange) GetHandshakeType() HandshakeType {
	return HandshakeTypeClientKeyExchange
}

func (m *ClientKeyExchange) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	publicKeyLength := buf[offset]
	offset++
	m.PublicKey = make([]byte, publicKeyLength)
	copy(m.PublicKey, buf[offset:offset+int(publicKeyLength)])
	offset += int(publicKeyLength)
	return offset, nil
}

func (m *ClientKeyExchange) Encode() []byte {
	result := make([]byte, 1)
	result[0] = byte(len(m.PublicKey))
	result = append(result, m.PublicKey...)
	return result
}
