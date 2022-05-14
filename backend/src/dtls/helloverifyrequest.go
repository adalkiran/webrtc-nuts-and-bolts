package dtls

import (
	"encoding/binary"
	"fmt"
)

type HelloVerifyRequest struct {
	Version DtlsVersion
	Cookie  []byte
}

func (m *HelloVerifyRequest) String() string {
	cookieStr := fmt.Sprintf("%x", m.Cookie)
	if len(cookieStr) == 0 {
		cookieStr = "<nil>"
	} else {
		cookieStr = "0x" + cookieStr
	}
	return fmt.Sprintf("[HelloVerifyRequest] Ver: <u>%s</u>, Cookie: <u>%s</u>", m.Version, cookieStr)
}

func (m *HelloVerifyRequest) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *HelloVerifyRequest) GetHandshakeType() HandshakeType {
	return HandshakeTypeHelloVerifyRequest
}

func (m *HelloVerifyRequest) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	// https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66
	m.Version = DtlsVersion(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2

	cookieLength := buf[offset]
	offset++
	m.Cookie = make([]byte, cookieLength)
	copy(m.Cookie, buf[offset:offset+int(cookieLength)])
	offset += int(cookieLength)

	return offset, nil
}

func (m *HelloVerifyRequest) Encode() []byte {
	result := make([]byte, 3)
	binary.BigEndian.PutUint16(result[0:2], uint16(m.Version))
	result[2] = byte(len(m.Cookie))
	result = append(result, m.Cookie...)

	return result
}
