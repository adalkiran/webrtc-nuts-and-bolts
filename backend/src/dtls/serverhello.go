package dtls

import (
	"encoding/binary"
	"fmt"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
)

type ServerHello struct {
	Version   DtlsVersion
	Random    Random
	SessionID []byte

	CipherSuiteID       CipherSuiteID
	CompressionMethodID byte
	Extensions          map[ExtensionType]Extension
}

func (m *ServerHello) String() string {
	extensionsStr := make([]string, len(m.Extensions))
	i := 0
	for _, ext := range m.Extensions {
		extensionsStr[i] = ext.String()
		i++
	}
	return common.JoinSlice("\n", false,
		fmt.Sprintf("[ServerHello] Ver: <u>%s</u>, SessionID: <u>%d</u>", m.Version, m.SessionID),
		fmt.Sprintf("Cipher Suite ID: <u>0x%x</u>", m.CipherSuiteID),
		common.ProcessIndent("Extensions:", "+", extensionsStr),
	)
}

func (m *ServerHello) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *ServerHello) GetHandshakeType() HandshakeType {
	return HandshakeTypeServerHello
}

func (m *ServerHello) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	// https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66
	m.Version = DtlsVersion(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2

	decodedRandom, offset, err := DecodeRandom(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	m.Random = *decodedRandom

	sessionIDLength := buf[offset]
	offset++
	m.SessionID = make([]byte, sessionIDLength)
	copy(m.SessionID, buf[offset:offset+int(sessionIDLength)])
	offset += int(sessionIDLength)

	m.CipherSuiteID = CipherSuiteID(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2

	m.CompressionMethodID = buf[offset]
	offset++

	extensionsMap, offset, err := DecodeExtensionMap(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	m.Extensions = extensionsMap
	return offset, nil
}

func (m *ServerHello) Encode() []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result[0:2], uint16(m.Version))
	result = append(result, m.Random.Encode()...)

	result = append(result, byte(len(m.SessionID)))
	result = append(result, m.SessionID...)

	result = append(result, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(result[len(result)-2:], uint16(m.CipherSuiteID))

	result = append(result, m.CompressionMethodID)

	encodedExtensions := EncodeExtensionMap(m.Extensions)
	result = append(result, encodedExtensions...)

	return result
}
