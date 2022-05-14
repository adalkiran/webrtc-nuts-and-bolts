package dtls

import (
	"encoding/binary"
	"fmt"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
)

type ClientHello struct {
	Version              DtlsVersion
	Random               Random
	Cookie               []byte
	SessionID            []byte
	CipherSuiteIDs       []CipherSuiteID
	CompressionMethodIDs []byte
	Extensions           map[ExtensionType]Extension
}

func (m *ClientHello) String() string {
	extensionsStr := make([]string, len(m.Extensions))
	i := 0
	for _, ext := range m.Extensions {
		extensionsStr[i] = ext.String()
		i++
	}
	cipherSuiteIDsStr := make([]string, len(m.CipherSuiteIDs))
	for i, cs := range m.CipherSuiteIDs {
		cipherSuiteIDsStr[i] = cs.String()
	}
	cookieStr := fmt.Sprintf("%x", m.Cookie)
	if len(cookieStr) == 0 {
		cookieStr = "<nil>"
	} else {
		cookieStr = "0x" + cookieStr
	}

	return common.JoinSlice("\n", false,
		fmt.Sprintf("[ClientHello] Ver: <u>%s</u>, Cookie: <u>%s</u>, SessionID: <u>%d</u>", m.Version, cookieStr, m.SessionID),
		common.ProcessIndent("Cipher Suite IDs:", "+", cipherSuiteIDsStr),
		common.ProcessIndent("Extensions:", "+", extensionsStr),
	)
}

func (m *ClientHello) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *ClientHello) GetHandshakeType() HandshakeType {
	return HandshakeTypeClientHello
}

func (m *ClientHello) Encode() []byte {
	return []byte{}
}

func (m *ClientHello) Decode(buf []byte, offset int, arrayLen int) (int, error) {
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

	cookieLength := buf[offset]
	offset++
	m.Cookie = make([]byte, cookieLength)
	copy(m.Cookie, buf[offset:offset+int(cookieLength)])
	offset += int(cookieLength)

	cipherSuiteIDs, offset, err := decodeCipherSuiteIDs(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	m.CipherSuiteIDs = cipherSuiteIDs

	compressionMethodIDs, offset, err := decodeCompressionMethodIDs(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	m.CompressionMethodIDs = compressionMethodIDs

	exts, offset, err := DecodeExtensionMap(buf, offset, arrayLen)
	if err != nil {
		return offset, err
	}
	m.Extensions = exts

	return offset, nil
}

func decodeCipherSuiteIDs(buf []byte, offset int, arrayLen int) ([]CipherSuiteID, int, error) {
	length := binary.BigEndian.Uint16(buf[offset : offset+2])
	count := length / 2
	offset += 2
	result := make([]CipherSuiteID, count)
	for i := 0; i < int(count); i++ {
		result[i] = CipherSuiteID(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	}
	return result, offset, nil
}

func decodeCompressionMethodIDs(buf []byte, offset int, arrayLen int) ([]byte, int, error) {
	count := buf[offset]
	offset += 1
	result := make([]byte, count)
	for i := 0; i < int(count); i++ {
		result[i] = buf[offset]
		offset += 1
	}
	return result, offset, nil
}
