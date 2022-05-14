package dtls

import "fmt"

type Finished struct {
	VerifyData []byte
}

func (m *Finished) String() string {
	return fmt.Sprintf("[Finished] VerifyData: <u>0x%x</u> (<u>%d bytes</u>)", m.VerifyData, len(m.VerifyData))
}

func (m *Finished) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *Finished) GetHandshakeType() HandshakeType {
	return HandshakeTypeFinished
}

func (m *Finished) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.VerifyData = make([]byte, arrayLen)
	copy(m.VerifyData, buf[offset:offset+arrayLen])
	offset += len(m.VerifyData)
	return offset, nil
}

func (m *Finished) Encode() []byte {
	result := make([]byte, len(m.VerifyData))
	copy(result, m.VerifyData)
	return result
}
