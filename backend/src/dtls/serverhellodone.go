package dtls

type ServerHelloDone struct {
}

func (m *ServerHelloDone) String() string {
	return "[ServerHelloDone]"
}

func (m *ServerHelloDone) GetContentType() ContentType {
	return ContentTypeHandshake
}

func (m *ServerHelloDone) GetHandshakeType() HandshakeType {
	return HandshakeTypeServerHelloDone
}

func (m *ServerHelloDone) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	return offset, nil
}

func (m *ServerHelloDone) Encode() []byte {
	result := make([]byte, 0)
	return result
}
