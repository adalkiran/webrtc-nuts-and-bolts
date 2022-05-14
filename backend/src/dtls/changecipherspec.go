package dtls

import (
	"errors"
)

type ChangeCipherSpec struct {
}

func (m *ChangeCipherSpec) String() string {
	return "[ChangeCipherSpec] Data: 1"
}

func (m *ChangeCipherSpec) GetContentType() ContentType {
	return ContentTypeChangeCipherSpec
}

func (m *ChangeCipherSpec) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	if arrayLen < 1 || buf[offset] != 1 {
		offset++
		return offset, errors.New("invalid cipher spec")
	}
	offset++
	return offset, nil
}

func (m *ChangeCipherSpec) Encode() []byte {
	result := []byte{0x01}
	return result
}
