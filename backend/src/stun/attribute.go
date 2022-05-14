package stun

import (
	"encoding/binary"
	"fmt"
)

const (
	attributeHeaderSize = 4
)

type Attribute struct {
	AttributeType   AttributeType
	Value           []byte
	OffsetInMessage int
}

func (a *Attribute) GetRawDataLength() int {
	return len(a.Value)
}

func (a *Attribute) GetRawFullLength() int {
	return attributeHeaderSize + len(a.Value)
}

func (a Attribute) String() string {
	return fmt.Sprintf("%s: [%s]", a.AttributeType, a.Value)
}

func DecodeAttribute(buf []byte, offset int, arrayLen int) (*Attribute, error) {
	if arrayLen < attributeHeaderSize {
		return nil, errIncompleteTURNFrame
	}
	offsetBackup := offset
	attrType := binary.BigEndian.Uint16(buf[offset : offset+2])

	offset += 2

	attrLength := int(binary.BigEndian.Uint16(buf[offset : offset+2]))

	offset += 2

	result := new(Attribute)

	result.OffsetInMessage = offsetBackup
	result.AttributeType = AttributeType(attrType)

	result.Value = buf[offset : offset+attrLength]

	return result, nil
}

func (a *Attribute) Encode() []byte {
	attrLen := 4 + len(a.Value)
	attrLen += (4 - (attrLen % 4)) % 4
	result := make([]byte, attrLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(a.AttributeType))
	binary.BigEndian.PutUint16(result[2:4], uint16(len(a.Value)))
	copy(result[4:], a.Value)
	return result
}
