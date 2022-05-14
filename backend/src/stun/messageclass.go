package stun

import "fmt"

type MessageClass byte

type messageClassDef struct {
	Name string
}

const (
	MessageClassRequest         MessageClass = 0x00
	MessageClassIndication      MessageClass = 0x01
	MessageClassSuccessResponse MessageClass = 0x02
	MessageClassErrorResponse   MessageClass = 0x03
)

var messageClassMap = map[MessageClass]messageClassDef{
	MessageClassRequest:         {"request"},
	MessageClassIndication:      {"indication"},
	MessageClassSuccessResponse: {"success response"},
	MessageClassErrorResponse:   {"error response"},
}

func (mc MessageClass) String() string {
	messageClassDef, ok := messageClassMap[mc]
	if !ok {
		// Just return hex representation of unknown class.
		return fmt.Sprintf("0x%x", uint16(mc))
	}
	return messageClassDef.Name
}
