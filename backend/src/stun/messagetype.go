package stun

import "fmt"

type MessageType struct {
	MessageMethod MessageMethod
	MessageClass  MessageClass
}

func (mt MessageType) String() string {
	return fmt.Sprintf("%s %s", mt.MessageMethod, mt.MessageClass)
}

const (
	methodABits = 0xf   // 0b0000000000001111
	methodBBits = 0x70  // 0b0000000001110000
	methodDBits = 0xf80 // 0b0000111110000000

	methodBShift = 1
	methodDShift = 2

	firstBit  = 0x1
	secondBit = 0x2

	c0Bit = firstBit
	c1Bit = secondBit

	classC0Shift = 4
	classC1Shift = 7
)

func decodeMessageType(mt uint16) MessageType {
	// Decoding class.
	// We are taking first bit from v >> 4 and second from v >> 7.
	c0 := (mt >> classC0Shift) & c0Bit
	c1 := (mt >> classC1Shift) & c1Bit
	class := c0 + c1

	// Decoding method.
	a := mt & methodABits                   // A(M0-M3)
	b := (mt >> methodBShift) & methodBBits // B(M4-M6)
	d := (mt >> methodDShift) & methodDBits // D(M7-M11)
	m := a + b + d

	return MessageType{
		MessageClass:  MessageClass(class),
		MessageMethod: MessageMethod(m),
	}
}

func (mt *MessageType) Encode() uint16 {
	m := uint16(mt.MessageMethod)
	a := m & methodABits // A = M * 0b0000000000001111 (right 4 bits)
	b := m & methodBBits // B = M * 0b0000000001110000 (3 bits after A)
	d := m & methodDBits // D = M * 0b0000111110000000 (5 bits after B)

	// Shifting to add "holes" for C0 (at 4 bit) and C1 (8 bit).
	m = a + (b << methodBShift) + (d << methodDShift)

	// C0 is zero bit of C, C1 is first bit.
	// C0 = C * 0b01, C1 = (C * 0b10) >> 1
	// Ct = C0 << 4 + C1 << 8.
	// Optimizations: "((C * 0b10) >> 1) << 8" as "(C * 0b10) << 7"
	// We need C0 shifted by 4, and C1 by 8 to fit "11" and "7" positions
	// (see figure 3).
	c := uint16(mt.MessageClass)
	c0 := (c & c0Bit) << classC0Shift
	c1 := (c & c1Bit) << classC1Shift
	class := c0 + c1

	return m + class
}

var (
	MessageTypeBindingRequest = MessageType{
		MessageMethod: MessageMethodStunBinding,
		MessageClass:  MessageClassRequest,
	}
	MessageTypeBindingSuccessResponse = MessageType{
		MessageMethod: MessageMethodStunBinding,
		MessageClass:  MessageClassSuccessResponse,
	}
	MessageTypeBindingErrorResponse = MessageType{
		MessageMethod: MessageMethodStunBinding,
		MessageClass:  MessageClassErrorResponse,
	}
	MessageTypeBindingIndication = MessageType{
		MessageMethod: MessageMethodStunBinding,
		MessageClass:  MessageClassIndication,
	}
)
