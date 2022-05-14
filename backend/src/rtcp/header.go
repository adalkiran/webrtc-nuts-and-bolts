package rtcp

import (
	"encoding/binary"
	"fmt"
)

type PacketType byte

const (
	// https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
	PayloadTypeFIR                PacketType = 192
	PayloadTypeNACK               PacketType = 193
	PayloadTypeSenderReport       PacketType = 200
	PayloadTypeReceiverReport     PacketType = 201
	PayloadTypeSourceDescription  PacketType = 202
	PayloadTypeGoodbye            PacketType = 203
	PayloadTypeApplicationDefined PacketType = 204
	PayloadTypeGenericRTPFeedback PacketType = 205
	PayloadTypePayloadSpecific    PacketType = 206
	PayloadTypeExtendedReport     PacketType = 207
	PayloadTypeAVBRTCPPacket      PacketType = 208
)

type Header struct {
	Version              byte
	Padding              bool
	ReceptionReportCount byte
	PacketType           PacketType
	Length               uint16
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|V=2|P|    RC   |       PT      |             length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            Payload                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func IsRtcpPacket(buf []byte, offset int, arrayLen int) bool {
	// https://csperkins.org/standards/ietf-67/2006-11-07-IETF67-AVT-rtp-rtcp-mux.pdf
	// Initial segment of RTCP header; 8 bit packet
	// type; values 192, 193, 200...208 used
	payloadType := buf[offset+1]
	return (payloadType >= 192 && payloadType <= 193) || (payloadType >= 200 && payloadType <= 208)
}

func DecodeHeader(buf []byte, offset int, arrayLen int) (*Header, int, error) {
	result := new(Header)
	firstByte := buf[offset]
	offset++
	result.Version = firstByte & 0b11000000 >> 6
	result.Padding = (firstByte & 0b00100000 >> 5) == 1
	result.ReceptionReportCount = firstByte & 0b00011111

	result.PacketType = PacketType(buf[offset])
	offset++

	result.Length = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2

	return result, offset, nil
}

func (pt PacketType) String() string {
	var result string
	switch pt {
	case PayloadTypeFIR:
		result = "FIR"
	case PayloadTypeNACK:
		result = "NACK"
	case PayloadTypeSenderReport:
		result = "SenderReport"
	case PayloadTypeReceiverReport:
		result = "ReceiverReport"
	case PayloadTypeSourceDescription:
		result = "SourceDescription"
	case PayloadTypeGoodbye:
		result = "Goodbye"
	case PayloadTypeApplicationDefined:
		result = "ApplicationDefined"
	case PayloadTypeGenericRTPFeedback:
		result = "GenericRTPFeedback"
	case PayloadTypePayloadSpecific:
		result = "PayloadSpecific"
	case PayloadTypeExtendedReport:
		result = "ExtendedReport"
	case PayloadTypeAVBRTCPPacket:
		result = "AVBRTCPPacket"
	default:
		result = "Unknown"
	}
	return fmt.Sprintf("%s (%d)", result, pt)
}
