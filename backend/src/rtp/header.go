package rtp

import (
	"encoding/binary"
	"fmt"
)

type PayloadType byte

const (
	PayloadTypeVP8  PayloadType = 96
	PayloadTypeOpus PayloadType = 109
)

type Header struct {
	Version          byte
	Padding          bool
	Extension        bool
	Marker           bool
	PayloadType      PayloadType
	SequenceNumber   uint16
	Timestamp        uint32
	SSRC             uint32
	CSRC             []uint32
	ExtensionProfile uint16
	Extensions       []Extension

	RawData []byte
}

type Extension struct {
	Id      byte
	Payload []byte
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|V=2|P|X|  CC   |M|     PT      |       Sequence Number         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Timestamp                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Synchronization Source (SSRC) identifier            |
	+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	|            Contributing Source (CSRC) identifiers             |
	|                             ....                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            Payload                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func IsRtpPacket(buf []byte, offset int, arrayLen int) bool {
	// https://csperkins.org/standards/ietf-67/2006-11-07-IETF67-AVT-rtp-rtcp-mux.pdf
	// Initial segment of RTP header; 7 bit payload
	// type; values 0...35 and 96...127 usually used
	payloadType := buf[offset+1] & 0b01111111
	return (payloadType <= 35) || (payloadType >= 96 && payloadType <= 127)
}

func DecodeHeader(buf []byte, offset int, arrayLen int) (*Header, int, error) {
	result := new(Header)
	offsetBackup := offset
	firstByte := buf[offset]
	offset++
	result.Version = firstByte & 0b11000000 >> 6
	result.Padding = (firstByte & 0b00100000 >> 5) == 1
	result.Extension = (firstByte & 0b00010000 >> 4) == 1
	csrcCount := firstByte & 0b00001111

	secondByte := buf[offset]
	offset++
	result.Marker = (secondByte & 0b10000000 >> 7) == 1
	result.PayloadType = PayloadType(secondByte & 0b01111111)

	result.SequenceNumber = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	result.Timestamp = binary.BigEndian.Uint32(buf[offset : offset+4])
	offset += 4
	result.SSRC = binary.BigEndian.Uint32(buf[offset : offset+4])
	offset += 4

	result.CSRC = make([]uint32, csrcCount)
	for i := 0; i < int(csrcCount); i++ {
		result.CSRC[i] = binary.BigEndian.Uint32(buf[offset : offset+4])
		offset += 4
	}
	result.RawData = buf[offsetBackup:offset]
	return result, offset, nil
}

func (pt PayloadType) String() string {
	result := pt.CodecName()
	return fmt.Sprintf("%s (%d)", result, pt)
}

func (pt PayloadType) CodecCodeNumber() string {
	return fmt.Sprintf("%d", int(pt))
}

func (pt PayloadType) CodecName() string {
	var result string
	switch pt {
	case PayloadTypeVP8:
		result = "VP8/90000"
	case PayloadTypeOpus:
		result = "OPUS/48000/2"
	default:
		result = "Unknown"
	}
	return result
}
