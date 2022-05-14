package dtls

import (
	"encoding/binary"
	"fmt"
)

type ContentType uint8

type DtlsVersion uint16

const (
	SequenceNumberSize = 6 // 48 bit

	// https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L314
	ContentTypeChangeCipherSpec ContentType = 20
	ContentTypeAlert            ContentType = 21
	ContentTypeHandshake        ContentType = 22
	ContentTypeApplicationData  ContentType = 23

	DtlsVersion1_0 DtlsVersion = 0xfeff
	DtlsVersion1_2 DtlsVersion = 0xfefd
)

type RecordHeader struct {
	//https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L320
	ContentType    ContentType
	Version        DtlsVersion
	Epoch          uint16
	SequenceNumber [SequenceNumberSize]byte
	Length         uint16
}

func (t ContentType) String() string {
	var result string
	switch t {
	case ContentTypeChangeCipherSpec:
		result = "ChangeCipherSpec"
	case ContentTypeAlert:
		result = "Alert"
	case ContentTypeHandshake:
		result = "Handshake"
	case ContentTypeApplicationData:
		result = "ApplicationData"

	default:
		result = "Unknown Content Type"
	}
	return fmt.Sprintf("%s (%d)", result, uint8(t))
}

func (v DtlsVersion) String() string {
	var result string
	switch v {
	case DtlsVersion1_0:
		result = "1.0"
	case DtlsVersion1_2:
		result = "1.2"
	default:
		result = "Unknown Version"
	}
	return fmt.Sprintf("%s (0x%x)", result, uint16(v))
}

func (h *RecordHeader) String() string {
	seqNum := binary.BigEndian.Uint64(append([]byte{0, 0}, h.SequenceNumber[:]...))
	return fmt.Sprintf("[Record Header] Content Type: <u>%s</u>, Ver: <u>%s</u>, Epoch: <u>%d</u>, SeqNum: <u>%d</u>", h.ContentType, h.Version, h.Epoch, seqNum)
}

func (h *RecordHeader) Encode() []byte {
	result := make([]byte, 7+SequenceNumberSize)
	result[0] = byte(h.ContentType)
	binary.BigEndian.PutUint16(result[1:], uint16(h.Version))
	binary.BigEndian.PutUint16(result[3:], uint16(h.Epoch))
	copy(result[5:], h.SequenceNumber[:])
	binary.BigEndian.PutUint16(result[5+SequenceNumberSize:], uint16(h.Length))
	return result
}

func DecodeRecordHeader(buf []byte, offset int, arrayLen int) (*RecordHeader, int, error) {
	result := new(RecordHeader)

	result.ContentType = ContentType(buf[offset])
	offset++
	result.Version = DtlsVersion(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	result.Epoch = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	copy(result.SequenceNumber[:], buf[offset:offset+SequenceNumberSize])
	offset += SequenceNumberSize
	result.Length = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	return result, offset, nil
}
