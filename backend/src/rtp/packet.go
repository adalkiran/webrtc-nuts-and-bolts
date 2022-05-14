package rtp

import "fmt"

type Packet struct {
	Header     *Header
	HeaderSize int
	Payload    []byte
	RawData    []byte
}

func DecodePacket(buf []byte, offset int, arrayLen int) (*Packet, int, error) {
	result := new(Packet)
	result.RawData = append([]byte{}, buf[offset:offset+arrayLen]...)
	var err error
	offsetBackup := offset
	result.Header, offset, err = DecodeHeader(buf, offset, arrayLen)
	if err != nil {
		return nil, offset, err
	}
	result.HeaderSize = offset - offsetBackup
	lastPosition := arrayLen - 1
	if result.Header.Padding {
		paddingSize := buf[arrayLen-1]
		lastPosition = arrayLen - 1 - int(paddingSize)
	}
	result.Payload = buf[offset:lastPosition]
	return result, offset, nil
}

func (p *Packet) String() string {
	return fmt.Sprintf("RTP Version: %d, SSRC: %d, Payload Type: %s, Seq Number: %d, CSRC Count: %d, Payload Length: %d Marker: %v",
		p.Header.Version, p.Header.SSRC, p.Header.PayloadType, p.Header.SequenceNumber, len(p.Header.CSRC), len(p.Payload), p.Header.Marker)
}
