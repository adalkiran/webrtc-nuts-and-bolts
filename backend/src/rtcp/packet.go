package rtcp

import "fmt"

type Packet struct {
	Header  *Header
	Payload []byte
}

func DecodePacket(buf []byte, offset int, arrayLen int) (*Packet, int, error) {
	result := new(Packet)
	var err error
	result.Header, offset, err = DecodeHeader(buf, offset, arrayLen)
	if err != nil {
		return nil, offset, err
	}
	// Passed decoding payload
	offset += int(result.Header.Length)
	return result, offset, nil
}

func (p *Packet) String() string {
	return fmt.Sprintf("Version: %d, Packet Type: %s, ReceptionReportCount: %d, Payload Length: %d",
		p.Header.Version, p.Header.PacketType, p.Header.ReceptionReportCount, p.Header.Length)
}
