package srtp

import (
	"net"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/rtp"
)

type SRTPContext struct {
	Addr              *net.UDPAddr
	Conn              *net.UDPConn
	ProtectionProfile ProtectionProfile
	GCM               *GCM
	srtpSSRCStates    map[uint32]*srtpSSRCState
}

type srtpSSRCState struct {
	ssrc                 uint32
	index                uint64
	rolloverHasProcessed bool
}

//https://github.com/pion/srtp/blob/3c34651fa0c6de900bdc91062e7ccb5992409643/context.go#L159
func (c *SRTPContext) getSRTPSSRCState(ssrc uint32) *srtpSSRCState {
	s, ok := c.srtpSSRCStates[ssrc]
	if ok {
		return s
	}

	s = &srtpSSRCState{
		ssrc: ssrc,
	}
	c.srtpSSRCStates[ssrc] = s
	return s
}

func (s *srtpSSRCState) nextRolloverCount(sequenceNumber uint16) (uint32, func()) {
	seq := int32(sequenceNumber)
	localRoc := uint32(s.index >> 16)
	localSeq := int32(s.index & (seqNumMax - 1))

	guessRoc := localRoc
	var difference int32 = 0

	if s.rolloverHasProcessed {
		// When localROC is equal to 0, and entering seq-localSeq > seqNumMedian
		// judgment, it will cause guessRoc calculation error
		if s.index > seqNumMedian {
			if localSeq < seqNumMedian {
				if seq-localSeq > seqNumMedian {
					guessRoc = localRoc - 1
					difference = seq - localSeq - seqNumMax
				} else {
					guessRoc = localRoc
					difference = seq - localSeq
				}
			} else {
				if localSeq-seqNumMedian > seq {
					guessRoc = localRoc + 1
					difference = seq - localSeq + seqNumMax
				} else {
					guessRoc = localRoc
					difference = seq - localSeq
				}
			}
		} else {
			// localRoc is equal to 0
			difference = seq - localSeq
		}
	}

	return guessRoc, func() {
		if !s.rolloverHasProcessed {
			s.index |= uint64(sequenceNumber)
			s.rolloverHasProcessed = true
			return
		}
		if difference > 0 {
			s.index += uint64(difference)
		}
	}
}

//https://github.com/pion/srtp/blob/3c34651fa0c6de900bdc91062e7ccb5992409643/srtp.go#L8
func (c *SRTPContext) DecryptRTPPacket(packet *rtp.Packet) ([]byte, error) {
	s := c.getSRTPSSRCState(packet.Header.SSRC)
	roc, updateROC := s.nextRolloverCount(packet.Header.SequenceNumber)
	result, err := c.GCM.Decrypt(packet, roc)
	if err != nil {
		return nil, err
	}
	updateROC()
	return result[packet.HeaderSize:], nil
}
