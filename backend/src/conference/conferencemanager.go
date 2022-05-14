package conference

import (
	"sync"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/agent"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/sdp"
)

type ConferenceManager struct {
	CandidateIPs []string
	UDPPort      int
	Conferences  map[string]*Conference        //key: ConferenceName
	Agents       map[string]*agent.ServerAgent //key: Ufrag

	ChanSdpOffer chan *sdp.SdpMessage
}

func NewConferenceManager(candidateIPs []string, udpPort int) *ConferenceManager {
	result := &ConferenceManager{
		CandidateIPs: candidateIPs,
		UDPPort:      udpPort,
		Conferences:  map[string]*Conference{},
		Agents:       map[string]*agent.ServerAgent{},
		ChanSdpOffer: make(chan *sdp.SdpMessage, 1),
	}
	return result
}

func (m *ConferenceManager) EnsureConference(conferenceName string) *Conference {
	conference, ok := m.Conferences[conferenceName]
	if !ok {
		newConference := NewConference(conferenceName, m.CandidateIPs, m.UDPPort)
		m.Conferences[conferenceName] = newConference
		m.Agents[newConference.IceAgent.Ufrag] = newConference.IceAgent
		return newConference
	}
	return conference
}

func (m *ConferenceManager) GetAgent(ufrag string) (*agent.ServerAgent, bool) {
	result, ok := m.Agents[ufrag]
	return result, ok
}

func (m *ConferenceManager) Run(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	for {
		select {
		case sdpOffer := <-m.ChanSdpOffer:
			conference, ok := m.Conferences[sdpOffer.ConferenceName]
			if !ok {
				logging.Warningf(logging.ProtoSDP, "Conference not found: <u>%s</u>, ignoring SdpOffer\n", sdpOffer.ConferenceName)
				continue
			}
			for _, sdpMediaItem := range sdpOffer.MediaItems {
				conference.IceAgent.EnsureSignalingMediaComponent(sdpMediaItem.Ufrag, sdpMediaItem.Pwd, sdpMediaItem.FingerprintHash)
			}
			logging.Descf(logging.ProtoSDP, "We processed incoming SDP, notified the conference's ICE Agent object (SignalingMediaComponents) about client (media) components' ufrag, pwd and fingerprint hash in the SDP. The server knows some metadata about the UDP packets will come in future. Now we are waiting for a STUN Binding Request packet via UDP, with server Ufrag <u>%s</u> from the client!", sdpOffer.MediaItems[0].Ufrag)
		}
	}
}
