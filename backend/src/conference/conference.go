package conference

import (
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/agent"
)

type Conference struct {
	ConferenceName string
	IceAgent       *agent.ServerAgent
}

func NewConference(conferenceName string, candidateIPs []string, udpPort int) *Conference {
	result := &Conference{
		ConferenceName: conferenceName,
		IceAgent:       agent.NewServerAgent(candidateIPs, udpPort, conferenceName),
	}
	return result
}
