package agent

import (
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/dtls"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type ServerAgent struct {
	ConferenceName           string
	Ufrag                    string
	Pwd                      string
	FingerprintHash          string
	IceCandidates            []*IceCandidate
	SignalingMediaComponents map[string]*SignalingMediaComponent
	Sockets                  map[string]UDPClientSocket
}

type SignalingMediaComponent struct {
	Agent           *ServerAgent
	Ufrag           string
	Pwd             string
	FingerprintHash string
}

type IceCandidate struct {
	Ip   string
	Port int
}

func NewServerAgent(candidateIPs []string, udpPort int, conferenceName string) *ServerAgent {
	result := &ServerAgent{
		ConferenceName:           conferenceName,
		Ufrag:                    GenerateICEUfrag(),
		Pwd:                      GenerateICEPwd(),
		FingerprintHash:          dtls.ServerCertificateFingerprint,
		IceCandidates:            []*IceCandidate{},
		SignalingMediaComponents: map[string]*SignalingMediaComponent{},
		Sockets:                  map[string]UDPClientSocket{},
	}
	for _, candidateIP := range candidateIPs {
		result.IceCandidates = append(result.IceCandidates, &IceCandidate{
			Ip:   candidateIP,
			Port: udpPort,
		})
	}
	logging.Descf(logging.ProtoAPP, "A new server ICE Agent was created (for a new conference) with Ufrag: <u>%s</u>, Pwd: <u>%s</u>, FingerprintHash: <u>%s</u>", result.Ufrag, result.Pwd, result.FingerprintHash)
	return result
}

func (a *ServerAgent) EnsureSignalingMediaComponent(iceUfrag string, icePwd string, fingerprintHash string) *SignalingMediaComponent {
	result, ok := a.SignalingMediaComponents[iceUfrag]
	if ok {
		return result
	}
	result = &SignalingMediaComponent{
		Agent:           a,
		Ufrag:           iceUfrag,
		Pwd:             icePwd,
		FingerprintHash: fingerprintHash,
	}
	a.SignalingMediaComponents[iceUfrag] = result
	return result
}
