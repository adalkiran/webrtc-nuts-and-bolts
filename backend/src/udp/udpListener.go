package udp

import (
	"net"
	"strings"
	"sync"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/agent"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/conference"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/stun"
)

type UdpListener struct {
	Ip   string
	Port int

	conn *net.UDPConn

	ConferenceManager *conference.ConferenceManager

	Sockets map[string]*agent.UDPClientSocket
}

func NewUdpListener(ip string, port int, conferenceManager *conference.ConferenceManager) *UdpListener {
	return &UdpListener{
		Ip:                ip,
		Port:              port,
		ConferenceManager: conferenceManager,
		Sockets:           map[string]*agent.UDPClientSocket{},
	}
}

func readUfrag(buf []byte, offset int, arrayLen int) (string, string, bool) {
	if !stun.IsMessage(buf, offset, arrayLen) {
		return "", "", false
	}
	stunMessage, stunErr := stun.DecodeMessage(buf, 0, arrayLen)
	if stunErr != nil {
		panic(stunErr)
	}
	if stunMessage.MessageType != stun.MessageTypeBindingRequest {
		return "", "", false
	}
	userNameAttr, userNameExists := stunMessage.Attributes[stun.AttrUserName]

	if !userNameExists {
		return "", "", false
	}

	userNameParts := strings.Split(string(userNameAttr.Value), ":")
	serverUserName := userNameParts[0]
	clientUserName := userNameParts[1]
	return serverUserName, clientUserName, true
}

func (udpListener *UdpListener) Run(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: udpListener.Port,
	})
	if err != nil {
		panic(err)
	}

	udpListener.conn = conn

	defer conn.Close()

	logging.Infof(logging.ProtoUDP, "Listen on <u>%v %d/UDP</u>", "single-port", udpListener.Port)
	logging.Descf(logging.ProtoUDP, "Clients will do media streaming via this connection. This UDP listener acts as demultiplexer, in other words, it can speak in STUN, DTLS, SRTP, SRTCP, etc... protocols in single port. It differentiates protocols by looking shape of packet headers. Clients don't know this listener's IP and port now, they will learn via signaling the SDP offer/answer data when they join a conference via signaling subsystem/WebSocket.")

	buf := make([]byte, 2048)

	// We run into an infinite loop for any incoming UDP packet from specified port.
	for {
		bufLen, addr, err := conn.ReadFromUDP(buf)
		if err == nil {
			// Is the client socket known and authenticated by server before?
			destinationSocket, ok := udpListener.Sockets[string(addr.IP)+":"+string(rune(addr.Port))]

			if !ok {
				logging.Descf(logging.ProtoUDP, "An UDP packet received from <u>%s:%d</u> first time. This client is not known already by UDP server. Is it a STUN binding request?", addr.IP, addr.Port)
				// If client socket is not known by server, it can be a STUN binding request.
				// Read the server and client ufrag (user fragment) string concatenated via ":" and split it.
				serverUfrag, clientUfrag, ok := readUfrag(buf, 0, bufLen)

				if !ok {
					logging.Descf(logging.ProtoUDP, "This packet is not a valid STUN binding request, ignore it.")
					// If this is not a valid STUN binding request, ignore it.
					continue
				}
				logging.Descf(logging.ProtoUDP, "It is a valid STUN binding request with Server Ufrag: <u>%s</u>, Client Ufrag: <u>%s</u>", serverUfrag, clientUfrag)
				logging.Descf(logging.ProtoUDP, "Looking for valid server agent related with an existing conference, with Ufrag: <u>%s</u>", serverUfrag)
				// It seems a valid STUN binding request, does serverUfrag point
				// a server agent (of a defined conference) which is already listening?
				agent, ok := udpListener.ConferenceManager.GetAgent(serverUfrag)
				if !ok {
					logging.Descf(logging.ProtoUDP, "Any server agent couldn't be found that serverUfrag <u>%s</u> points, ignore it.", serverUfrag)
					// Any server agent couldn't be found that serverUfrag points, ignore it.
					continue
				}
				logging.Descf(logging.ProtoUDP, "Found server ICE Agent related with conference <u>%s</u>.", agent.ConferenceName)
				signalingMediaComponent, ok := agent.SignalingMediaComponents[clientUfrag]
				if !ok {
					logging.Descf(logging.ProtoUDP, "Client Ufrag <u>%s</u> is not known by server agent <u>%s</u>. SDP Offer/Answer should be processed before UDP STUN binding request. Ignore it.", clientUfrag, serverUfrag)
					// Any server agent couldn't be found that serverUfrag points, ignore it.
					continue
				}
				logging.Descf(logging.ProtoUDP, "Found SignalingMediaComponent for client Ufrag <u>%s</u>. It seems we can define a client socket to the server agent(<u>%s</u>). Creating a new UDPClientSocket object for this UDP client.", signalingMediaComponent.Ufrag, agent.ConferenceName)
				// It seems we can define a client socket to the server agent.
				destinationSocket = udpListener.addNewUDPClientSocket(agent, addr, clientUfrag)

				// If this STUN binding request's client ufrag is not known by our agent, ignore the request.
				// Agent should know the ufrag by SDP offer coming from WebSocket, before coming STUN binding request from UDP.
				if destinationSocket == nil {
					continue
				}
			}

			// Now the client socket is known by server, we forward incoming byte array to our socket object dedicated for the client.
			destinationSocket.AddBuffer(buf, 0, bufLen)
		} else {
			logging.Errorf(logging.ProtoUDP, "Some error: %s", err)
		}
	}

}

func (udpListener *UdpListener) addNewUDPClientSocket(serverAgent *agent.ServerAgent, addr *net.UDPAddr, clientUfrag string) *agent.UDPClientSocket {
	clientComponent, ok := serverAgent.SignalingMediaComponents[clientUfrag]
	if !ok {
		// It seems clientUfrag is not known by the server agent, ignore it.
		return nil
	}
	udpClientSocket, err := agent.NewUDPClientSocket(addr, serverAgent.Ufrag, serverAgent.Pwd, clientUfrag, udpListener.conn, clientComponent.FingerprintHash)
	if err != nil {
		panic(err)
	}
	serverAgent.Sockets[clientUfrag] = *udpClientSocket
	udpListener.Sockets[string(addr.IP)+":"+string(rune(addr.Port))] = udpClientSocket
	return udpClientSocket
}
