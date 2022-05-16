package signaling

import (
	"encoding/json"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/conference"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/sdp"
)

// See: https://github.com/gorilla/websocket/tree/master/examples/chat

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type WsHub struct {
	maxClientId int

	// Registered clients.
	clients map[*WsClient]bool

	// Inbound messages from the clients.
	messageReceived chan *ReceivedMessage

	broadcast chan BroadcastMessage

	// Register requests from the clients.
	register chan *WsClient

	// Unregister requests from clients.
	unregister chan *WsClient

	ConferenceManager *conference.ConferenceManager
}

type BroadcastMessage struct {
	Message        []byte
	ExcludeClients []int
}

type MessageContainer struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func newWsHub(conferenceManager *conference.ConferenceManager) *WsHub {
	return &WsHub{
		messageReceived:   make(chan *ReceivedMessage),
		broadcast:         make(chan BroadcastMessage),
		register:          make(chan *WsClient),
		unregister:        make(chan *WsClient),
		clients:           make(map[*WsClient]bool),
		ConferenceManager: conferenceManager,
	}
}

func processBroadcastMessage(h *WsHub, broadcastMessage BroadcastMessage) {
	for client := range h.clients {
		if broadcastMessage.ExcludeClients != nil {
			var found = false
			for _, item := range broadcastMessage.ExcludeClients {
				if item == client.id {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}
		select {
		case client.send <- broadcastMessage.Message:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
}

func writeContainerJSON(client *WsClient, messageType string, messageData interface{}) {
	client.conn.WriteJSON(MessageContainer{
		Type: messageType,
		Data: messageData,
	})
}

func (h *WsHub) run() {
	for {
		select {
		case client := <-h.register:
			h.maxClientId++
			client.id = h.maxClientId
			h.clients[client] = true
			logging.Infof(logging.ProtoWS, "A new client connected: <u>client %d</u> (from <u>%s</u>)", client.id, client.conn.RemoteAddr())
			logging.Descf(logging.ProtoWS, "Sending welcome message via WebSocket. The client is informed with client ID given by the signaling server.")
			writeContainerJSON(client, "Welcome", ClientWelcomeMessage{
				Id:      client.id,
				Message: "Welcome!",
			})
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				logging.Infof(logging.ProtoWS, "Client disconnected: <u>client %d</u> (from <u>%s</u>)", client.id, client.conn.RemoteAddr())
			}
		case broadcastMessage := <-h.broadcast:
			processBroadcastMessage(h, broadcastMessage)
		case receivedMessage := <-h.messageReceived:
			var messageObj map[string]interface{}
			json.Unmarshal(receivedMessage.Message, &messageObj)

			logging.Infof(logging.ProtoWS, "Message received from <u>client %d</u> type <u>%s</u>", receivedMessage.Sender.id, messageObj["type"])
			switch messageObj["type"] {
			case "JoinConference":
				h.processJoinConference(messageObj["data"].(map[string]interface{}), receivedMessage.Sender)
			case "SdpOfferAnswer":
				incomingSdpOfferAnswerMessage := sdp.ParseSdpOfferAnswer(messageObj["data"].(map[string]interface{}))
				incomingSdpOfferAnswerMessage.ConferenceName = receivedMessage.Sender.conference.ConferenceName
				h.ConferenceManager.ChanSdpOffer <- incomingSdpOfferAnswerMessage
				/*
					processBroadcastMessage(h, BroadcastMessage{
						ExcludeClients: []int{receivedMessage.Sender.id},
						Message:        receivedMessage.Message,
					})
				*/
			default:
				h.broadcast <- BroadcastMessage{
					Message: receivedMessage.Message,
				}
			}
		}
	}
}

func (h *WsHub) processJoinConference(messageData map[string]interface{}, wsClient *WsClient) {
	conferenceName := messageData["conferenceName"].(string)
	logging.Descf(logging.ProtoWS, "The <u>client %d</u> wanted to join the conference <u>%s</u>.", wsClient.id, conferenceName)
	wsClient.conference = h.ConferenceManager.EnsureConference(conferenceName)
	logging.Descf(logging.ProtoWS, "The client was joined the conference. Now we should generate an SDP Offer including our UDP candidates (IP-port pairs) and send to the client via Signaling/WebSocket.")
	sdpMessage := sdp.GenerateSdpOffer(wsClient.conference.IceAgent)
	logging.Infof(logging.ProtoSDP, "Sending SDP Offer to <u>client %d</u> (<u>%s</u>) for conference <u>%s</u>: %s", wsClient.id, wsClient.RemoteAddrStr(), conferenceName, sdpMessage)
	logging.LineSpacer(2)
	writeContainerJSON(wsClient, "SdpOffer", sdpMessage)
}
