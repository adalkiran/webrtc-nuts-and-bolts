package signaling

type JoinConferenceData struct {
	ConferenceName string
	WsClient       WsClient
}
