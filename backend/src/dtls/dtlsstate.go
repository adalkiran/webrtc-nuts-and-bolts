package dtls

type DTLSState byte

const (
	DTLSStateNew        DTLSState = 1
	DTLSStateConnecting DTLSState = 2
	DTLSStateConnected  DTLSState = 3
	DTLSStateFailed     DTLSState = 4
)

func (s DTLSState) String() string {
	switch s {
	case DTLSStateNew:
		return "New"
	case DTLSStateConnecting:
		return "Connecting"
	case DTLSStateConnected:
		return "Connected"
	case DTLSStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}
