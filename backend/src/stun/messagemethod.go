package stun

import "fmt"

type MessageMethod uint16

type messageMethodDef struct {
	Name string
}

const (
	MessageMethodStunBinding           MessageMethod = 0x0001
	MessageMethodTurnAllocate          MessageMethod = 0x0003
	MessageMethodTurnRefresh           MessageMethod = 0x0004
	MessageMethodTurnSend              MessageMethod = 0x0006
	MessageMethodTurnData              MessageMethod = 0x0007
	MessageMethodTurnCreatePermission  MessageMethod = 0x0008
	MessageMethodTurnChannelBind       MessageMethod = 0x0009
	MessageMethodTurnConnect           MessageMethod = 0x000a
	MessageMethodTurnConnectionBind    MessageMethod = 0x000b
	MessageMethodTurnConnectionAttempt MessageMethod = 0x000c
)

var messageMethodMap = map[MessageMethod]messageMethodDef{
	MessageMethodStunBinding:           {"STUN Binding"},
	MessageMethodTurnAllocate:          {"TURN Allocate"},
	MessageMethodTurnRefresh:           {"TURN Refresh"},
	MessageMethodTurnSend:              {"TURN Send"},
	MessageMethodTurnData:              {"TURN Data"},
	MessageMethodTurnCreatePermission:  {"TURN CreatePermission"},
	MessageMethodTurnChannelBind:       {"TURN ChannelBind"},
	MessageMethodTurnConnect:           {"TURN Connect"},
	MessageMethodTurnConnectionBind:    {"TURN ConnectionBind"},
	MessageMethodTurnConnectionAttempt: {"TURN ConnectionAttempt"},
}

func (mm MessageMethod) String() string {
	messageMethodDef, ok := messageMethodMap[mm]
	if !ok {
		// Just return hex representation of unknown method.
		return fmt.Sprintf("0x%x", uint16(mm))
	}
	return messageMethodDef.Name
}
