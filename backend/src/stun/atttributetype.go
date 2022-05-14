package stun

import "fmt"

type AttributeType uint16

type attributeTypeDef struct {
	Name string
}

func (at AttributeType) String() string {
	attributeTypeDef, ok := attributeTypeMap[at]
	if !ok {
		// Just return hex representation of unknown attribute type.
		return fmt.Sprintf("0x%x", uint16(at))
	}
	return attributeTypeDef.Name
}

const (
	// STUN attributes:

	AttrMappedAddress     AttributeType = 0x0001
	AttrResponseAddress   AttributeType = 0x0002
	AttrChangeRequest     AttributeType = 0x0003
	AttrSourceAddress     AttributeType = 0x0004
	AttrChangedAddress    AttributeType = 0x0005
	AttrUserName          AttributeType = 0x0006
	AttrPassword          AttributeType = 0x0007
	AttrMessageIntegrity  AttributeType = 0x0008
	AttrErrorCode         AttributeType = 0x0009
	AttrUnknownAttributes AttributeType = 0x000a
	AttrReflectedFrom     AttributeType = 0x000b
	AttrRealm             AttributeType = 0x0014
	AttrNonce             AttributeType = 0x0015
	AttrXorMappedAddress  AttributeType = 0x0020
	AttrSoftware          AttributeType = 0x8022
	AttrAlternameServer   AttributeType = 0x8023
	AttrFingerprint       AttributeType = 0x8028

	// TURN attributes:
	AttrChannelNumber      AttributeType = 0x000C
	AttrLifetime           AttributeType = 0x000D
	AttrXorPeerAdddress    AttributeType = 0x0012
	AttrData               AttributeType = 0x0013
	AttrXorRelayedAddress  AttributeType = 0x0016
	AttrEvenPort           AttributeType = 0x0018
	AttrRequestedPort      AttributeType = 0x0019
	AttrDontFragment       AttributeType = 0x001A
	AttrReservationRequest AttributeType = 0x0022

	// ICE attributes:
	AttrPriority       AttributeType = 0x0024
	AttrUseCandidate   AttributeType = 0x0025
	AttrIceControlled  AttributeType = 0x8029
	AttrIceControlling AttributeType = 0x802A
)

var attributeTypeMap = map[AttributeType]attributeTypeDef{
	// STUN attributes:
	AttrMappedAddress:     {"MAPPED-ADDRESS"},
	AttrResponseAddress:   {"RESPONSE-ADDRESS"},
	AttrChangeRequest:     {"CHANGE-REQUEST"},
	AttrSourceAddress:     {"SOURCE-ADDRESS"},
	AttrChangedAddress:    {"CHANGED-ADDRESS"},
	AttrUserName:          {"USERNAME"},
	AttrPassword:          {"PASSWORD"},
	AttrMessageIntegrity:  {"MESSAGE-INTEGRITY"},
	AttrErrorCode:         {"ERROR-CODE"},
	AttrUnknownAttributes: {"UNKNOWN-ATTRIBUTE"},
	AttrReflectedFrom:     {"REFLECTED-FROM"},
	AttrRealm:             {"REALM"},
	AttrNonce:             {"NONCE"},
	AttrXorMappedAddress:  {"XOR-MAPPED-ADDRES"},
	AttrSoftware:          {"SOFTWARE"},
	AttrAlternameServer:   {"ALTERNATE-SERVER"},
	AttrFingerprint:       {"FINGERPRINT"},

	// TURN attributes:
	AttrChannelNumber:      {"CHANNEL-NUMBER"},
	AttrLifetime:           {"LIFETIME"},
	AttrXorPeerAdddress:    {"XOR-PEER-ADDRESS"},
	AttrData:               {"DATA"},
	AttrXorRelayedAddress:  {"XOR-RELAYED-ADDRESS"},
	AttrEvenPort:           {"EVEN-PORT"},
	AttrRequestedPort:      {"REQUESTED-TRANSPORT"},
	AttrDontFragment:       {"DONT-FRAGMENT"},
	AttrReservationRequest: {"RESERVATION-TOKEN"},

	// ICE attributes:
	AttrPriority:       {"PRIORITY"},
	AttrUseCandidate:   {"USE-CANDIDATE"},
	AttrIceControlled:  {"ICE-CONTROLLED"},
	AttrIceControlling: {"ICE-CONTROLLING"},
}
