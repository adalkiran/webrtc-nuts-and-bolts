package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/config"
)

var (
	//errInvalidTURNFrame    = errors.New("data is not a valid TURN frame, no STUN or ChannelData found")
	errIncompleteTURNFrame = errors.New("data contains incomplete STUN or TURN frame")
)

type Message struct {
	MessageType   MessageType
	TransactionID [TransactionIDSize]byte
	Attributes    map[AttributeType]Attribute
	RawMessage    []byte
}

const (
	magicCookie       = 0x2112A442
	messageHeaderSize = 20

	TransactionIDSize = 12 // 96 bit

	stunHeaderSize = 20

	hmacSignatureSize = 20

	fingerprintSize = 4

	fingerprintXorMask = 0x5354554e
)

func (m Message) String() string {
	transactionIDStr := base64.StdEncoding.EncodeToString(m.TransactionID[:])
	attrsStr := ""
	for _, a := range m.Attributes {
		attrsStr += fmt.Sprintf("%s ", strings.ReplaceAll(a.String(), "\r", " "))
	}
	return fmt.Sprintf("%s id=%s attrs=%s", m.MessageType, transactionIDStr, attrsStr)
}

func IsMessage(buf []byte, offset int, arrayLen int) bool {
	return arrayLen >= messageHeaderSize && binary.BigEndian.Uint32(buf[offset+4:offset+8]) == magicCookie
}

func DecodeMessage(buf []byte, offset int, arrayLen int) (*Message, error) {
	if arrayLen < stunHeaderSize {
		return nil, errIncompleteTURNFrame
	}

	offsetBackup := offset

	messageType := binary.BigEndian.Uint16(buf[offset : offset+2])

	offset += 2

	messageLength := int(binary.BigEndian.Uint16(buf[offset : offset+2]))

	offset += 2

	// Adding message cookie length
	offset += 4

	result := new(Message)

	result.RawMessage = buf[offsetBackup : offsetBackup+arrayLen]

	result.MessageType = decodeMessageType(messageType)

	copy(result.TransactionID[:], buf[offset:offset+TransactionIDSize])

	offset += TransactionIDSize
	result.Attributes = map[AttributeType]Attribute{}
	for offset-stunHeaderSize < messageLength {
		decodedAttr, err := DecodeAttribute(buf, offset, arrayLen)
		if err != nil {
			return nil, err
		}
		result.SetAttribute(*decodedAttr)
		offset += decodedAttr.GetRawFullLength()

		if decodedAttr.GetRawDataLength()%4 > 0 {
			offset += 4 - decodedAttr.GetRawDataLength()%4
		}
	}
	return result, nil
}

func calculateHmac(binMsg []byte, pwd string) []byte {
	key := []byte(pwd)
	messageLength := uint16(len(binMsg) + attributeHeaderSize + hmacSignatureSize - messageHeaderSize)
	binary.BigEndian.PutUint16(binMsg[2:4], messageLength)
	mac := hmac.New(sha1.New, key)
	mac.Write(binMsg)
	return mac.Sum(nil)
}

func calculateFingerprint(binMsg []byte) []byte {
	result := make([]byte, 4)
	messageLength := uint16(len(binMsg) + attributeHeaderSize + fingerprintSize - messageHeaderSize)
	binary.BigEndian.PutUint16(binMsg[2:4], messageLength)

	binary.BigEndian.PutUint32(result, crc32.ChecksumIEEE(binMsg)^fingerprintXorMask)
	return result
}

func (m *Message) preEncode() {
	// https://github.com/jitsi/ice4j/blob/32a8aadae8fde9b94081f8d002b6fda3490c20dc/src/main/java/org/ice4j/message/Message.java#L1015
	delete(m.Attributes, AttrMessageIntegrity)
	delete(m.Attributes, AttrFingerprint)
	m.Attributes[AttrSoftware] = *createAttrSoftware(config.Val.Server.SoftwareName)
}
func (m *Message) postEncode(encodedMessage []byte, dataLength int, pwd string) []byte {
	// https://github.com/jitsi/ice4j/blob/32a8aadae8fde9b94081f8d002b6fda3490c20dc/src/main/java/org/ice4j/message/Message.java#L1015
	messageIntegrityAttr := &Attribute{
		AttributeType: AttrMessageIntegrity,
		Value:         calculateHmac(encodedMessage, pwd),
	}
	encodedMessageIntegrity := messageIntegrityAttr.Encode()
	encodedMessage = append(encodedMessage, encodedMessageIntegrity...)

	messageFingerprint := &Attribute{
		AttributeType: AttrFingerprint,
		Value:         calculateFingerprint(encodedMessage),
	}
	encodedFingerprint := messageFingerprint.Encode()

	encodedMessage = append(encodedMessage, encodedFingerprint...)

	binary.BigEndian.PutUint16(encodedMessage[2:4], uint16(dataLength+len(encodedMessageIntegrity)+len(encodedFingerprint)))

	return encodedMessage
}

func (m *Message) Encode(pwd string) []byte {
	m.preEncode()
	// https://github.com/jitsi/ice4j/blob/311a495b21f38cc2dfcc4f7118dab96b8134aed6/src/main/java/org/ice4j/message/Message.java#L907
	var encodedAttrs []byte
	for _, attr := range m.Attributes {
		encodedAttr := attr.Encode()
		encodedAttrs = append(encodedAttrs, encodedAttr...)
	}

	result := make([]byte, messageHeaderSize+len(encodedAttrs))

	binary.BigEndian.PutUint16(result[0:2], m.MessageType.Encode())
	binary.BigEndian.PutUint16(result[2:4], uint16(len(encodedAttrs)))
	binary.BigEndian.PutUint32(result[4:8], magicCookie)
	copy(result[8:20], m.TransactionID[:])
	copy(result[20:], encodedAttrs)
	result = m.postEncode(result, len(encodedAttrs), pwd)

	return result
}

func (m *Message) Validate(ufrag string, pwd string) {
	// https://github.com/jitsi/ice4j/blob/311a495b21f38cc2dfcc4f7118dab96b8134aed6/src/main/java/org/ice4j/stack/StunStack.java#L1254
	userNameAttr, okUserName := m.Attributes[AttrUserName]
	if okUserName {
		userName := strings.Split(string(userNameAttr.Value), ":")[0]
		if userName != ufrag {
			panic("Message not valid: UserName!")
		}
	}
	if messageIntegrityAttr, ok := m.Attributes[AttrMessageIntegrity]; ok {
		if !okUserName {
			panic("Message not valid: missing username!")
		}
		binMsg := make([]byte, messageIntegrityAttr.OffsetInMessage)
		copy(binMsg, m.RawMessage[0:messageIntegrityAttr.OffsetInMessage])

		calculatedHmac := calculateHmac(binMsg, pwd)
		if !bytes.Equal(calculatedHmac, messageIntegrityAttr.Value) {
			panic(fmt.Sprintf("Message not valid: MESSAGE-INTEGRITY not valid expected: %v , received: %v not compatible!", calculatedHmac, messageIntegrityAttr.Value))
		}
	}

	if fingerprintAttr, ok := m.Attributes[AttrFingerprint]; ok {
		binMsg := make([]byte, fingerprintAttr.OffsetInMessage)
		copy(binMsg, m.RawMessage[0:fingerprintAttr.OffsetInMessage])

		calculatedFingerprint := calculateFingerprint(binMsg)
		if !bytes.Equal(calculatedFingerprint, fingerprintAttr.Value) {
			panic(fmt.Sprintf("Message not valid: FINGERPRINT not valid expected: %v , received: %v not compatible!", calculatedFingerprint, fingerprintAttr.Value))
		}
	}
}

func (m *Message) SetAttribute(attr Attribute) {
	m.Attributes[attr.AttributeType] = attr
}

func createAttrSoftware(software string) *Attribute {
	return &Attribute{
		AttributeType: AttrSoftware,
		Value:         []byte(software),
	}
}

func NewMessage(messageType MessageType, transactionID [12]byte) *Message {
	result := &Message{
		MessageType:   messageType,
		TransactionID: transactionID,
		Attributes:    map[AttributeType]Attribute{},
	}
	return result
}
