package stun

import (
	"bytes"
	"crypto/rand"
	"net"
)

type StunClient struct {
	ServerAddr string
	Ufrag      string
	Pwd        string
}

func NewStunClient(serverAddr string, ufrag string, pwd string) *StunClient {
	return &StunClient{
		ServerAddr: serverAddr,
		Ufrag:      ufrag,
		Pwd:        pwd,
	}
}

// https://github.com/ccding/go-stun
func (c *StunClient) Discover() (*MappedAddress, error) {
	transactionID, err := generateTransactionID()
	if err != nil {
		return nil, err
	}
	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.ServerAddr)
	if err != nil {
		return nil, err
		//return NATError, nil, err
	}
	bindingRequest := createBindingRequest(transactionID)
	encodedBindingRequest := bindingRequest.Encode(c.Pwd)
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.WriteToUDP(encodedBindingRequest, serverUDPAddr)
	buf := make([]byte, 1024)

	for {
		bufLen, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		// If requested target server address and responder address not fit, ignore the packet
		if !addr.IP.Equal(serverUDPAddr.IP) || addr.Port != serverUDPAddr.Port {
			continue
		}
		stunMessage, stunErr := DecodeMessage(buf, 0, bufLen)
		if stunErr != nil {
			panic(stunErr)
		}
		stunMessage.Validate(c.Ufrag, c.Pwd)
		if !bytes.Equal(stunMessage.TransactionID[:], transactionID[:]) {
			continue
		}
		xorMappedAddressAttr, ok := stunMessage.Attributes[AttrXorMappedAddress]
		if !ok {
			continue
		}
		mappedAddress := DecodeAttrXorMappedAddress(xorMappedAddressAttr, stunMessage.TransactionID)
		return mappedAddress, nil
	}
}

func generateTransactionID() ([12]byte, error) {
	result := [12]byte{}
	_, err := rand.Read(result[:])
	if err != nil {
		return result, err
	}
	return result, nil
}

func createBindingRequest(transactionID [12]byte) *Message {
	responseMessage := NewMessage(MessageTypeBindingRequest, transactionID)
	return responseMessage
}
