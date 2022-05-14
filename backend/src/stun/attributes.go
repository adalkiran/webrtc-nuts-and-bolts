package stun

import (
	"encoding/binary"
	"net"
)

type IPFamily byte

const (
	IPFamilyIPv4 IPFamily = 0x01
	IPFamilyIPV6 IPFamily = 0x02
)

type MappedAddress struct {
	IPFamily IPFamily
	IP       net.IP
	Port     uint16
}

func CreateAttrXorMappedAddress(transactionID []byte, addr *net.UDPAddr) *Attribute {
	// https://github.com/jitsi/ice4j/blob/311a495b21f38cc2dfcc4f7118dab96b8134aed6/src/main/java/org/ice4j/attribute/XorMappedAddressAttribute.java#L131
	xorMask := make([]byte, 16)
	binary.BigEndian.PutUint32(xorMask[0:4], magicCookie)
	copy(xorMask[4:], transactionID)
	//addressBytes := ms.Addr.IP
	portModifier := ((uint16(xorMask[0]) << 8) & 0x0000FF00) | (uint16(xorMask[1]) & 0x000000FF)
	addressBytes := make([]byte, len(addr.IP.To4()))
	copy(addressBytes, addr.IP.To4())
	port := uint16(addr.Port) ^ portModifier
	for i := range addressBytes {
		addressBytes[i] ^= xorMask[i]
	}

	value := make([]byte, 8)

	value[1] = byte(IPFamilyIPv4)
	binary.BigEndian.PutUint16(value[2:4], port)
	copy(value[4:8], addressBytes)
	return &Attribute{
		AttributeType: AttrXorMappedAddress,
		Value:         value,
	}
}

func DecodeAttrXorMappedAddress(attr Attribute, transactionID [12]byte) *MappedAddress {
	xorMask := make([]byte, 16)
	binary.BigEndian.PutUint32(xorMask[0:4], magicCookie)
	copy(xorMask[4:], transactionID[:])

	xorIP := make([]byte, 16)
	for i := 0; i < len(attr.Value)-4; i++ {
		xorIP[i] = attr.Value[i+4] ^ xorMask[i]
	}
	family := IPFamily(attr.Value[1])
	port := binary.BigEndian.Uint16(attr.Value[2:4])
	// Truncate if IPv4, otherwise net.IP sometimes renders it as an IPv6 address.
	if family == IPFamilyIPv4 {
		xorIP = xorIP[:4]
	}
	x := binary.BigEndian.Uint16(xorMask[:2])
	return &MappedAddress{
		IPFamily: family,
		IP:       net.IP(xorIP),
		Port:     port ^ x,
	}
}

func CreateAttrUserName(userName string) *Attribute {
	return &Attribute{
		AttributeType: AttrUserName,
		Value:         []byte(userName),
	}
}
