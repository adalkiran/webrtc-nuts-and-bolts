package dtls

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const (
	RandomBytesLength = 28
)

// https://github.com/pion/dtls/blob/b3e235f54b60ccc31aa10193807b5e8e394f17ff/pkg/protocol/handshake/random.go
type Random struct {
	GMTUnixTime time.Time
	RandomBytes [RandomBytesLength]byte
}

func (r *Random) Encode() []byte {
	result := make([]byte, 4+RandomBytesLength)

	binary.BigEndian.PutUint32(result[0:4], uint32(r.GMTUnixTime.Unix()))
	copy(result[4:], r.RandomBytes[:])
	return result
}

func (r *Random) Generate() error {
	r.GMTUnixTime = time.Now()
	tmp := make([]byte, RandomBytesLength)
	_, err := rand.Read(tmp)
	copy(r.RandomBytes[:], tmp)
	return err
}

func DecodeRandom(buf []byte, offset int, arrayLen int) (*Random, int, error) {
	result := new(Random)
	result.GMTUnixTime = time.Unix(int64(binary.BigEndian.Uint32(buf[offset:offset+4])), 0)
	offset += 4
	copy(result.RandomBytes[:], buf[offset:offset+RandomBytesLength])
	offset += RandomBytesLength

	return result, offset, nil
}
