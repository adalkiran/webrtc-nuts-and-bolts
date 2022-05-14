package transcoding

import (
	"bytes"
	"errors"
	"fmt"
	"image/jpeg"
	"os"
	"path/filepath"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/rtp"
	"github.com/xlab/libvpx-go/vpx"
)

var (
	currentFrame []byte
	seenKeyFrame = false
)

// https://stackoverflow.com/questions/68859120/how-to-convert-vp8-interframe-into-image-with-pion-webrtc
type VP8Decoder struct {
	src     <-chan *rtp.Packet
	context *vpx.CodecCtx
	iface   *vpx.CodecIface
}

func NewVP8Decoder(src <-chan *rtp.Packet) (*VP8Decoder, error) {
	result := &VP8Decoder{
		src:     src,
		context: vpx.NewCodecCtx(),
		iface:   vpx.DecoderIfaceVP8(),
	}
	err := vpx.Error(vpx.CodecDecInitVer(result.context, result.iface, nil, 0, vpx.DecoderABIVersion))
	if err != nil {
		return nil, err
	}
	return result, nil
}

var (
	fileCount      = 0
	saveDir        = "../output"
	saveFilePrefix = "shoot"
)

func (d *VP8Decoder) Run() {

	newpath := filepath.Join(".", saveDir)
	err := os.MkdirAll(newpath, os.ModePerm)

	if err != nil {
		panic(err)
	}

	packetCounter := 0
	//https://stackoverflow.com/questions/68859120/how-to-convert-vp8-interframe-into-image-with-pion-webrtc
	for rtpPacket := range d.src {
		packetCounter++

		vp8Packet := &VP8Packet{}
		vp8Packet.Unmarshal(rtpPacket.Payload)
		isKeyFrame := vp8Packet.Payload[0] & 0x01

		switch {
		case !seenKeyFrame && isKeyFrame == 1:
			continue
		case currentFrame == nil && vp8Packet.S != 1:
			continue
		}

		seenKeyFrame = true
		currentFrame = append(currentFrame, vp8Packet.Payload[0:]...)

		if !rtpPacket.Header.Marker {
			continue
		} else if len(currentFrame) == 0 {
			continue
		}

		err := vpx.Error(vpx.CodecDecode(d.context, string(currentFrame), uint32(len(currentFrame)), nil, 0))
		if err != nil {
			logging.Errorf(logging.ProtoVP8, "Error while decoding packet: %s", err)
			currentFrame = nil
			seenKeyFrame = false
			continue
		}

		var iter vpx.CodecIter
		img := vpx.CodecGetFrame(d.context, &iter)
		if img != nil {
			img.Deref()

			outputImageFilePath, err := d.saveImageFile(img)
			if err != nil {
				logging.Errorf(logging.ProtoVP8, "Error while image saving: %s", err)
			} else {
				logging.Infof(logging.ProtoVP8, "Image file saved: %s\n", outputImageFilePath)
			}

		}
		currentFrame = nil
		seenKeyFrame = false

	}
}

func (d *VP8Decoder) saveImageFile(img *vpx.Image) (string, error) {
	fileCount++
	buffer := new(bytes.Buffer)
	if err := jpeg.Encode(buffer, img.ImageYCbCr(), nil); err != nil {
		return "", fmt.Errorf("jpeg Encode Error: %s", err)
	}

	outputImageFilePath := fmt.Sprintf("%s%d%s", filepath.Join(saveDir, saveFilePrefix), fileCount, ".jpg")
	fo, err := os.Create(outputImageFilePath)

	if err != nil {
		return "", fmt.Errorf("image create Error: %s", err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	if _, err := fo.Write(buffer.Bytes()); err != nil {
		return "", fmt.Errorf("image write Error: %s", err)
	}
	return outputImageFilePath, nil
}

/*
      0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+
     |X|R|N|S|PartID | (REQUIRED)
     +-+-+-+-+-+-+-+-+
X:   |I|L|T|K| RSV   | (OPTIONAL)
     +-+-+-+-+-+-+-+-+
I:   |M| PictureID   | (OPTIONAL)
     +-+-+-+-+-+-+-+-+
L:   |   TL0PICIDX   | (OPTIONAL)
     +-+-+-+-+-+-+-+-+
T/K: |TID|Y| KEYIDX  | (OPTIONAL)
     +-+-+-+-+-+-+-+-+
*/

//https://tools.ietf.org/id/draft-ietf-payload-vp8-05.html
type VP8Packet struct {
	// Required Header
	X   uint8 /* extended control bits present */
	N   uint8 /* when set to 1 this frame can be discarded */
	S   uint8 /* start of VP8 partition */
	PID uint8 /* partition index */

	// Extended control bits
	I uint8 /* 1 if PictureID is present */
	L uint8 /* 1 if TL0PICIDX is present */
	T uint8 /* 1 if TID is present */
	K uint8 /* 1 if KEYIDX is present */

	// Optional extension
	PictureID uint16 /* 8 or 16 bits, picture ID */
	TL0PICIDX uint8  /* 8 bits temporal level zero index */
	TID       uint8  /* 2 bits temporal layer index */
	Y         uint8  /* 1 bit layer sync bit */
	KEYIDX    uint8  /* 5 bits temporal key frame index */

	Payload []byte
}

func (p *VP8Packet) Unmarshal(payload []byte) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("errNilPacket")
	}

	payloadLen := len(payload)

	if payloadLen < 4 {
		return nil, errors.New("errShortPacket")
	}

	payloadIndex := 0

	p.X = (payload[payloadIndex] & 0x80) >> 7
	p.N = (payload[payloadIndex] & 0x20) >> 5
	p.S = (payload[payloadIndex] & 0x10) >> 4
	p.PID = payload[payloadIndex] & 0x07

	payloadIndex++

	if p.X == 1 {
		p.I = (payload[payloadIndex] & 0x80) >> 7
		p.L = (payload[payloadIndex] & 0x40) >> 6
		p.T = (payload[payloadIndex] & 0x20) >> 5
		p.K = (payload[payloadIndex] & 0x10) >> 4
		payloadIndex++
	}

	if p.I == 1 { // PID present?
		if payload[payloadIndex]&0x80 > 0 { // M == 1, PID is 16bit
			p.PictureID = (uint16(payload[payloadIndex]&0x7F) << 8) | uint16(payload[payloadIndex+1])
			payloadIndex += 2
		} else {
			p.PictureID = uint16(payload[payloadIndex])
			payloadIndex++
		}
	}

	if payloadIndex >= payloadLen {
		return nil, errors.New("errShortPacket")
	}

	if p.L == 1 {
		p.TL0PICIDX = payload[payloadIndex]
		payloadIndex++
	}

	if payloadIndex >= payloadLen {
		return nil, errors.New("errShortPacket")
	}

	if p.T == 1 || p.K == 1 {
		if p.T == 1 {
			p.TID = payload[payloadIndex] >> 6
			p.Y = (payload[payloadIndex] >> 5) & 0x1
		}
		if p.K == 1 {
			p.KEYIDX = payload[payloadIndex] & 0x1F
		}
		payloadIndex++
	}

	if payloadIndex >= payloadLen {
		return nil, errors.New("errShortPacket")
	}
	p.Payload = payload[payloadIndex:]
	return p.Payload, nil
}
