package logging

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	blacklist = map[string]string{}

	protocolPrefixColor  = color.New(color.FgWhite, color.BgBlue).SprintfFunc()
	underlinePrefixColor = color.New(color.Underline).SprintFunc()

	freeLevel    = NewLoggerLevel("")
	descLevel    = NewLoggerLevel("DESCRIPTION", color.FgGreen)
	infoLevel    = NewLoggerLevel("INFO", color.FgHiBlue)
	warningLevel = NewLoggerLevel("WARNING", color.FgYellow)
	errorLevel   = NewLoggerLevel("ERROR", color.FgRed)

	Freef    = freeLevel.Printf
	Descf    = descLevel.Printf
	Infof    = infoLevel.Printf
	Warningf = warningLevel.Printf
	Errorf   = errorLevel.Printf
)

const (
	ProtoAPP    = "APP"
	ProtoHTTP   = "HTTP"
	ProtoWS     = "WS"
	ProtoSDP    = "SDP"
	ProtoCRYPTO = "CRYPTO"
	ProtoUDP    = "UDP"
	ProtoSTUN   = "STUN"
	ProtoDTLS   = "DTLS"
	ProtoRTP    = "RTP"
	ProtoSRTP   = "SRTP"
	ProtoRTCP   = "RTCP"
	ProtoVP8    = "VP8"
)

type ColorFunc func(format string, v ...interface{}) string

type LoggerLevel struct {
	logLevelPrefix string
	colorFunc      ColorFunc
}

func NewLoggerLevel(logLevelPrefix string, colorAttributes ...color.Attribute) *LoggerLevel {
	//Color module should be enabled, if you don't this, color module doesn't act as expected.
	color.NoColor = false
	return &LoggerLevel{
		logLevelPrefix: logLevelPrefix,
		colorFunc:      color.New(colorAttributes...).SprintfFunc(),
	}
}

func (l *LoggerLevel) processString(s string, colorFunc ColorFunc) string {
	startTag := "<u>"
	endTag := "</u>"
	for startIdx := strings.Index(s, startTag); startIdx > -1; startIdx = strings.Index(s, startTag) {
		endIdx := strings.Index(s, endTag)
		if endIdx < startIdx {
			//format = format[:startIdx] + format[startIdx+len(startTag):]
			panic(fmt.Errorf("format string is invalid: proper %s not found in: %s", endTag, s))
		} else {
			tagBody := s[startIdx+len(startTag) : endIdx]
			//We should recall colorFunc after application of another color function. Because underlinePrefixColor resets all formatting syntax.
			s = s[:startIdx] + underlinePrefixColor(tagBody) + colorFunc("%s", s[endIdx+len(endTag):])
		}
	}
	return s
}

func (l *LoggerLevel) printNow() string {
	now := time.Now() // get this early.
	year, month, day := now.Date()
	hour, min, sec := now.Clock()
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec)
}

func (l *LoggerLevel) Printf(protocolPrefix string, format string, v ...interface{}) {
	timeText := l.printNow()
	protocolText := ""
	if protocolPrefix != "" {
		protocolText = protocolPrefixColor("[%s]", protocolPrefix)
		for i := len(protocolPrefix); i < 6; i++ {
			protocolText = protocolText + " "
		}
	}
	bodyText := fmt.Sprintf(format, v...)

	for searchFor, replaceWith := range blacklist {
		bodyText = strings.ReplaceAll(bodyText, searchFor, replaceWith)
	}

	if l.logLevelPrefix != "" {
		bodyText = l.colorFunc("[%s] %s\n", l.logLevelPrefix, bodyText)
	} else {
		bodyText = l.colorFunc("%s\n", bodyText)
	}
	bodyText = l.processString(bodyText, l.colorFunc)
	fmt.Printf("%s %s %s", timeText, protocolText, bodyText)
}

func LineSpacer(lineCount int) {
	s := ""
	for i := 0; i < lineCount; i++ {
		s = s + "\n"
	}
	fmt.Print(s)
}

func AddToBlacklist(searchFor string, replaceWith string) {
	blacklist[searchFor] = replaceWith
}
