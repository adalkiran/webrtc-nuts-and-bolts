type MediaType = 'audio' | 'video'
type CandidateType = 'host'
type TransportType = 'udp' | 'tcp'
type FingerprintType = 'sha-256'


class SdpMessage {
	sessionId:  string  
	mediaItems: SdpMedia[]
}

class SdpMedia {
    mediaId: number
	type: MediaType
	ufrag: string              
	pwd: string              
	fingerprintType: FingerprintType    
	fingerprintHash: string        
	candidates: SdpMediaCandidate[]
	payloads: string
	rtpCodec: string
}

class SdpMediaCandidate {
	ip:        string
    port:      number
	type:      CandidateType
	transport: TransportType
}

export {SdpMessage}