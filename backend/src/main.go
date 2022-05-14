// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/agent"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/conference"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/config"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/dtls"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/signaling"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/stun"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/udp"
)

var (
	conferenceManager *conference.ConferenceManager
)

func main() {
	//See: https://codewithyury.com/golang-wait-for-all-goroutines-to-finish/
	//See: https://www.geeksforgeeks.org/using-waitgroup-in-golang/
	waitGroup := new(sync.WaitGroup)

	logging.Freef("", "Welcome to WebRTC Nuts and Bolts!")
	logging.Freef("", "=================================")
	logging.Freef("", "You can trace these logs to understand the WebRTC processes and flows.")
	logging.LineSpacer(3)

	logging.Infof(logging.ProtoAPP, "Reading configuration file...")
	config.Load()

	if config.Val.Server.UDP.DockerHostIp != "" && config.Val.Server.MaskIpOnConsole {
		logging.AddToBlacklist(config.Val.Server.UDP.DockerHostIp, common.MaskIPString(config.Val.Server.UDP.DockerHostIp))
	}

	logging.Descf(logging.ProtoAPP, "Configuration content:\n%s", config.ToString())

	dtls.Init()

	discoveredServerIPs := discoverServerIPs()

	if config.Val.Server.MaskIpOnConsole {
		for _, ip := range discoveredServerIPs {
			logging.AddToBlacklist(ip, common.MaskIPString(ip))
		}
	}

	logging.Infof(logging.ProtoAPP, "Discovered IPs: [<u>%s</u>]", common.JoinSlice(", ", false, discoveredServerIPs...))
	logging.Descf(logging.ProtoAPP, "We looked to network device interfaces for IP addresses, and also asked \"what is my WAN IP?\" to the specified STUN server, via STUN protocol. Additionally, if defined, we add statically configured IP to the list. We use these IPs to create local ICE candidates (to say remote peers \"hey, I'm open to the network by these addresses and ports, maybe you can contact me by one of these IP-port pairs, I hope you can achieve with one of them.\").")

	conferenceManager = conference.NewConferenceManager(discoveredServerIPs, config.Val.Server.UDP.SinglePort)
	waitGroup.Add(1)
	go conferenceManager.Run(waitGroup)

	var udpListener = udp.NewUdpListener("0.0.0.0", config.Val.Server.UDP.SinglePort, conferenceManager)
	waitGroup.Add(1)
	go udpListener.Run(waitGroup)

	httpServer, err := signaling.NewHttpServer(fmt.Sprintf(":%d", config.Val.Server.Signaling.WsPort), conferenceManager)
	if err != nil {
		logging.Errorf(logging.ProtoAPP, "Http Server error: %s", err)
	}
	waitGroup.Add(1)
	go httpServer.Run(waitGroup)

	//We can run in an idle loop with calling last (httpServer's) Run function without go routine, but we want to see the sync.WaitGroup in action.
	time.Sleep(1 * time.Second)
	logging.Infof(logging.ProtoAPP, "Server components started...")
	logging.LineSpacer(2)
	waitGroup.Wait()
}

func discoverServerIPs() []string {
	localIPs := common.GetLocalIPs()
	result := []string{}
	result = append(result, localIPs...)

	if config.Val.Server.MaskIpOnConsole {
		for _, ip := range result {
			logging.AddToBlacklist(ip, common.MaskIPString(ip))
		}
	}

	logging.Infof(logging.ProtoAPP, "Discovered Local IPs: [<u>%s</u>]", common.JoinSlice(", ", false, result...))

	if config.Val.Server.UDP.DockerHostIp != "" {
		result = append(result, config.Val.Server.UDP.DockerHostIp)
		logging.Infof(logging.ProtoAPP, "Added configured IP statically (not discovered): <u>%s</u>", config.Val.Server.UDP.DockerHostIp)

	}

	logging.Infof(logging.ProtoAPP, "Creating STUN Client...")

	stunClientUfrag := agent.GenerateICEUfrag()
	stunClientPwd := agent.GenerateICEPwd()
	stunClient := stun.NewStunClient(config.Val.Server.StunServerAddr, stunClientUfrag, stunClientPwd)
	mappedAddress, err := stunClient.Discover()
	if err != nil {
		logging.Errorf(logging.ProtoAPP, "[STUN] Discovery error: %s", err)
		return result
	}
	externalIP := mappedAddress.IP.To4().String()
	if config.Val.Server.MaskIpOnConsole {
		logging.AddToBlacklist(externalIP, common.MaskIPString(externalIP))
	}
	logging.Infof(logging.ProtoAPP, "Discovered external IP from STUN server (<u>%s</u>) as <u>%s</u>", stunClient.ServerAddr, externalIP)

	result = append(result, externalIP)
	return result
}
