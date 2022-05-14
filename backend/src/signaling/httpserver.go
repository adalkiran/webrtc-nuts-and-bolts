package signaling

import (
	"net/http"
	"sync"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/conference"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type HttpServer struct {
	HttpServerAddr string
	WsHub          *WsHub
}

func NewHttpServer(httpServerAddr string, conferenceManager *conference.ConferenceManager) (*HttpServer, error) {
	wsHub := newWsHub(conferenceManager)

	httpServer := &HttpServer{
		HttpServerAddr: httpServerAddr,
		WsHub:          wsHub,
	}
	http.HandleFunc("/", httpServer.serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		httpServer.serveWs(w, r)
	})

	return httpServer, nil
}

func (s *HttpServer) Run(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	go s.WsHub.run()
	logging.Infof(logging.ProtoWS, "WebSocket Server started on <u>%s</u>", s.HttpServerAddr)
	logging.Descf(logging.ProtoWS, "Clients should make first contact with this WebSocket (the Signaling part)")
	err := http.ListenAndServe(s.HttpServerAddr, nil)
	if err != nil {
		panic(err)
	}
}

func (s *HttpServer) serveHome(w http.ResponseWriter, r *http.Request) {
	logging.Infof(logging.ProtoHTTP, "Request: <u>%s</u>", r.URL)
	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "home.html")
}

// serveWs handles websocket requests from the peer.
func (s *HttpServer) serveWs(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.Errorf(logging.ProtoHTTP, "Error: %s", err)
		return
	}
	client := &WsClient{wsHub: s.WsHub, conn: conn, send: make(chan []byte, 256)}
	client.wsHub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}
