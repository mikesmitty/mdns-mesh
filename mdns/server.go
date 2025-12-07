package mdns

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/denisbrodbeck/machineid"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipv4mdns = "224.0.0.251"
	ipv6mdns = "ff02::fb"
	mdnsPort = 5353
	bufSize  = 65536
)

type Config struct {
	AllowFilter []string
	DenyFilter  []string
	DenyIP      []string
	FilterTTL   int
	HighPort    bool
	ListenIP    string
	Monitor     []string
	PortFilter  []string
	Server      *url.URL
	Topic       string
	UniqueID    string
}

type Server struct {
	config   Config
	uniqueID string

	ipv4CMs  []*ipv4.ControlMessage
	ipv4Dst  *net.UDPAddr
	ipv4High *ipv4.PacketConn
	ipv4Low  *ipv4.PacketConn

	ipv6Dst  *net.UDPAddr
	ipv6High *ipv6.PacketConn
	ipv6Low  *ipv6.PacketConn

	filterDeny  bool
	filterRegex []*regexp.Regexp
	portRegex   []*regexp.Regexp
	client      mqtt.Client
	wg          sync.WaitGroup
}

type Msg struct {
	Sender string
	Data   []byte
}

func StartServer(config Config) error {
	uniqueID, err := getUniqueID(config)
	if err != nil {
		return err
	}

	portRegex, filterRegex, filterDeny, err := getRegexFilters(config)
	if err != nil {
		return err
	}

	ifs, err := getInterfaces(config)
	if err != nil {
		return err
	}

	cms, err := getCM4(config, ifs)
	if err != nil {
		return err
	}

	ipv4Low, err := listener4(config, ifs, mdnsPort)
	if err != nil {
		return err
	}
	ipv4High, err := listener4(config, ifs, 0)
	if err != nil {
		return err
	}

	ipv4Dst := &net.UDPAddr{
		IP:   net.ParseIP(ipv4mdns),
		Port: 5353,
	}

	s := &Server{
		config:      config,
		filterDeny:  filterDeny,
		filterRegex: filterRegex,
		ipv4CMs:     cms,
		ipv4Dst:     ipv4Dst,
		ipv4High:    ipv4High,
		ipv4Low:     ipv4Low,
		portRegex:   portRegex,
		uniqueID:    uniqueID,
	}

	c, err := s.connect(uniqueID, config.Server)
	if err != nil {
		return err
	}
	s.client = c

	if ipv4Low != nil {
		s.wg.Add(1)
		go s.receive(ipv4Low)
	}

	if ipv4High != nil {
		s.wg.Add(1)
		go s.receive(ipv4High)
	}

	s.wg.Wait()

	return nil
}

func (s *Server) onConnect(c mqtt.Client) {
	log.Info("Connected to MQTT server")
	token := c.Subscribe(s.config.Topic, 0, s.send)
	if token.Wait() && token.Error() != nil {
		log.Errorf("Error subscribing to topic %s: %v", s.config.Topic, token.Error())
	} else {
		log.Infof("Subscribed to topic: %s", s.config.Topic)
	}
}

func (s *Server) onConnectionLost(c mqtt.Client, err error) {
	log.Warnf("Connection to MQTT server lost: %v", err)
}

// Check filters to deny messages in from/out to the wire
func (s *Server) discardMessage(msg dns.Msg) bool {
	if s.filterDeny && labelMatch(msg, s.filterRegex) {
		log.Debug("Deny filter discarding message")
		log.Tracef("Deny filter discarding message: %+v", msg)
		return true
	} else if len(s.filterRegex) > 0 && !labelMatch(msg, s.filterRegex) {
		log.Debug("No allow filter match, discarding message")
		log.Tracef("No allow filter match, discarding message: %+v", msg)
		return true
	}

	return false
}

// Start loop to pull multicast broadcasts off the wire and send them to MQTT
func (s *Server) receive(p *ipv4.PacketConn) {
	defer s.wg.Done()

	for {
		b := make([]byte, bufSize)
		n, cm, _, err := p.ReadFrom(b)
		if err != nil {
			log.Errorf("Error reading packet from wire: %v", err)
			continue
		}

		if cm == nil {
			log.Error("Received no ControlMessage from packet")
			continue
		}

		if cm.TTL == s.config.FilterTTL {
			log.Debug("Discarding packet with filter TTL")
			log.Tracef("Discarding packet with filter TTL: %+v\n", cm)
			continue
		}

		if ipDenied(cm.Src, s.config.DenyIP) {
			log.Debugf("Discarding packet from denied IP: %s", cm.Src)
			log.Tracef("Discarding packet from denied IP: %+v\n", cm)
			continue
		}

		msg := dns.Msg{}
		err = msg.Unpack(b[:n])
		if err != nil {
			log.Warnf("Error parsing packet from wire: %v", err)
		}
		log.Tracef("Received message from wire: %+v", msg)

		if s.discardMessage(msg) {
			log.Debugf("Discarding message from wire: %s", cm.Src)
			continue
		}

		jsonMsg, err := json.Marshal(Msg{Sender: s.uniqueID, Data: b[:n]})
		if err != nil {
			log.Errorf("Error marshalling message from wire: %v", err)
		}
		s.client.Publish(s.config.Topic, 0, false, jsonMsg)
		log.Debug("Sent message to mesh")
	}
}

// Accept messages from NATS and send them out on the wire
func (s *Server) send(client mqtt.Client, msg mqtt.Message) {
	m := Msg{}
	err := json.Unmarshal(msg.Payload(), &m)
	if err != nil {
		log.Errorf("Error unmarshalling message from mesh: %v", err)
		return
	}

	if m.Sender == s.uniqueID {
		log.Debug("Ignoring mesh message from self")
		return
	}

	dm := dns.Msg{}
	err = dm.Unpack(m.Data)
	if err != nil {
		log.Warnf("Error parsing mesh packet: %v", err)
		return
	}

	if s.discardMessage(dm) {
		log.Debugf("Discarding message from sender: %s", m.Sender)
		return
	}

	var p *ipv4.PacketConn
	match := labelMatch(dm, s.portRegex)
	if (s.config.HighPort && match) || (!s.config.HighPort && !match) {
		p = s.ipv4Low
		log.Debugf("Mesh message to low port, from sender: %s", m.Sender)
	} else {
		p = s.ipv4High
		log.Debugf("Mesh message to high port, from sender: %s", m.Sender)
	}

	for _, cm := range s.ipv4CMs {
		if _, err := p.WriteTo(m.Data, cm, s.ipv4Dst); err != nil {
			log.Errorf("Unable to send broadcast to wire: %v", err)
		}
	}

	log.Tracef("Rebroadcast message to wire: %+v", msg)
}

func (s *Server) connect(clientId string, uri *url.URL) (mqtt.Client, error) {
	opts := createClientOptions(clientId, uri, s.onConnect, s.onConnectionLost)
	client := mqtt.NewClient(opts)
	token := client.Connect()
	for !token.WaitTimeout(3 * time.Second) {
	}
	if err := token.Error(); err != nil {
		return nil, err
	}
	return client, nil
}

func createClientOptions(clientId string, uri *url.URL, onConnect mqtt.OnConnectHandler, onConnectionLost mqtt.ConnectionLostHandler) *mqtt.ClientOptions {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s", uri.Host))
	opts.SetUsername(uri.User.Username())
	password, _ := uri.User.Password()
	opts.SetPassword(password)
	opts.SetClientID(clientId)
	opts.SetOnConnectHandler(onConnect)
	opts.SetConnectionLostHandler(onConnectionLost)
	return opts
}

// Compile the high/low port filters and allow/deny list filters
func getRegexFilters(config Config) (portRegex []*regexp.Regexp, filterRegex []*regexp.Regexp, filterDeny bool, err error) {
	if len(config.AllowFilter) > 0 && len(config.DenyFilter) > 0 {
		return nil, nil, false, fmt.Errorf("allow-filter and deny-filter cannot be used together")
	}

	var r *regexp.Regexp
	for _, filter := range config.PortFilter {
		r, err = regexp.Compile(filter)
		if err != nil {
			err = fmt.Errorf("error compiling port-filter regex '%s': %v", filter, err)
			return
		}

		portRegex = append(portRegex, r)
	}

	var filters []string
	if len(config.DenyFilter) > 0 {
		filters = config.DenyFilter
		filterDeny = true
	} else {
		filters = config.AllowFilter
	}

	for _, filter := range filters {
		r, err = regexp.Compile(filter)
		if err != nil {
			err = fmt.Errorf("error compiling filter regex '%s': %v", filter, err)
			return
		}

		filterRegex = append(filterRegex, r)
	}

	return
}

// Get a unique ID so we don't repeat our own traffic
func getUniqueID(config Config) (string, error) {
	if config.UniqueID != "" {
		log.Warn("Using provided unique sender ID. If shared with other instances this could cause a self-DoS")
		return config.UniqueID, nil
	}

	uniqueID, err := machineid.ID()
	if uniqueID == "" || err != nil {
		log.Info("No machine id found, using hostname as sender id")

		uniqueID, err = os.Hostname()
		if uniqueID == "" || err != nil {
			log.Fatal("Unable to get machine id or hostname for use as sender id. Please provide a UniqueID")
			return "", err
		}
	}

	return uniqueID, nil
}

// Check if IP is on the deny list
func ipDenied(ip net.IP, ips []string) bool {
	for i := range ips {
		if ip.String() == ips[i] {
			return true
		}
	}

	return false
}

// Check if the DNS labels (question/answer name(s)) match our regex filters
func labelMatch(msg dns.Msg, regex []*regexp.Regexp) bool {
	for _, r := range regex {
		for _, q := range msg.Question {
			name := strings.TrimSuffix(q.Name, ".")
			if r.MatchString(name) {
				return true
			}
		}
		for _, a := range msg.Answer {
			name := strings.TrimSuffix(a.Header().Name, ".")
			if r.MatchString(name) {
				return true
			}
		}
	}

	return false
}
