package sdtl

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type IOMessage struct {
	addr   *net.UDPAddr
	n      int
	buffer [2048]byte
	err    error
}

func createRcv(udp *net.UDPConn) <-chan *IOMessage {
	io := make(chan *IOMessage, 10)
	go func() {
		var buf [2048]byte
		for {
			n, a, e := udp.ReadFromUDP(buf[:])
			if e != nil {
				msg := &IOMessage{
					err: e,
				}
				io <- msg
				break
			}
			msg := &IOMessage{
				addr: a,
				n:    n,
			}
			copy(msg.buffer[:], buf[:n])
			io <- msg
		}
		io <- nil
	}()
	return io
}

func createSnd(udp *net.UDPConn) chan<- *IOMessage {
	io := make(chan *IOMessage)
	go func() {
		for {
			msg := <-io
			if msg == nil {
				break
			}
			udp.WriteToUDP(msg.buffer[:msg.n], msg.addr)
		}
	}()
	return io
}

func errorf(where string, message string, encap error) error {
	return fmt.Errorf("in %s: %s, %v", where, message, encap)
}

func routeMsg(msg *IOMessage) (*IOMessage, error) {
	ct := getConnTable()

	conn, e := ct.getConnectionByPublic(msg.addr)

	if e != nil || conn.state != ConnectionReady || conn.encrypt == nil {
		return nil, errorf("routeMsg", "invalid state", e)
	}

	b, e := loadDataFrame(conn.encrypt, msg.buffer[2:msg.n])
	if e != nil {
		return nil, errorf("routeMsg", "invalid message", e)
	}
	fmt.Println(b)
	iphdr, e := ipv4.ParseHeader(b)
	if e != nil {
		return nil, errorf("routeMsg", "invalid encapsulated message", e)
	}
	conn.mtime = time.Now()
	conn, e = ct.getConnectionByPrivate(iphdr.Dst)
	if e != nil || conn.state != ConnectionReady || conn.encrypt == nil || conn.pubAddr == nil {
		return nil, errorf("routeMsg", "not route to host", e)
	}
	msg.buffer[0] = ProtocolVer
	msg.buffer[1] = msgDFE
	tmp, e := dumpDataFrame(conn.encrypt, b)
	if e != nil {
		return nil, errorf("routeMsg", "impossible dump message", e)
	}
	copy(msg.buffer[2:], tmp)
	msg.n = len(tmp) + 2
	msg.addr = conn.pubAddr
	return msg, nil
}

func handleSTR(signkey *ecdsa.PrivateKey, msg *IOMessage) (*IOMessage, error) {
	var (
		start startHandShake
		hsmsg handShake
	)
	ct := getConnTable()
	ip := extractIP(msg.buffer[2:])
	fmt.Println(ip)
	conn, e := ct.getConnectionByPrivate(ip)
	if e != nil {
		return nil, errorf("handleSTR", "private address not found", e)
	}

	if conn.publicKey == nil {
		return nil, errorf("handleSTR", "public ket not found", nil)
	}

	e = start.load(conn.publicKey, msg.buffer[2:])
	if e != nil {
		return nil, errorf("handleSTR", "loading message", e)
	}

	conn.encrypt, e = newCipher()
	if e != nil {
		return nil, errorf("handleSTR", "creating a new cipher", e)
	}
	conn.session = start.session
	conn.pubAddr = msg.addr
	hsmsg.session = start.session
	copy(hsmsg.epk[:], conn.encrypt.PublicKey())
	data, e := packHandShakeMessage(signkey, msgSHS, &hsmsg)
	if e != nil {
		conn.session = [8]byte{}
		conn.encrypt = nil
		conn.pubAddr = nil
		return nil, errorf("handleSTR", "impossible to pack message", e)
	}
	conn.state = HandShakeServerSent
	conn.mtime = time.Now()
	ct.addPublic(msg.addr, conn)
	copy(msg.buffer[:len(data)], data)
	msg.n = len(data)
	return msg, nil
}

func handleCHS(msg *IOMessage) error {
	var (
		hsmsg handShake
	)

	ct := getConnTable()

	conn, e := ct.getConnectionByPublic(msg.addr)
	if e != nil {
		return fmt.Errorf("handleCHS(); public connection not found")
	}
	if conn.state != HandShakeServerSent {
		return fmt.Errorf("handleCHS(): received a CHS in a different state: %d", conn.state)
	}
	e = hsmsg.load(conn.publicKey, msg.buffer[2:])
	if e != nil || hsmsg.session != conn.session {
		return fmt.Errorf("handleCHS(): invalid session - error(%v)", e)
	}
	e = conn.encrypt.SharedSecret(hsmsg.epk[:])
	if e != nil {
		return fmt.Errorf("handleCHS(): creating shared secret - error(%v)", e)
	}
	conn.state = ConnectionReady
	return nil
}

func log(format string, v ...interface{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf("[%s] %s", currentTime, fmt.Sprintf(format, v...))
	fmt.Println(message)
}

func (s *Server) ListenAndServe() {
	var (
		err error
	)
	recv := createRcv(s.udp)
	send := createSnd(s.udp)

	for {
		msg := <-recv
		if msg.err != nil {
			log("ERROR: fatal error: %v - Exit", msg.err)
			break
		}
		if msg.buffer[0] != ProtocolVer {
			log("ERROR: protocol missmatch from %s - Drop", msg.addr.String())
			continue
		}
		switch msg.buffer[1] {
		case msgSTR:
			log("INFO: Start Handshake from: %s", msg.addr.String())
			msg, err = handleSTR(s.priKey, msg)
		case msgCHS:
			log("INFO: Client Handshake from: %s", msg.addr.String())
			err = handleCHS(msg)
			msg = nil
		case msgDFE:
			// Data Frame Encripted
			msg, err = routeMsg(msg)

		}

		if err != nil {
			log("ERROR: message %v - Drop", err)
		}

		if msg != nil {
			send <- msg
		}

	}
	send <- nil
	<-recv // Waiting end
}

type Server struct {
	udp    *net.UDPConn
	priKey *ecdsa.PrivateKey
}

func SDTLServer(config string) (*Server, error) {
	cfg, err := ParseConfig(config)
	if err != nil {
		return nil, err
	}

	pk, err := PrivateFromPemFile(cfg.Server.PrivateKey)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", cfg.Server.Listen, cfg.Server.Port))
	if err != nil {
		return nil, err
	}

	c, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	ct := getConnTable()
	for _, host := range cfg.Hosts {
		pb, e := PublicKeyFromPemFile(host.PublicKey)
		if e != nil {
			return nil, e
		}
		ip := net.ParseIP(host.IP)
		ct.addPrivate(ip, pb)
	}
	return &Server{
		udp:    c,
		priKey: pk,
	}, nil
}
