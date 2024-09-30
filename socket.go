package sdtl

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"
)

type Socket struct {
	signerkey *ecdsa.PrivateKey
	verifykey *ecdsa.PublicKey
	raddr     *net.UDPAddr
	conn      *net.UDPConn
	ip        net.IP
	connected bool
	session   [8]byte
	encrypt   *aesCipher
}

func packHandShakeMessage(signerkey *ecdsa.PrivateKey, msgType uint, msg handShakeInterface) ([]byte, error) {
	pack := make([]byte, 2+msg.size())
	body, err := msg.dump(signerkey)
	if err != nil {
		return nil, err
	}
	pack[0] = ProtocolVer
	pack[1] = byte(msgType)
	copy(pack[2:], body)
	return pack, nil
}

func (c *Socket) packHandShakeMessage(msgType uint, msg handShakeInterface) ([]byte, error) {
	return packHandShakeMessage(c.signerkey, msgType, msg)
}

func NewSocketClient(key *ecdsa.PrivateKey) (*Socket, error) {
	return newSocket(key)
}

func newSocket(key *ecdsa.PrivateKey) (*Socket, error) {
	var (
		s Socket
	)
	s.signerkey = key
	return &s, nil
}

func (s *Socket) Connect(to string, key *ecdsa.PublicKey, ip string) error {
	var (
		e error
	)
	if to == "" {
		return fmt.Errorf("invalid address value")
	}

	s.raddr, e = net.ResolveUDPAddr("udp4", to)
	if e != nil {
		return e
	}

	s.verifykey = key
	s.conn, e = net.ListenUDP("udp4", nil)
	if e != nil {
		return e
	}
	s.ip = net.ParseIP(ip)
	s.session = createRandomSession()
	e = s.handShakeClient()
	if e != nil {
		s.conn.Close()
	}

	return e
}

func (s *Socket) readFromUDP() ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 2048)
	n, addr, e := s.conn.ReadFromUDP(buf)
	if e != nil {
		return nil, addr, e
	}

	return buf[:n], addr, nil
}

func (s *Socket) handShakeClient() error {
	var (
		start startHandShake
		hsmsg handShake
	)

	start.session = s.session
	copy(start.ip[:], s.ip.To4())
	pkg, err := s.packHandShakeMessage(msgSTR, &start)
	if err != nil {
		return err
	}
	success := false
	timeout := time.Second
	// 1 Sec of tollerance
	s.conn.SetReadDeadline(time.Now().Add(timeout))
	for tries := 3; tries > 0 && !success; tries-- {
		_, err = s.conn.WriteToUDP(pkg, s.raddr)
		if err != nil {
			return err
		}

		for {
			data, addr, err := s.readFromUDP()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Stablish again 1 sec of tolerance
					timeout *= 2
					s.conn.SetReadDeadline(time.Now().Add(timeout))
					break
				}
				return err
			}

			// Drop Message
			if data[0] != ProtocolVer || data[1] != msgSHS {
				continue
			}
			// Drop Message
			err = hsmsg.load(s.verifykey, data[2:])
			if err != nil || hsmsg.session != s.session || addr.String() != s.raddr.String() {
				continue
			}
			// Clean the Deadline
			s.conn.SetReadDeadline(time.Time{})
			success = true
			break
		}
	}
	if !success {
		return fmt.Errorf("handshake timeout")
	}

	s.encrypt, err = newCipher()
	if err != nil {
		return err
	}

	err = s.encrypt.SharedSecret(hsmsg.epk[:])
	if err != nil {
		return err
	}

	// Store the public key
	hsmsg.session = s.session
	copy(hsmsg.epk[:], s.encrypt.PublicKey())

	hsmsg.signature = [64]byte{}
	pkg, err = s.packHandShakeMessage(msgCHS, &hsmsg)
	if err != nil {
		return err
	}
	_, err = s.conn.WriteToUDP(pkg, s.raddr)
	return err
}

func (s *Socket) Write(data []byte) (int, error) {
	var buffer [2048]byte

	buffer[0] = ProtocolVer
	buffer[1] = msgDFE
	tmp, err := dumpDataFrame(s.encrypt, data)
	if err != nil {
		return 0, err
	}

	copy(buffer[2:], tmp)
	_, err = s.conn.WriteToUDP(buffer[:len(tmp)+2], s.raddr)
	return len(tmp), err
}

func (s *Socket) Read(buffer []byte) (int, error) {

	for {
		n, addr, err := s.conn.ReadFromUDP(buffer[:])
		if err != nil {
			return 0, err
		}
		if addr.String() != s.raddr.String() {
			continue // Drop
		}

		if buffer[0] != ProtocolVer || buffer[1] != msgDFE {
			continue // Drop
		}

		tmp, err := loadDataFrame(s.encrypt, buffer[2:n])
		if err != nil {
			return 0, err
		}
		copy(buffer[0:len(tmp)], tmp)
		return len(tmp), nil
	}
}
