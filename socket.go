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
	laddr     *net.UDPAddr
	raddr     *net.UDPAddr
	conn      *net.UDPConn
	connected bool
	session   [8]byte
	encrypt   *aesCipher
}

func (c *Socket) packHandShakeMessage(msgType uint, msg handShakeInterface) ([]byte, error) {
	pack := make([]byte, 2+msg.size())
	body, err := msg.dump(c.signerkey)
	if err != nil {
		return nil, err
	}
	pack[0] = ProtocolVer
	pack[1] = byte(msgType)
	copy(pack[2:], body)
	return pack, nil
}

func NewSocket(address string, key *ecdsa.PrivateKey) (*Socket, error) {
	var (
		s Socket
		e error
	)
	if address != "" {
		s.laddr, e = net.ResolveUDPAddr("udp4", address)
		if e != nil {
			return nil, e
		}
	}
	s.signerkey = key
	return &s, nil
}

func (s *Socket) Connect(address string, key *ecdsa.PublicKey) error {
	var (
		e error
	)
	if address == "" {
		return fmt.Errorf("invalid address value")
	}

	s.raddr, e = net.ResolveUDPAddr("udp4", address)
	if e != nil {
		return e
	}

	s.verifykey = key

	s.conn, e = net.ListenUDP("udp4", s.laddr)
	if e != nil {
		return e
	}
	if s.laddr == nil {
		s.laddr = s.conn.LocalAddr().(*net.UDPAddr)
	}

	s.session = createRandomSession()
	fmt.Println("Session: ", s.session)
	e = s.handShakeClient()
	if e != nil {
		s.conn.Close()
	}

	return e
}

func (s *Socket) Accept(address string, key *ecdsa.PublicKey) error {
	var (
		e error
	)

	if address != "" {
		s.raddr, e = net.ResolveUDPAddr("udp4", address)
		if e != nil {
			return e
		}
	}

	s.verifykey = key
	s.conn, e = net.ListenUDP("udp4", s.laddr)
	if e != nil {
		return e
	}
	// Server Handshake
	e = s.handShakeServer()
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
	pkg, err := s.packHandShakeMessage(startHandShakeMsg, &start)
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
			fmt.Println(data, addr, err)
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
			if data[0] != ProtocolVer || data[1] != serverHandShakeMsg {
				continue
			}
			// Drop Message
			err = hsmsg.load(s.verifykey, data[2:])
			fmt.Println("Cliente: ", err)
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
	fmt.Println("Cliente Secret: ", err)
	if err != nil {
		return err
	}

	// Store the public key
	hsmsg.session = s.session
	copy(hsmsg.epk[:], s.encrypt.PublicKey())

	hsmsg.signature = [64]byte{}
	pkg, err = s.packHandShakeMessage(clientHandShakeMsg, &hsmsg)
	if err != nil {
		return err
	}
	_, err = s.conn.WriteToUDP(pkg, s.raddr)
	return err
}

func (s *Socket) handShakeServer() error {
	var (
		start startHandShake
		hsmsg handShake
		err   error
	)

	success := false
	for !success {
		data, addr, err := s.readFromUDP()
		fmt.Println("Server: ", data, addr, err)
		if err != nil {
			return err
		}
		if data[0] != ProtocolVer || data[1] != startHandShakeMsg {
			continue
		}

		err = start.load(s.verifykey, data[2:])
		if err != nil {
			continue
		}

		success = true
		s.session = start.session
		if s.raddr == nil {
			s.raddr = addr
		}
	}

	hsmsg.session = s.session
	s.encrypt, err = newCipher()
	copy(hsmsg.epk[:], s.encrypt.PublicKey())

	pkt, err := s.packHandShakeMessage(serverHandShakeMsg, &hsmsg)
	if err != nil {
		return nil
	}
	success = false
	timeout := time.Second
	// 1 Sec of tollerance
	s.conn.SetReadDeadline(time.Now().Add(timeout))
	for tries := 3; tries > 0 && !success; tries-- {
		_, err = s.conn.WriteToUDP(pkt, s.raddr)
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
			if data[1] != clientHandShakeMsg {
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

	err = s.encrypt.SharedSecret(hsmsg.epk[:])
	return err
}

func (s *Socket) Send(data []byte) error {
	var buffer [2048]byte

	buffer[0] = ProtocolVer
	buffer[1] = dataFrameMsg

	tmp, err := dumpDataFrame(s.encrypt, data)
	if err != nil {
		return err
	}

	copy(buffer[2:], tmp)
	_, err = s.conn.WriteToUDP(buffer[:len(tmp)+2], s.raddr)
	return err
}

func (s *Socket) Recv() ([]byte, error) {
	var buffer [2048]byte

	n, addr, err := s.conn.ReadFromUDP(buffer[:])
	if err != nil {
		return nil, err
	}
	if addr.String() != s.raddr.String() {
		return nil, nil
	}

	if buffer[0] != ProtocolVer || buffer[1] != dataFrameMsg {
		return nil, nil
	}

	tmp, err := loadDataFrame(s.encrypt, buffer[2:n])
	if err != nil {
		return nil, err
	}

	return tmp, nil
}
