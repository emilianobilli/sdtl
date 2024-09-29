package sdtl

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	ConnectionClose     = 0
	HandShakeServerSent = 1
	ConnectionReady     = 2
)

type connection struct {
	publicKey *ecdsa.PublicKey
	encrypt   *aesCipher
	mtime     time.Time
	state     int
	session   [8]byte
	pubAddr   *net.UDPAddr
	priAddr   net.IP
}

type connTable struct {
	private map[uint32]*connection
	public  map[string]*connection
}

var instance *connTable
var once sync.Once

// GetInstance proporciona acceso a la única instancia de Singleton.
func getConnTable() *connTable {
	once.Do(func() {
		instance = &connTable{
			private: make(map[uint32]*connection),
			public:  make(map[string]*connection),
		}
	})
	return instance
}

func ipToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid address")
	}
	return binary.BigEndian.Uint32(ip), nil
}

func (c *connTable) addPrivate(ip net.IP, pubKey *ecdsa.PublicKey) error {
	u32, e := ipToUint32(ip)
	if e != nil {
		return e
	}

	client, ok := c.private[u32]
	if ok {
		return fmt.Errorf("duplicated entry")
	}

	client = &connection{}
	client.state = ConnectionClose
	client.publicKey = pubKey
	client.priAddr = ip
	c.private[u32] = client
	return nil
}

func (c *connTable) addPublic(addr *net.UDPAddr, conn *connection) {
	c.public[addr.String()] = conn
}

func (c *connTable) close(conn *connection) {
	if conn == nil {
		return
	}
	conn.encrypt = nil
	conn.mtime = time.Time{}
	conn.state = ConnectionClose
	if conn.pubAddr != nil {
		addr := conn.pubAddr.String()
		delete(c.public, addr)
		conn.pubAddr = nil
	}
	return
}

func (c *connTable) getConnectionByPublic(addr *net.UDPAddr) (*connection, error) {
	client, ok := c.public[addr.String()]
	if ok {
		return client, nil
	}
	return nil, fmt.Errorf("not found")
}

func (c *connTable) getConnectionByPrivate(ip net.IP) (*connection, error) {
	u32, e := ipToUint32(ip)
	if e != nil {
		return nil, e
	}
	client, ok := c.private[u32]
	if ok {
		return client, nil
	}
	return nil, fmt.Errorf("not found")
}
