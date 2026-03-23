package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"maxss/internal/protocol"
)

const (
	socksCmdConnect      byte = 0x01
	socksCmdUDPAssociate byte = 0x03
)

type Options struct {
	ListenAddr string
	ServerAddr string
	SNI        string
	Path       string
	Username   string
	Password   string
	ConfigName string
	Insecure   bool
}

type tunnel struct {
	ws      *websocket.Conn
	session *protocol.SessionCipher
	wmu     sync.Mutex
}

type socksRequest struct {
	cmd    byte
	target string
}

func Run(opts Options) error {
	return RunWithContext(context.Background(), opts)
}

func RunWithContext(ctx context.Context, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:1080"
	}
	if opts.Path == "" {
		opts.Path = "/.well-known/maxss"
	}
	if opts.ConfigName == "" {
		opts.ConfigName = "Secure Config"
	}
	if opts.ServerAddr == "" || opts.Username == "" || opts.Password == "" {
		return errors.New("server, username and password are required")
	}

	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("maxss local SOCKS5 on %s", opts.ListenAddr)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := handleSOCKSConn(c, opts); err != nil {
				log.Printf("socks connection error: %v", err)
			}
		}(conn)
	}
}

func handleSOCKSConn(conn net.Conn, opts Options) error {
	req, err := socksHandshake(conn)
	if err != nil {
		return err
	}
	switch req.cmd {
	case socksCmdConnect:
		return handleSOCKSTCP(conn, opts, req.target)
	case socksCmdUDPAssociate:
		return handleSOCKSUDP(conn, opts)
	default:
		return errors.New("unsupported socks command")
	}
}

func handleSOCKSTCP(conn net.Conn, opts Options, target string) error {
	t, err := dialTunnel(opts, target)
	if err != nil {
		return err
	}
	defer t.ws.Close()

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if err := t.send(protocol.MsgData, buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				_ = t.send(protocol.MsgClose, nil)
				return
			}
		}
	}()

	for {
		_, frame, err := t.ws.ReadMessage()
		if err != nil {
			break
		}
		plain, err := t.session.Decrypt(frame)
		if err != nil {
			break
		}
		typ, payload, err := protocol.DecodeMessage(plain)
		if err != nil {
			break
		}
		switch typ {
		case protocol.MsgData:
			if len(payload) > 0 {
				if _, err := conn.Write(payload); err != nil {
					return err
				}
			}
		case protocol.MsgClose:
			return nil
		case protocol.MsgError:
			return fmt.Errorf("server error: %s", string(payload))
		}
	}

	select {
	case <-done:
	default:
	}
	return nil
}

func handleSOCKSUDP(conn net.Conn, opts Options) error {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return err
	}
	defer udpLn.Close()

	local := udpLn.LocalAddr().(*net.UDPAddr)
	if err := writeSocksReply(conn, 0x00, local.IP, local.Port); err != nil {
		return err
	}

	stop := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(stop)
		_ = udpLn.Close()
	}()

	var clientAddrMu sync.RWMutex
	var clientAddr *net.UDPAddr

	tunnels := map[string]*tunnel{}
	var tunnelsMu sync.Mutex
	closeAll := func() {
		tunnelsMu.Lock()
		defer tunnelsMu.Unlock()
		for _, t := range tunnels {
			_ = t.ws.Close()
		}
		tunnels = map[string]*tunnel{}
	}
	defer closeAll()

	ensureTunnel := func(target string) (*tunnel, error) {
		tunnelsMu.Lock()
		t := tunnels[target]
		tunnelsMu.Unlock()
		if t != nil {
			return t, nil
		}

		t, err := dialTunnel(opts, "udp:"+target)
		if err != nil {
			return nil, err
		}

		tunnelsMu.Lock()
		tunnels[target] = t
		tunnelsMu.Unlock()

		go func(target string, t *tunnel) {
			for {
				_, frame, err := t.ws.ReadMessage()
				if err != nil {
					break
				}
				plain, err := t.session.Decrypt(frame)
				if err != nil {
					break
				}
				typ, payload, err := protocol.DecodeMessage(plain)
				if err != nil {
					break
				}
				switch typ {
				case protocol.MsgData:
					pkt, err := buildSocksUDPDatagram(target, payload)
					if err != nil {
						continue
					}
					clientAddrMu.RLock()
					ca := clientAddr
					clientAddrMu.RUnlock()
					if ca != nil {
						_, _ = udpLn.WriteToUDP(pkt, ca)
					}
				case protocol.MsgClose:
					return
				case protocol.MsgError:
					log.Printf("udp tunnel error %s: %s", target, string(payload))
				}
			}
			_ = t.ws.Close()
			tunnelsMu.Lock()
			if current, ok := tunnels[target]; ok && current == t {
				delete(tunnels, target)
			}
			tunnelsMu.Unlock()
		}(target, t)

		return t, nil
	}

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		clientAddrMu.Lock()
		clientAddr = addr
		clientAddrMu.Unlock()

		target, payload, err := parseSocksUDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		t, err := ensureTunnel(target)
		if err != nil {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if err := t.send(protocol.MsgData, payload); err != nil {
			_ = t.ws.Close()
			tunnelsMu.Lock()
			if current, ok := tunnels[target]; ok && current == t {
				delete(tunnels, target)
			}
			tunnelsMu.Unlock()
		}
	}
}

func dialTunnel(opts Options, target string) (*tunnel, error) {
	u := url.URL{Scheme: "wss", Host: opts.ServerAddr, Path: opts.Path}
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         opts.SNI,
			InsecureSkipVerify: opts.Insecure,
			NextProtos:         []string{"http/1.1"},
		},
		HandshakeTimeout: 10 * time.Second,
	}
	ws, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	priv, pub, err := protocol.GenerateX25519Key()
	if err != nil {
		ws.Close()
		return nil, err
	}
	salt, err := protocol.RandomSalt(32)
	if err != nil {
		ws.Close()
		return nil, err
	}
	req := protocol.HandshakeRequest{
		Version:    protocol.Version,
		Username:   opts.Username,
		Password:   opts.Password,
		ConfigName: opts.ConfigName,
		ClientPub:  protocol.EncodePubB64(pub),
		Salt:       protocol.EncodeSaltB64(salt),
		Timestamp:  time.Now().Unix(),
	}
	b, _ := json.Marshal(req)
	if err := ws.WriteMessage(websocket.TextMessage, b); err != nil {
		ws.Close()
		return nil, err
	}

	_, respMsg, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return nil, err
	}
	var resp protocol.HandshakeResponse
	if err := json.Unmarshal(respMsg, &resp); err != nil {
		ws.Close()
		return nil, err
	}
	if !resp.OK {
		ws.Close()
		if resp.Error == "" {
			resp.Error = "handshake rejected"
		}
		return nil, errors.New(resp.Error)
	}

	peer, err := protocol.DecodePublicKey(resp.ServerPub)
	if err != nil {
		ws.Close()
		return nil, err
	}
	shared, err := protocol.DeriveShared(priv, peer)
	if err != nil {
		ws.Close()
		return nil, err
	}
	session, err := protocol.DeriveSessionCipher(shared, salt, opts.Username+"|"+opts.ConfigName, 32, 512)
	if err != nil {
		ws.Close()
		return nil, err
	}

	t := &tunnel{ws: ws, session: session}
	if err := t.send(protocol.MsgConnect, []byte(target)); err != nil {
		ws.Close()
		return nil, err
	}

	_, frame, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return nil, err
	}
	plain, err := session.Decrypt(frame)
	if err != nil {
		ws.Close()
		return nil, err
	}
	typ, payload, err := protocol.DecodeMessage(plain)
	if err != nil {
		ws.Close()
		return nil, err
	}
	if typ == protocol.MsgError {
		ws.Close()
		return nil, fmt.Errorf("connect failed: %s", string(payload))
	}
	if typ != protocol.MsgConnectOK {
		ws.Close()
		return nil, fmt.Errorf("unexpected response type: %d", typ)
	}
	return t, nil
}

func (t *tunnel) send(msgType byte, payload []byte) error {
	plain := protocol.EncodeMessage(msgType, payload)
	enc, err := t.session.Encrypt(plain)
	if err != nil {
		return err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_ = t.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return t.ws.WriteMessage(websocket.BinaryMessage, enc)
}

func socksHandshake(conn net.Conn) (socksRequest, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return socksRequest{}, err
	}
	if head[0] != 0x05 {
		return socksRequest{}, errors.New("unsupported socks version")
	}
	nMethods := int(head[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socksRequest{}, err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return socksRequest{}, err
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHead); err != nil {
		return socksRequest{}, err
	}
	if reqHead[0] != 0x05 {
		return socksRequest{}, errors.New("unsupported socks request")
	}
	cmd := reqHead[1]
	if cmd != socksCmdConnect && cmd != socksCmdUDPAssociate {
		return socksRequest{}, errors.New("unsupported socks command")
	}

	host, port, err := readSocksAddress(conn, reqHead[3])
	if err != nil {
		return socksRequest{}, err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if cmd == socksCmdConnect {
		if err := writeSocksReply(conn, 0x00, net.IPv4zero, 0); err != nil {
			return socksRequest{}, err
		}
	}
	return socksRequest{cmd: cmd, target: target}, nil
}

func readSocksAddress(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(r, ln); err != nil {
			return "", 0, err
		}
		domain := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, err
		}
		host = string(domain)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	default:
		return "", 0, errors.New("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return host, port, nil
}

func writeSocksReply(conn net.Conn, rep byte, bindIP net.IP, bindPort int) error {
	if bindIP == nil {
		bindIP = net.IPv4zero
	}
	if ip4 := bindIP.To4(); ip4 != nil {
		reply := make([]byte, 10)
		reply[0] = 0x05
		reply[1] = rep
		reply[2] = 0x00
		reply[3] = 0x01
		copy(reply[4:8], ip4)
		binary.BigEndian.PutUint16(reply[8:10], uint16(bindPort))
		_, err := conn.Write(reply)
		return err
	}
	ip16 := bindIP.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	reply := make([]byte, 22)
	reply[0] = 0x05
	reply[1] = rep
	reply[2] = 0x00
	reply[3] = 0x04
	copy(reply[4:20], ip16)
	binary.BigEndian.PutUint16(reply[20:22], uint16(bindPort))
	_, err := conn.Write(reply)
	return err
}

func parseSocksUDPDatagram(pkt []byte) (string, []byte, error) {
	if len(pkt) < 4 {
		return "", nil, errors.New("udp packet too short")
	}
	if pkt[0] != 0x00 || pkt[1] != 0x00 {
		return "", nil, errors.New("invalid udp rsv")
	}
	if pkt[2] != 0x00 {
		return "", nil, errors.New("fragmented udp is not supported")
	}
	atyp := pkt[3]
	i := 4
	var host string
	switch atyp {
	case 0x01:
		if len(pkt) < i+4+2 {
			return "", nil, errors.New("invalid ipv4 udp packet")
		}
		host = net.IP(pkt[i : i+4]).String()
		i += 4
	case 0x03:
		if len(pkt) < i+1 {
			return "", nil, errors.New("invalid domain udp packet")
		}
		dl := int(pkt[i])
		i++
		if len(pkt) < i+dl+2 {
			return "", nil, errors.New("invalid domain udp packet")
		}
		host = string(pkt[i : i+dl])
		i += dl
	case 0x04:
		if len(pkt) < i+16+2 {
			return "", nil, errors.New("invalid ipv6 udp packet")
		}
		host = net.IP(pkt[i : i+16]).String()
		i += 16
	default:
		return "", nil, errors.New("unsupported udp atyp")
	}
	port := binary.BigEndian.Uint16(pkt[i : i+2])
	i += 2
	payload := append([]byte(nil), pkt[i:]...)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, payload, nil
}

func buildSocksUDPDatagram(target string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	portN, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, 4+16+2)
	header = append(header, 0x00, 0x00, 0x00)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, 0x01)
			header = append(header, ip4...)
		} else {
			header = append(header, 0x04)
			header = append(header, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("udp host too long")
		}
		header = append(header, 0x03, byte(len(host)))
		header = append(header, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portN))
	header = append(header, portBytes...)

	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out, nil
}
