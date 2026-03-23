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
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"maxss/internal/protocol"
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
	target, err := socksHandshake(conn)
	if err != nil {
		return err
	}

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

func socksHandshake(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", errors.New("unsupported socks version")
	}
	nMethods := int(head[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHead); err != nil {
		return "", err
	}
	if reqHead[0] != 0x05 || reqHead[1] != 0x01 {
		return "", errors.New("only CONNECT command is supported")
	}

	atyp := reqHead[3]
	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			return "", err
		}
		domain := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		return "", errors.New("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}
