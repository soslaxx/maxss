package server

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"maxss/internal/auth"
	"maxss/internal/config"
	"maxss/internal/db"
	"maxss/internal/protocol"
	"maxss/internal/util"
)

type Manager struct {
	ConfigDir string
	DBPath    string
	CertDir   string

	store  *db.Store
	wg     sync.WaitGroup
	closed atomic.Bool
}

type runtimeServer struct {
	cfg    config.Config
	http   *http.Server
	active atomic.Int64
}

type wsWriter struct {
	conn  *websocket.Conn
	mu    sync.Mutex
	jitter int
}

func NewManager(configDir, dbPath, certDir string) (*Manager, error) {
	mrand.Seed(time.Now().UnixNano())
	store, err := db.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &Manager{
		ConfigDir: configDir,
		DBPath:    dbPath,
		CertDir:   certDir,
		store:     store,
	}, nil
}

func (m *Manager) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.wg.Wait()
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

func (m *Manager) Run(ctx context.Context) error {
	cfgs, err := config.LoadAll(m.ConfigDir)
	if err != nil {
		return err
	}
	if len(cfgs) == 0 {
		return errors.New("no config files found in configs directory")
	}

	servers := make([]*runtimeServer, 0, len(cfgs))
	for _, fc := range cfgs {
		cfg := fc.Config.Clone()
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			certFile, keyFile, err := util.EnsureSelfSignedCert(m.CertDir, cfg.Name, cfg.SNI)
			if err != nil {
				return err
			}
			cfg.TLS.CertFile = certFile
			cfg.TLS.KeyFile = keyFile
			if err := config.SaveConfig(fc.Path, cfg); err != nil {
				return err
			}
		}

		rs, err := m.buildServer(cfg)
		if err != nil {
			return fmt.Errorf("build server for %s: %w", cfg.Name, err)
		}
		servers = append(servers, rs)
	}

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		srv := s
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			log.Printf("maxss server [%s] listening on %s", srv.cfg.Name, srv.http.Addr)
			err := srv.http.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		for _, s := range servers {
			_ = s.http.Shutdown(context.Background())
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.http.Shutdown(shutdownCtx)
		}
		return nil
	}
}

func (m *Manager) buildServer(cfg config.Config) (*runtimeServer, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	alpn := cfg.Transport.ALPN
	if strings.EqualFold(strings.TrimSpace(cfg.Transport.Type), "tls-ws") {
		if len(alpn) != 1 || !strings.EqualFold(alpn[0], "http/1.1") {
			log.Printf("maxss [%s]: forcing ALPN to http/1.1 for tls-ws transport", cfg.Name)
		}
		alpn = []string{"http/1.1"}
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
		ServerName:   cfg.SNI,
	}
	mux := http.NewServeMux()
	rs := &runtimeServer{cfg: cfg}
	mux.HandleFunc(cfg.Transport.Path, m.handleTunnel(rs))
	mux.HandleFunc("/", decoyHandler(cfg.SNI))

	httpSrv := &http.Server{
		Addr:         net.JoinHostPort(cfg.Listen, fmt.Sprintf("%d", cfg.Port)),
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  time.Duration(cfg.Limits.IdleTimeoutSec) * time.Second,
	}
	rs.http = httpSrv
	return rs, nil
}

func decoyHandler(sni string) http.HandlerFunc {
	body := fmt.Sprintf("<!doctype html><html><head><title>%s</title></head><body>OK</body></html>", sni)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func (m *Manager) handleTunnel(rs *runtimeServer) http.HandlerFunc {
	cfg := rs.cfg
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		ReadBufferSize:  cfg.Transport.ReadBufferKB * 1024,
		WriteBufferSize: cfg.Transport.WriteBufferKB * 1024,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if rs.active.Load() >= int64(cfg.Limits.MaxConnections) {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadLimit(int64(cfg.Transport.MaxFrameKB * 1024 * 4))
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Limits.HandshakeTimeoutSec) * time.Second))

		_ = m.store.IncStat("total_connections", 1)
		_ = m.store.IncStat("active_connections", 1)
		rs.active.Add(1)
		defer func() {
			rs.active.Add(-1)
			_ = m.store.IncStat("active_connections", -1)
		}()

		username, session, err := m.performHandshake(conn, cfg)
		if err != nil {
			_ = m.store.IncStat("auth_failures", 1)
			_ = writeJSON(conn, protocol.HandshakeResponse{OK: false, Error: err.Error()})
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		bytesIn, bytesOut := m.relaySession(conn, session, cfg)
		_ = m.store.AddTraffic(username, bytesIn, bytesOut)
		_ = m.store.IncStat("bytes_in", bytesIn)
		_ = m.store.IncStat("bytes_out", bytesOut)
	}
}

func (m *Manager) performHandshake(conn *websocket.Conn, cfg config.Config) (string, *protocol.SessionCipher, error) {
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return "", nil, err
	}
	var req protocol.HandshakeRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return "", nil, errors.New("invalid handshake")
	}
	if req.Version != protocol.Version {
		return "", nil, fmt.Errorf("unsupported version %d", req.Version)
	}
	if !protocol.ValidateClientTimestamp(req.Timestamp, 2*time.Minute) {
		return "", nil, errors.New("handshake timestamp out of range")
	}

	allowed, user, err := m.store.IsUserAllowed(req.Username, cfg.Name)
	if err != nil {
		return "", nil, errors.New("invalid credentials")
	}
	if strings.TrimSpace(req.ConfigName) != "" && !strings.EqualFold(strings.TrimSpace(req.ConfigName), strings.TrimSpace(cfg.Name)) {
		return "", nil, errors.New("config mismatch for this endpoint")
	}
	if !allowed {
		return "", nil, errors.New("user not allowed for this config or expired/limited")
	}
	ok, err := auth.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil || !ok {
		return "", nil, errors.New("invalid credentials")
	}

	peer, err := protocol.DecodePublicKey(req.ClientPub)
	if err != nil {
		return "", nil, errors.New("invalid client key")
	}
	salt, err := protocol.DecodeSalt(req.Salt)
	if err != nil || len(salt) < 16 {
		return "", nil, errors.New("invalid salt")
	}

	priv, pub, err := protocol.GenerateX25519Key()
	if err != nil {
		return "", nil, err
	}
	shared, err := protocol.DeriveShared(priv, peer)
	if err != nil {
		return "", nil, err
	}
	contextLabel := strings.ToLower(strings.TrimSpace(req.Username)) + "|" + cfg.Name
	session, err := protocol.DeriveSessionCipher(shared, salt, contextLabel, cfg.Obfuscation.PaddingMin, cfg.Obfuscation.PaddingMax)
	if err != nil {
		return "", nil, err
	}

	resp := protocol.HandshakeResponse{
		OK:        true,
		ServerPub: protocol.EncodePubB64(pub),
		SessionID: newSessionID(),
		Features: []string{
			"tls1.3",
			"x25519",
			"hkdf-sha512",
			"aes-256-gcm",
			"xchacha20-poly1305",
			"hmac-sha3-256",
			"blake2b-mask",
			"udp-relay",
		},
	}
	if err := writeJSON(conn, resp); err != nil {
		return "", nil, err
	}
	return req.Username, session, nil
}

func (m *Manager) relaySession(conn *websocket.Conn, session *protocol.SessionCipher, cfg config.Config) (bytesIn, bytesOut int64) {
	writer := &wsWriter{conn: conn, jitter: cfg.Obfuscation.JitterMS}

	_, firstFrame, err := conn.ReadMessage()
	if err != nil {
		return 0, 0
	}
	plain, err := session.Decrypt(firstFrame)
	if err != nil {
		return 0, 0
	}
	msgType, payload, err := protocol.DecodeMessage(plain)
	if err != nil || msgType != protocol.MsgConnect {
		_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("connect required")))
		return 0, 0
	}
	target, err := protocol.ParseConnectPayload(payload)
	if err != nil {
		_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte(err.Error())))
		return 0, 0
	}
	mode := "tcp"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "udp:") {
		mode = "udp"
		target = strings.TrimSpace(target[4:])
	}
	if target == "" {
		_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("empty target")))
		return 0, 0
	}
	if mode == "udp" {
		return m.relayUDPSession(conn, session, writer, cfg, target)
	}

	dialTimeout := time.Duration(cfg.Limits.DialTimeoutSec) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	remote, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("dial failed")))
		return 0, 0
	}
	defer remote.Close()
	_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgConnectOK, []byte("ok")))

	done := make(chan struct{}, 2)
	var bo atomic.Int64
	var bi atomic.Int64

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				bi.Add(int64(n))
				if err := writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgData, buf[:n])); err != nil {
					break
				}
			}
			if err != nil {
				_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgClose, nil))
				break
			}
		}
		done <- struct{}{}
	}()

	for {
		_, frame, err := conn.ReadMessage()
		if err != nil {
			break
		}
		plain, err := session.Decrypt(frame)
		if err != nil {
			break
		}
		t, p, err := protocol.DecodeMessage(plain)
		if err != nil {
			break
		}
		switch t {
		case protocol.MsgData:
			if len(p) == 0 {
				continue
			}
			n, err := remote.Write(p)
			if n > 0 {
				bo.Add(int64(n))
			}
			if err != nil {
				goto exit
			}
		case protocol.MsgPing:
		case protocol.MsgClose:
			_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgClose, nil))
			goto exit
		default:
			_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("unknown message")))
			goto exit
		}
	}

exit:
	select {
	case <-done:
	default:
	}
	return bo.Load(), bi.Load()
}

func (m *Manager) relayUDPSession(conn *websocket.Conn, session *protocol.SessionCipher, writer *wsWriter, cfg config.Config, target string) (bytesIn, bytesOut int64) {
	dialTimeout := time.Duration(cfg.Limits.DialTimeoutSec) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	remote, err := net.DialTimeout("udp", target, dialTimeout)
	if err != nil {
		_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("dial failed")))
		return 0, 0
	}
	defer remote.Close()
	_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgConnectOK, []byte("ok")))

	done := make(chan struct{}, 2)
	var bo atomic.Int64
	var bi atomic.Int64

	readTimeout := time.Duration(cfg.Limits.IdleTimeoutSec) * time.Second
	if readTimeout <= 0 {
		readTimeout = 180 * time.Second
	}

	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(readTimeout))
			n, err := remote.Read(buf)
			if n > 0 {
				bi.Add(int64(n))
				if err := writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgData, buf[:n])); err != nil {
					break
				}
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgClose, nil))
				break
			}
		}
		done <- struct{}{}
	}()

	for {
		_, frame, err := conn.ReadMessage()
		if err != nil {
			break
		}
		plain, err := session.Decrypt(frame)
		if err != nil {
			break
		}
		t, p, err := protocol.DecodeMessage(plain)
		if err != nil {
			break
		}
		switch t {
		case protocol.MsgData:
			if len(p) == 0 {
				continue
			}
			n, err := remote.Write(p)
			if n > 0 {
				bo.Add(int64(n))
			}
			if err != nil {
				goto exit
			}
		case protocol.MsgPing:
		case protocol.MsgClose:
			_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgClose, nil))
			goto exit
		default:
			_ = writer.writeEncrypted(session, protocol.EncodeMessage(protocol.MsgError, []byte("unknown message")))
			goto exit
		}
	}

exit:
	select {
	case <-done:
	default:
	}
	return bo.Load(), bi.Load()
}

func writeJSON(conn *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, b)
}

func (w *wsWriter) writeEncrypted(session *protocol.SessionCipher, msg []byte) error {
	if w.jitter > 0 {
		time.Sleep(time.Duration(mrand.Intn(w.jitter+1)) * time.Millisecond)
	}
	enc, err := session.Encrypt(msg)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	return w.conn.WriteMessage(websocket.BinaryMessage, enc)
}

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func EnsureRuntimePaths(baseDir string) (configDir, dbPath, certDir string, err error) {
	configDir = filepath.Join(baseDir, "configs")
	dbPath = filepath.Join(baseDir, "users.db")
	certDir = filepath.Join(baseDir, "certs")
	if err = os.MkdirAll(configDir, 0o750); err != nil {
		return
	}
	if err = os.MkdirAll(certDir, 0o750); err != nil {
		return
	}
	return
}
