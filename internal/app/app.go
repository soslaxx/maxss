package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"maxss/internal/client"
	"maxss/internal/cli"
	"maxss/internal/config"
	"maxss/internal/db"
	"maxss/internal/server"
)

const (
	Version        = "1.0.0"
	DefaultBaseDir = "/var/www/maxss-core"
)

func Run(args []string) error {
	if len(args) == 0 {
		return runPanel(defaultOpts())
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "panel", "menu":
		return runPanelWithFlags(args[1:])
	case "init":
		return runInit(args[1:])
	case "quick-config":
		return runQuickConfig(args[1:])
	case "connect":
		return runConnect(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("maxss %s\n", Version)
		return nil
	case "help", "--help", "-h":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

type runtimeOpts struct {
	baseDir   string
	configDir string
	dbPath    string
	certDir   string
}

func defaultOpts() runtimeOpts {
	base := DefaultBaseDir
	return runtimeOpts{
		baseDir:   base,
		configDir: filepath.Join(base, "configs"),
		dbPath:    filepath.Join(base, "users.db"),
		certDir:   filepath.Join(base, "certs"),
	}
}

func parseBaseFlags(fs *flag.FlagSet, opts *runtimeOpts) {
	fs.StringVar(&opts.baseDir, "base-dir", opts.baseDir, "Base directory")
	fs.StringVar(&opts.configDir, "config-dir", opts.configDir, "Config directory")
	fs.StringVar(&opts.dbPath, "db", opts.dbPath, "SQLite database path")
	fs.StringVar(&opts.certDir, "cert-dir", opts.certDir, "Certificate directory")
}

func runServe(args []string) error {
	opts := defaultOpts()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	parseBaseFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensurePaths(opts); err != nil {
		return err
	}

	mgr, err := server.NewManager(opts.configDir, opts.dbPath, opts.certDir)
	if err != nil {
		return err
	}
	defer mgr.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return mgr.Run(ctx)
}

func runPanel(args runtimeOpts) error {
	if err := ensurePaths(args); err != nil {
		return err
	}
	return cli.RunMenu(cli.MenuOptions{
		ConfigDir:   args.configDir,
		DBPath:      args.dbPath,
		ServiceName: "maxss.service",
	})
}

func runPanelWithFlags(args []string) error {
	opts := defaultOpts()
	fs := flag.NewFlagSet("panel", flag.ContinueOnError)
	parseBaseFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runPanel(opts)
}

func runInit(args []string) error {
	opts := defaultOpts()
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	parseBaseFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensurePaths(opts); err != nil {
		return err
	}

	store, err := db.Open(opts.dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if _, err := config.LoadAll(opts.configDir); err != nil {
		return err
	}
	fmt.Println("Initialization complete")
	return nil
}

func runQuickConfig(args []string) error {
	opts := defaultOpts()
	port := 443
	sni := "www.cloudflare.com"
	fs := flag.NewFlagSet("quick-config", flag.ContinueOnError)
	parseBaseFlags(fs, &opts)
	fs.IntVar(&port, "port", port, "Listen port")
	fs.StringVar(&sni, "sni", sni, "Camouflage SNI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensurePaths(opts); err != nil {
		return err
	}
	path, cfg, err := config.CreateSecureConfig(opts.configDir, port, sni, "Secure Config")
	if err != nil {
		return err
	}
	fmt.Printf("Created %s in %s\n", cfg.Name, path)
	return nil
}

func runConnect(args []string) error {
	opts := client.Options{
		ListenAddr: "127.0.0.1:1080",
		Path:       "/.well-known/maxss",
		ConfigName: "Secure Config",
	}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.StringVar(&opts.ListenAddr, "listen", opts.ListenAddr, "Local SOCKS5 listen address")
	fs.StringVar(&opts.ServerAddr, "server", "", "Remote maxss server address (host:port)")
	fs.StringVar(&opts.SNI, "sni", "www.cloudflare.com", "TLS SNI")
	fs.StringVar(&opts.Path, "path", opts.Path, "WebSocket path")
	fs.StringVar(&opts.Username, "username", "", "Username")
	fs.StringVar(&opts.Password, "password", "", "Password (or hash:<argon2-hash>)")
	fs.StringVar(&opts.ConfigName, "config-name", opts.ConfigName, "Config NAME on server")
	fs.BoolVar(&opts.Insecure, "insecure", false, "Skip TLS certificate verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return client.Run(opts)
}

func ensurePaths(opts runtimeOpts) error {
	if opts.baseDir == "" {
		return errors.New("base directory is empty")
	}
	if err := os.MkdirAll(opts.baseDir, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.configDir, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.certDir, 0o750); err != nil {
		return err
	}
	return nil
}

func printHelp() {
	fmt.Println("maxss - Maximum Stealth & Speed")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  maxss                 # Open control panel")
	fmt.Println("  maxss serve           # Run server")
	fmt.Println("  maxss panel           # Open control panel")
	fmt.Println("  maxss init            # Initialize DB/configs")
	fmt.Println("  maxss quick-config    # Create strongest config from flags")
	fmt.Println("  maxss connect         # Start local SOCKS5 client using maxss transport")
	fmt.Println("  maxss version")
}
