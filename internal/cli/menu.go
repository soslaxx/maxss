package cli

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"maxss/internal/auth"
	"maxss/internal/config"
	"maxss/internal/db"
	"maxss/internal/subscription"
)

type MenuOptions struct {
	ConfigDir   string
	DBPath      string
	ServiceName string
}

func RunMenu(opts MenuOptions) error {
	store, err := db.Open(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := config.EnsureConfigDir(opts.ConfigDir); err != nil {
		return err
	}

	r := bufio.NewReader(os.Stdin)
	for {
		printMenu()
		choice := prompt(r, "Select option")
		switch choice {
		case "1":
			if err := createUserFlow(r, store); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "2":
			if err := deleteUserFlow(r, store); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "3":
			if err := listUsersFlow(store); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "4":
			if err := createConfigFlow(r, opts.ConfigDir); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "5":
			if err := subscriptionFlow(r, store, opts.ConfigDir); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "6":
			if err := manageConfigsFlow(r, opts.ConfigDir); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "7":
			if err := restartService(opts.ServiceName); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "8":
			if err := statsFlow(store, opts.ConfigDir); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "9":
			if err := quickConfigFlow(r, opts.ConfigDir); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "0", "q", "Q", "exit":
			return nil
		default:
			fmt.Println("Invalid option")
		}
		fmt.Println()
	}
}

func printMenu() {
	fmt.Println("=== MAXSS Control Panel v1.0 ===")
	fmt.Println()
	fmt.Println("1) Create new user")
	fmt.Println("2) Delete user")
	fmt.Println("3) List all users")
	fmt.Println("4) Create secure config")
	fmt.Println("5) Generate subscription link")
	fmt.Println("6) Manage configs")
	fmt.Println("7) Restart service")
	fmt.Println("8) Show statistics")
	fmt.Println("9) Quick secure config")
	fmt.Println("0) Exit")
}

func createUserFlow(r *bufio.Reader, store *db.Store) error {
	fmt.Println("Create new user")
	username := prompt(r, "Username")
	password := prompt(r, "Password")
	allowed := prompt(r, "Allowed config NAMES (comma separated)")
	limitText := promptDefault(r, "Traffic limit GB (-1 = unlimited)", "-1")
	expiresText := promptDefault(r, "Expires in days (-1 = forever)", "-1")

	trafficLimit, err := strconv.ParseInt(strings.TrimSpace(limitText), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid traffic limit")
	}
	expiresDays, err := strconv.ParseInt(strings.TrimSpace(expiresText), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid expires value")
	}

	expiresAt := "-1"
	if expiresDays != -1 {
		expiresAt = time.Now().Add(time.Duration(expiresDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := store.CreateUser(username, hash, allowed, trafficLimit, expiresAt); err != nil {
		return err
	}
	fmt.Println("User created")
	return nil
}

func deleteUserFlow(r *bufio.Reader, store *db.Store) error {
	fmt.Println("Delete user")
	username := prompt(r, "Username")
	if err := store.DeleteUser(username); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return err
	}
	fmt.Println("User deleted")
	return nil
}

func listUsersFlow(store *db.Store) error {
	users, err := store.ListUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}
	fmt.Printf("%-4s %-16s %-28s %-10s %-24s %-10s\n", "ID", "Username", "Allowed Configs", "LimitGB", "ExpiresAt", "UsedMB")
	for _, u := range users {
		exp := u.ExpiresAt
		if exp == "-1" {
			exp = "forever"
		}
		fmt.Printf("%-4d %-16s %-28s %-10d %-24s %-10d\n", u.ID, u.Username, u.AllowedConfigs, u.TrafficLimitGB, exp, u.TrafficUsedMB)
	}
	return nil
}

func createConfigFlow(r *bufio.Reader, configDir string) error {
	fmt.Println("Create secure config")
	name := promptDefault(r, "NAME", "Secure Config")
	portText := promptDefault(r, "Port", "443")
	sni := promptDefault(r, "SNI", "www.cloudflare.com")

	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("invalid port")
	}
	path, cfg, err := config.CreateSecureConfig(configDir, port, sni, name)
	if err != nil {
		return err
	}
	fmt.Printf("Created %s (%s)\n", cfg.Name, path)
	return nil
}

func quickConfigFlow(r *bufio.Reader, configDir string) error {
	fmt.Println("Quick secure config")
	portText := promptDefault(r, "Port", "443")
	sni := promptDefault(r, "SNI", "www.cloudflare.com")
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("invalid port")
	}
	path, cfg, err := config.CreateSecureConfig(configDir, port, sni, "Secure Config")
	if err != nil {
		return err
	}
	fmt.Printf("Created strongest config: %s (%s)\n", cfg.Name, path)
	return nil
}

func subscriptionFlow(r *bufio.Reader, store *db.Store, configDir string) error {
	fmt.Println("Generate subscription link")
	username := prompt(r, "Username")
	defaultAddr := detectPublicServerAddress()
	addr := promptDefault(r, "Server address override (optional)", defaultAddr)

	user, err := store.GetUser(username)
	if err != nil {
		return err
	}
	cfgs, err := config.LoadAll(configDir)
	if err != nil {
		return err
	}
	link, err := subscription.Generate(*user, cfgs, addr)
	if err != nil {
		return err
	}
	if err := store.UpdateSubscription(user.Username, link); err != nil {
		return err
	}
	fmt.Println("Subscription link:")
	fmt.Println(link)
	return nil
}

func detectPublicServerAddress() string {
	client := &http.Client{Timeout: 3 * time.Second}
	sources := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipv4.icanhazip.com",
	}
	for _, src := range sources {
		req, err := http.NewRequest(http.MethodGet, src, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "maxss/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 1500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.IP == nil {
		return ""
	}
	return strings.TrimSpace(udpAddr.IP.String())
}

func manageConfigsFlow(r *bufio.Reader, configDir string) error {
	for {
		cfgs, err := config.LoadAll(configDir)
		if err != nil {
			return err
		}
		fmt.Println("Manage configs")
		if len(cfgs) == 0 {
			fmt.Println("No configs found")
		} else {
			for i, fc := range cfgs {
				fmt.Printf("%d) %s (%s:%d) -> %s\n", i+1, fc.Config.Name, fc.Config.Listen, fc.Config.Port, fc.Path)
			}
		}
		fmt.Println("d) Delete config")
		fmt.Println("v) View config JSON")
		fmt.Println("b) Back")
		choice := prompt(r, "Choice")
		switch strings.ToLower(choice) {
		case "b":
			return nil
		case "d":
			idxText := prompt(r, "Config number to delete")
			idx, err := strconv.Atoi(idxText)
			if err != nil || idx < 1 || idx > len(cfgs) {
				fmt.Println("Invalid number")
				continue
			}
			if err := config.DeleteConfig(cfgs[idx-1].Path); err != nil {
				fmt.Printf("Delete failed: %v\n", err)
				continue
			}
			fmt.Println("Config deleted")
		case "v":
			idxText := prompt(r, "Config number to view")
			idx, err := strconv.Atoi(idxText)
			if err != nil || idx < 1 || idx > len(cfgs) {
				fmt.Println("Invalid number")
				continue
			}
			b, err := os.ReadFile(cfgs[idx-1].Path)
			if err != nil {
				fmt.Printf("Read failed: %v\n", err)
				continue
			}
			fmt.Println(string(b))
		default:
			fmt.Println("Invalid option")
		}
		fmt.Println()
	}
}

func restartService(service string) error {
	if strings.TrimSpace(service) == "" {
		service = "maxss.service"
	}
	cmd := exec.Command("systemctl", "restart", service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("Service restarted")
	return nil
}

func statsFlow(store *db.Store, configDir string) error {
	cfgs, err := config.LoadAll(configDir)
	if err != nil {
		return err
	}
	st, err := store.GetStats(int64(len(cfgs)))
	if err != nil {
		return err
	}
	fmt.Println("Statistics")
	fmt.Printf("Users: %d\n", st.Users)
	fmt.Printf("Configs: %d\n", st.Configs)
	fmt.Printf("Total Connections: %d\n", st.TotalConnections)
	fmt.Printf("Active Connections: %d\n", st.ActiveConnections)
	fmt.Printf("Bytes In: %d\n", st.BytesIn)
	fmt.Printf("Bytes Out: %d\n", st.BytesOut)
	fmt.Printf("Auth Failures: %d\n", st.AuthFailures)
	return nil
}

func prompt(r *bufio.Reader, title string) string {
	fmt.Printf("%s: ", title)
	v, _ := r.ReadString('\n')
	return strings.TrimSpace(v)
}

func promptDefault(r *bufio.Reader, title, def string) string {
	if def == "" {
		return prompt(r, title)
	}
	fmt.Printf("%s [%s]: ", title, def)
	v, _ := r.ReadString('\n')
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}
