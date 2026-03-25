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
	NoColor     bool
}

const (
	ansiReset   = "\x1b[0m"
	ansiTitle   = "\x1b[1;38;5;51m"
	ansiBorder  = "\x1b[1;38;5;45m"
	ansiMenu    = "\x1b[38;5;159m"
	ansiPrompt  = "\x1b[1;38;5;220m"
	ansiSuccess = "\x1b[1;32m"
	ansiError   = "\x1b[1;31m"
	ansiMuted   = "\x1b[38;5;246m"
	ansiByline  = "\x1b[1;38;5;214m"
)

type menuTheme struct {
	color bool
}

var activeTheme = menuTheme{color: true}

func newMenuTheme(noColor bool) menuTheme {
	return menuTheme{color: !noColor}
}

func (t menuTheme) paint(style, text string) string {
	if !t.color {
		return text
	}
	return style + text + ansiReset
}

func (t menuTheme) title(text string) string {
	return t.paint(ansiTitle, text)
}

func (t menuTheme) border(text string) string {
	return t.paint(ansiBorder, text)
}

func (t menuTheme) menu(text string) string {
	return t.paint(ansiMenu, text)
}

func (t menuTheme) prompt(text string) string {
	return t.paint(ansiPrompt, text)
}

func (t menuTheme) success(text string) string {
	return t.paint(ansiSuccess, text)
}

func (t menuTheme) error(text string) string {
	return t.paint(ansiError, text)
}

func (t menuTheme) muted(text string) string {
	return t.paint(ansiMuted, text)
}

func (t menuTheme) byline(text string) string {
	return t.paint(ansiByline, text)
}

func (t menuTheme) showSplash() {
	if t.color {
		fmt.Print("\x1b[2J\x1b[H")
	}
	fmt.Println(t.border("+------------------------------------------------------------+"))
	fmt.Println(t.border("|                 MAXSS TERMINAL SHELL                       |"))
	fmt.Println(t.border("+------------------------------------------------------------+"))
	fmt.Println(t.title(" __  __    _    __  ______ ____  "))
	fmt.Println(t.title("|  \\/  |  / \\   \\ \\/ / ___/ ___| "))
	fmt.Println(t.title("| |\\/| | / _ \\   \\  /\\___ \\___ \\ "))
	fmt.Println(t.title("| |  | |/ ___ \\  /  \\ ___) |__) |"))
	fmt.Println(t.title("|_|  |_/_/   \\_\\/_/\\_\\____/____/ "))
	fmt.Println()

	fmt.Println(t.byline(" ____   ___  ____  _        _    __  ____  __"))
	fmt.Println(t.byline("/ ___| / _ \\/ ___|| |      / \\   \\ \\/ /\\ \\/ /"))
	fmt.Println(t.byline("\\___ \\| | | \\___ \\| |     / _ \\   \\  /  \\  / "))
	fmt.Println(t.byline(" ___) | |_| |___) | |___ / ___ \\  /  \\  /  \\ "))
	fmt.Println(t.byline("|____/ \\___/|____/|_____/_/   \\_\\/_/\\_\\/_/\\_\\"))
	fmt.Println(t.byline("                 Maximum Stealth & Speed"))
	fmt.Println(t.border("+------------------------------------------------------------+"))
	fmt.Println()
}

func printError(err error) {
	fmt.Println(activeTheme.error(fmt.Sprintf("Error: %v", err)))
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

	activeTheme = newMenuTheme(opts.NoColor)
	activeTheme.showSplash()

	r := bufio.NewReader(os.Stdin)
	for {
		printMenu()
		choice := prompt(r, "Select option")
		switch choice {
		case "1":
			if err := createUserFlow(r, store); err != nil {
				printError(err)
			}
		case "2":
			if err := deleteUserFlow(r, store); err != nil {
				printError(err)
			}
		case "3":
			if err := listUsersFlow(store); err != nil {
				printError(err)
			}
		case "4":
			if err := createConfigFlow(r, opts.ConfigDir); err != nil {
				printError(err)
			}
		case "5":
			if err := subscriptionFlow(r, store, opts.ConfigDir); err != nil {
				printError(err)
			}
		case "6":
			if err := manageConfigsFlow(r, opts.ConfigDir); err != nil {
				printError(err)
			}
		case "7":
			if err := restartService(opts.ServiceName); err != nil {
				printError(err)
			}
		case "8":
			if err := statsFlow(store, opts.ConfigDir); err != nil {
				printError(err)
			}
		case "9":
			if err := quickConfigFlow(r, opts.ConfigDir); err != nil {
				printError(err)
			}
		case "0", "q", "Q", "exit":
			return nil
		default:
			fmt.Println(activeTheme.error("Invalid option"))
		}
		fmt.Println()
	}
}

func printMenu() {
	fmt.Println(activeTheme.title("=== MAXSS Control Panel v1.0 ==="))
	fmt.Println()
	fmt.Println(activeTheme.menu("1) Create new user"))
	fmt.Println(activeTheme.menu("2) Delete user"))
	fmt.Println(activeTheme.menu("3) List all users"))
	fmt.Println(activeTheme.menu("4) Create secure config"))
	fmt.Println(activeTheme.menu("5) Generate subscription link"))
	fmt.Println(activeTheme.menu("6) Manage configs"))
	fmt.Println(activeTheme.menu("7) Restart service"))
	fmt.Println(activeTheme.menu("8) Show statistics"))
	fmt.Println(activeTheme.menu("9) Quick secure config"))
	fmt.Println(activeTheme.menu("0) Exit"))
}

func createUserFlow(r *bufio.Reader, store *db.Store) error {
	fmt.Println(activeTheme.title("Create new user"))
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
	fmt.Println(activeTheme.success("User created"))
	return nil
}

func deleteUserFlow(r *bufio.Reader, store *db.Store) error {
	fmt.Println(activeTheme.title("Delete user"))
	username := prompt(r, "Username")
	if err := store.DeleteUser(username); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return err
	}
	fmt.Println(activeTheme.success("User deleted"))
	return nil
}

func listUsersFlow(store *db.Store) error {
	users, err := store.ListUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println(activeTheme.muted("No users found"))
		return nil
	}
	fmt.Println(activeTheme.title("Users"))
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
	fmt.Println(activeTheme.title("Create secure config"))
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
	fmt.Println(activeTheme.success(fmt.Sprintf("Created %s (%s)", cfg.Name, path)))
	return nil
}

func quickConfigFlow(r *bufio.Reader, configDir string) error {
	fmt.Println(activeTheme.title("Quick secure config"))
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
	fmt.Println(activeTheme.success(fmt.Sprintf("Created strongest config: %s (%s)", cfg.Name, path)))
	return nil
}

func subscriptionFlow(r *bufio.Reader, store *db.Store, configDir string) error {
	fmt.Println(activeTheme.title("Generate subscription link"))
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
	fmt.Println(activeTheme.success("Subscription link:"))
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
		fmt.Println(activeTheme.title("Manage configs"))
		if len(cfgs) == 0 {
			fmt.Println(activeTheme.muted("No configs found"))
		} else {
			for i, fc := range cfgs {
				fmt.Printf("%d) %s (%s:%d) -> %s\n", i+1, fc.Config.Name, fc.Config.Listen, fc.Config.Port, fc.Path)
			}
		}
		fmt.Println(activeTheme.menu("d) Delete config"))
		fmt.Println(activeTheme.menu("v) View config JSON"))
		fmt.Println(activeTheme.menu("b) Back"))
		choice := prompt(r, "Choice")
		switch strings.ToLower(choice) {
		case "b":
			return nil
		case "d":
			idxText := prompt(r, "Config number to delete")
			idx, err := strconv.Atoi(idxText)
			if err != nil || idx < 1 || idx > len(cfgs) {
				fmt.Println(activeTheme.error("Invalid number"))
				continue
			}
			if err := config.DeleteConfig(cfgs[idx-1].Path); err != nil {
				fmt.Println(activeTheme.error(fmt.Sprintf("Delete failed: %v", err)))
				continue
			}
			fmt.Println(activeTheme.success("Config deleted"))
		case "v":
			idxText := prompt(r, "Config number to view")
			idx, err := strconv.Atoi(idxText)
			if err != nil || idx < 1 || idx > len(cfgs) {
				fmt.Println(activeTheme.error("Invalid number"))
				continue
			}
			b, err := os.ReadFile(cfgs[idx-1].Path)
			if err != nil {
				fmt.Println(activeTheme.error(fmt.Sprintf("Read failed: %v", err)))
				continue
			}
			fmt.Println(string(b))
		default:
			fmt.Println(activeTheme.error("Invalid option"))
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
	fmt.Println(activeTheme.success("Service restarted"))
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
	fmt.Println(activeTheme.title("Statistics"))
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
	fmt.Printf("%s: ", activeTheme.prompt(title))
	v, _ := r.ReadString('\n')
	return strings.TrimSpace(v)
}

func promptDefault(r *bufio.Reader, title, def string) string {
	if def == "" {
		return prompt(r, title)
	}
	fmt.Printf("%s [%s]: ", activeTheme.prompt(title), def)
	v, _ := r.ReadString('\n')
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}
