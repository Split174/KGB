package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Функция проверки наличия необходимых утилит
func checkRequirements() error {
	requiredCommands := []string{"wget", "nft"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("error: %s is not installed", cmd)
		}
	}
	return nil
}

// Функция создания временной директории
func setupTempDir() (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "ipfilter-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup, nil
}

// Функция загрузки IP-диапазонов для указанной страны
func downloadCountryIPs(country string, tempDir string) (string, error) {
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone", country)
	outputFile := filepath.Join(tempDir, fmt.Sprintf("%s-aggregated.zone", country))

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download IP ranges for country %s: %v", country, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download IP ranges for country %s: status %d", country, resp.StatusCode)
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return outputFile, nil
}

// Функция настройки nftables
func setupNftables(mode string, countryCodes string, tempDir string) error {
	// Удаляем старую таблицу если она существует
	exec.Command("nft", "delete", "table", "ip", "kgb_filter").Run()

	// Создаем базовые правила
	commands := [][]string{
		{"add", "table", "ip", "kgb_filter"},
		{"add", "chain", "ip", "kgb_filter", "kgb_input", "{ type filter hook input priority 0 ; policy accept ; }"},
		{"add", "rule", "ip", "kgb_filter", "kgb_input", "iif", "lo", "accept"},
		{"add", "rule", "ip", "kgb_filter", "kgb_input", "ct", "state", "established,related", "accept"},
	}

	for _, cmd := range commands {
		if err := exec.Command("nft", cmd...).Run(); err != nil {
			return fmt.Errorf("failed to execute nft command: %v", err)
		}
	}

	// Настраиваем наборы и правила для каждой страны
	countries := strings.Split(countryCodes, ",")
	for _, country := range countries {
		setName := fmt.Sprintf("kgb_ips_%s", country)

		// Создаем набор
		createSet := []string{"add", "set", "ip", "kgb_filter", setName, "{ type ipv4_addr ; flags interval ; }"}
		if err := exec.Command("nft", createSet...).Run(); err != nil {
			return fmt.Errorf("failed to create nft set for country %s: %v", country, err)
		}

		// Загружаем IP-адреса и добавляем в набор
		file, err := downloadCountryIPs(country, tempDir)
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read IP file: %v", err)
		}

		ips := strings.Split(string(content), "\n")
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			addElement := []string{"add", "element", "ip", "kgb_filter", setName, "{", ip, "}"}
			if err := exec.Command("nft", addElement...).Run(); err != nil {
				fmt.Printf("Warning: failed to add IP %s to set %s: %v\n", ip, setName, err)
			}
		}

		// Добавляем финальные правила для набора
		if mode == "allow" {
			if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "ip", "saddr", "@"+setName, "accept").Run(); err != nil {
				return fmt.Errorf("failed to add allow rule for set %s: %v", setName, err)
			}
		} else {
			if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "ip", "saddr", "@"+setName, "drop").Run(); err != nil {
				return fmt.Errorf("failed to add deny rule for set %s: %v", setName, err)
			}
		}
	}

	// Добавляем финальные правила по умолчанию
	if mode == "allow" {
		if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "drop").Run(); err != nil {
			return fmt.Errorf("failed to add final drop rule: %v", err)
		}
	} else {
		if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "accept").Run(); err != nil {
			return fmt.Errorf("failed to add final accept rule: %v", err)
		}
	}

	return nil
}

func main() {
	// Определение флагов командной строки
	allowMode := flag.String("allow", "", "Allowed country codes (comma-separated)")
	denyMode := flag.String("deny", "", "Denied country codes (comma-separated)")
	flag.Parse()

	// Проверка аргументов
	if (*allowMode == "" && *denyMode == "") || (*allowMode != "" && *denyMode != "") {
		fmt.Println("Usage: program --allow country_codes or --deny country_codes")
		fmt.Println("Example: program --allow ru,us,ch")
		fmt.Println("Example: program --deny cn,kr")
		os.Exit(1)
	}

	// Проверка формата кодов стран
	mode := "allow"
	countryCodes := *allowMode
	if *denyMode != "" {
		mode = "deny"
		countryCodes = *denyMode
	}

	if !regexp.MustCompile(`^[a-z,]+$`).MatchString(countryCodes) {
		fmt.Println("Error: Invalid country codes format. Use lowercase letters separated by commas.")
		os.Exit(1)
	}

	// Проверка требований
	if err := checkRequirements(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Создание временной директории
	tempDir, cleanup, err := setupTempDir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer cleanup()

	// Настройка nftables
	if err := setupNftables(mode, countryCodes, tempDir); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
