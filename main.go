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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Метрики Prometheus
var (
	packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kgb_packets_total",
			Help: "Total number of packets filtered by country",
		},
		[]string{"country", "action"},
	)

	bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kgb_bytes_total",
			Help: "Total number of bytes filtered by country",
		},
		[]string{"country", "action"},
	)

	lastUpdate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kgb_last_update_timestamp",
			Help: "Timestamp of the last metrics update",
		},
		[]string{"country"},
	)

	blockedCountries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kgb_blocked_countries",
			Help: "Number of countries that are currently blocked",
		},
		[]string{"country"},
	)

	allowedCountries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kgb_allowed_countries",
			Help: "Number of countries that are currently allowed",
		},
		[]string{"country"},
	)
)

// Глобальные переменные
var (
	currentMode      string
	currentCountries []string
	metricsLock      sync.Mutex
)

func init() {
	// Регистрация метрик в Prometheus
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
	prometheus.MustRegister(lastUpdate)
	prometheus.MustRegister(blockedCountries) // Регистрация метрики для заблокированных стран
	prometheus.MustRegister(allowedCountries) // Регистрация метрики для разрешенных стран
}

// Функция обновления метрик Prometheus
func updatePrometheusMetrics() {
	for {
		metricsLock.Lock()
		cmd := exec.Command("nft", "list", "table", "ip", "kgb_filter")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error collecting metrics: %v\n", err)
			metricsLock.Unlock()
			time.Sleep(10 * time.Second)
			continue
		}

		lines := strings.Split(string(output), "\n")
		now := time.Now().Unix()

		for _, line := range lines {
			if matches := regexp.MustCompile(`@kgb_ips_(\w+).*counter packets (\d+) bytes (\d+)`).FindStringSubmatch(line); matches != nil {
				country := matches[1]
				packets := parseInt(matches[2])
				bytes := parseInt(matches[3])

				// Обновляем метрики
				packetsTotal.WithLabelValues(country, currentMode).Add(float64(packets))
				bytesTotal.WithLabelValues(country, currentMode).Add(float64(bytes))
				lastUpdate.WithLabelValues(country).Set(float64(now))
			}
		}
		metricsLock.Unlock()
		time.Sleep(10 * time.Second)
	}
}

func parseInt(s string) int64 {
	val, _ := strconv.ParseInt(s, 10, 64)
	return val
}

func contains(slice []string, item string) bool {
	for _, element := range slice {
		if element == item {
			return true
		}
	}
	return false
}

// Функция получения статистики блокировок
func getBlockingStatistics() error {
	cmd := exec.Command("nft", "list", "table", "ip", "kgb_filter", "-a")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get statistics: %v", err)
	}

	// Обработка вывода
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "counter packets") {
			// Извлекаем имя сета и статистику
			if matches := regexp.MustCompile(`@kgb_ips_(\w+).*counter packets (\d+) bytes (\d+)`).FindStringSubmatch(line); matches != nil {
				country := matches[1]
				packets := matches[2]
				bytes := matches[3]
				fmt.Printf("Country %s: %s packets, %s bytes\n", country, packets, bytes)
			}
		}
	}
	return nil
}

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

		// Добавляем правила для учета пакетов и действия
		if mode == "allow" {
			if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "ip", "saddr", "@"+setName, "counter", "accept").Run(); err != nil {
				return fmt.Errorf("failed to add allow rule for set %s: %v", setName, err)
			}
			allowedCountries.WithLabelValues(country).Set(1)
			blockedCountries.WithLabelValues(country).Set(0)
		} else {
			if err := exec.Command("nft", "add", "rule", "ip", "kgb_filter", "kgb_input", "ip", "saddr", "@"+setName, "counter", "drop").Run(); err != nil {
				return fmt.Errorf("failed to add deny rule for set %s: %v", setName, err)
			}
			blockedCountries.WithLabelValues(country).Set(1)
			allowedCountries.WithLabelValues(country).Set(0)
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
	metricsPort := flag.Int("metrics-port", 9000, "Port for Prometheus metrics")
	showStats := flag.Bool("stats", false, "Show current blocking statistics")
	flag.Parse()

	// Проверка флага статистики
	if *showStats {
		if err := getBlockingStatistics(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	// Проверка аргументов
	if (*allowMode == "" && *denyMode == "") || (*allowMode != "" && *denyMode != "") {
		fmt.Println("Usage: program --allow country_codes or --deny country_codes")
		fmt.Println("Example: program --allow ru,us,ch")
		fmt.Println("Example: program --deny cn,kr")
		fmt.Println("Additional options:")
		fmt.Println("  --stats           Show current blocking statistics")
		fmt.Println("  --metrics-port    Port for Prometheus metrics (default: 9000)")
		os.Exit(1)
	}

	// Определение режима работы
	if *allowMode != "" {
		currentMode = "allow"
		currentCountries = strings.Split(*allowMode, ",")
	} else {
		currentMode = "deny"
		currentCountries = strings.Split(*denyMode, ",")
	}

	// Проверка формата кодов стран
	countryCodes := strings.Join(currentCountries, ",")
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
	if err := setupNftables(currentMode, countryCodes, tempDir); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Запуск сборщика метрик в отдельной горутине
	go updatePrometheusMetrics()

	// Настройка HTTP сервера для метрик Prometheus
	http.Handle("/metrics", promhttp.Handler())
	fmt.Printf("Starting metrics server on :%d\n", *metricsPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *metricsPort), nil); err != nil {
		fmt.Printf("Error starting metrics server: %v\n", err)
		os.Exit(1)
	}
}
