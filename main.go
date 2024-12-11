package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

type Config struct {
	AllowMode    bool
	DenyMode     bool
	Countries    []string
	UpdatePeriod time.Duration
}

type IPBlocker struct {
	program *ebpf.Program
	ipMap   *ebpf.Map
	config  Config
	mutex   sync.RWMutex
}

func NewIPBlocker(config Config) (*IPBlocker, error) {
	// Загрузка eBPF программы из файла
	spec, err := ebpf.LoadCollectionSpec("xdp_filter.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %v", err)
	}

	// Создаем новую коллекцию
	var objs struct {
		IPFilter *ebpf.Program `ebpf:"ip_filter"`
		IPMap    *ebpf.Map     `ebpf:"ip_map"`
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %v", err)
	}

	// Получение имени сетевого интерфейса
	iface := getDefaultInterface()
	if iface == "" {
		objs.IPFilter.Close()
		objs.IPMap.Close()
		return nil, fmt.Errorf("failed to get default interface")
	}

	// Прикрепление XDP программы к интерфейсу
	if err := attachXDPProgram(objs.IPFilter, iface); err != nil {
		objs.IPFilter.Close()
		objs.IPMap.Close()
		return nil, fmt.Errorf("failed to attach XDP program: %v", err)
	}

	blocker := &IPBlocker{
		program: objs.IPFilter,
		ipMap:   objs.IPMap,
		config:  config,
	}

	// Первоначальная загрузка IP-адресов
	if err := blocker.updateIPList(); err != nil {
		blocker.Close()
		return nil, fmt.Errorf("failed to perform initial IP update: %v", err)
	}

	return blocker, nil
}

func attachXDPProgram(prog *ebpf.Program, ifaceName string) error {
	// Получаем индекс интерфейса
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %v", err)
	}

	// Используем netlink для прикрепления XDP программы
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to get link: %v", err)
	}

	if err := netlink.LinkSetXdpFd(link, prog.FD()); err != nil {
		return fmt.Errorf("failed to set XDP fd: %v", err)
	}

	return nil
}

// Вспомогательные функции

func getDefaultInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		// Пропускаем loopback и интерфейсы без UP флага
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Ищем интерфейс с IPv4 адресом
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return iface.Name
				}
			}
		}
	}
	return ""
}

// Метод для корректного закрытия и очистки ресурсов
func (b *IPBlocker) Close() error {
	if b.program != nil {
		b.program.Close()
	}
	if b.ipMap != nil {
		b.ipMap.Close()
	}
	return nil
}

func main() {
	// Парсинг флагов
	allow := flag.Bool("allow", false, "Allow only specified countries")
	deny := flag.Bool("deny", false, "Deny specified countries")
	countries := flag.String("countries", "", "Comma-separated country codes")
	flag.Parse()

	// Проверка валидности флагов
	if *allow && *deny {
		log.Fatal("Cannot use both --allow and --deny modes")
	}
	if !*allow && !*deny {
		log.Fatal("Must specify either --allow or --deny mode")
	}
	if *countries == "" {
		log.Fatal("Must specify countries")
	}

	config := Config{
		AllowMode:    *allow,
		DenyMode:     *deny,
		Countries:    strings.Split(*countries, ","),
		UpdatePeriod: time.Hour,
	}

	blocker, err := NewIPBlocker(config)
	if err != nil {
		log.Fatal(err)
	}
	defer blocker.Close()

	// Добавим периодический вывод статистики
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			count, err := blocker.GetMapStats()
			if err != nil {
				log.Printf("Failed to get stats: %v", err)
				continue
			}
			log.Printf("Current map entries: %d", count)
		}
	}()

	go blocker.periodicUpdate()

	// Держим программу запущенной
	select {}
}

type mapKey struct {
	PrefixLen uint32
	IP        uint32
}

func (b *IPBlocker) updateIPList() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Очищаем существующие записи
	var key mapKey
	var value uint8

	iter := b.ipMap.Iterate()
	for iter.Next(&key, &value) {
		err := b.ipMap.Delete(&key)
		if err != nil {
			log.Printf("Failed to delete key: %v", err)
		}
	}

	// Загрузка новых данных для каждой страны
	for _, country := range b.config.Countries {
		url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone",
			strings.ToLower(country))

		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			cidr := scanner.Text()
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			// Преобразование IP в uint32
			ip := ipToUint32(network.IP)
			prefixLen, _ := network.Mask.Size()

			key := mapKey{
				PrefixLen: uint32(prefixLen),
				IP:        ip,
			}

			// В режиме allow помечаем разрешенные IP
			// В режиме deny помечаем запрещенные IP
			value := uint8(1)
			if b.config.DenyMode {
				value = 0
			}

			if err := b.ipMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
				log.Printf("Failed to update IP map for %s: %v", cidr, err)
			}
		}
	}

	return nil
}

func (b *IPBlocker) GetMapStats() (int, error) {
	count := 0
	var key mapKey
	var value uint8

	iter := b.ipMap.Iterate()
	for iter.Next(&key, &value) {
		count++
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key.IP)
		log.Printf("Found entry: %v/%d -> %d", ip, key.PrefixLen, value)
	}

	return count, nil
}

func (b *IPBlocker) periodicUpdate() {
	ticker := time.NewTicker(b.config.UpdatePeriod)
	defer ticker.Stop()

	for {
		if err := b.updateIPList(); err != nil {
			log.Printf("Failed to update IP list: %v", err)
		}
		<-ticker.C
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
