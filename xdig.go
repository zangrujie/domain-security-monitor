/**
 * @Project :   Kaweh
 * @File    :   xdig.go
 * @Contact :
 * @License :   (C)Copyright 2025
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 2025/6/17 23:49     idealeer    0.0         None
 */

/*
#cgo windows CFLAGS: -I D:/MySecurityProject/npcap-sdk-1.16/Include
#cgo windows LDFLAGS: -L D:/MySecurityProject/npcap-sdk-1.16/Lib/x64 -lwpcap
*/

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface, srcIP, srcMAC, gtwMAC, domainFile, domainList, dnsFile, dnsList, outputFile, qType string
	rate, waitingTime                                                                         uint
	totalCount, sentCount, foundCount, try, pythonTry                                         uint64
	dnsServers, domains                                                                       []string
	showVersion, dryRun                                                                       bool
	packetChan                                                                                = make(chan []byte, 20000)
	storeChan                                                                                 = make(chan string, 20000)
	srcMACB, gtwMACB                                                                          net.HardwareAddr
	srcIPB                                                                                    net.IP
	logLevel                                                                                  uint
	startTime                                                                                 time.Time
	qDNSType                                                                                  layers.DNSType
)

// NetworkInfo is a struct to parse the JSON returned from the Python script.
type NetworkInfo struct {
	Iface       string `json:"iface"`
	SrcIPLocal  string `json:"src_ip_local"`
	SrcIPPublic string `json:"src_ip_public"`
	LocalMac    string `json:"local_mac"`
	GatewayMac  string `json:"gateway_mac"`
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	Operator    string `json:"operator"`
	Error       string `json:"error"` // Used to handle potential errors from the Python script.
}

const version = "XDIG v1.0"

func printBanner() {
	cyan := "\033[36m"
	reset := "\033[0m"

	fmt.Println(
		cyan +
			`
#  __   _______ _____ _____ 
#  \ \ / /  _  \_   _|  __ \
#   \ V /| | | | | | | |  \/
#   /   \| | | | | | | | __ 
#  / /^\ \ |/ / _| |_| |_\ \
#  \/   \/___/  \___/ \____/
` + reset,
	)
	fmt.Println("🔍 XDIG - Fast DNS Resolution Using Multiple Resolvers")
	fmt.Println("📦 Version:", version)
	fmt.Println("✨ Supports: high-speed DNS resolution with rotating resolvers\n")
}

func initParams() {
	flag.UintVar(&logLevel, "v", 2, "Log verbosity level (0=silent, 1=only result, 2=progress, 3=all)")
	flag.BoolVar(&showVersion, "V", false, "Show version and exit")
	flag.StringVar(&iface, "iface", "ens160", "Network interface")
	flag.StringVar(&srcIP, "srcip", "", "Source IP")
	flag.StringVar(&srcMAC, "srcmac", "", "Source MAC")
	flag.StringVar(&gtwMAC, "gtwmac", "", "Gateway MAC")
	flag.UintVar(&rate, "rate", 1000, "Query rate (qps)")
	flag.StringVar(&domainFile, "domainfile", "", "Path to domain list (default example.com)")
	flag.StringVar(&domainList, "domainlist", "", "Domain list with semicolon seperated (default example.com)")
	flag.StringVar(&dnsFile, "dnsfile", "", "Path to DNS server IP list (default 8.8.8.8")
	flag.StringVar(&dnsList, "dnslist", "", "DNS server IP list with semicolon seperated (default 8.8.8.8")
	flag.StringVar(&outputFile, "out", "result-<date>.txt", "Output file")
	flag.StringVar(&qType, "type", "A", "Query type")
	flag.Uint64Var(&try, "try", 1, "Query target for several times")
	flag.BoolVar(&dryRun, "dry", false, "Dry run mode (only print)")
	flag.UintVar(&waitingTime, "wtgtime", 5, "Waiting time (s) until exit")

	flag.Parse()

	if showVersion {
		fmt.Println("XDIG - Multi-resolver DNS Resolver")
		fmt.Println("Version:", version)

		os.Exit(0)
	}

	if logLevel != 1 {
		printBanner()

		log.Println("Initializing parameters...")
	}

	if !dryRun && (iface == "" || srcIP == "" || srcMAC == "" || gtwMAC == "") {
		log.Println("iface, srcip, srcmac, or gtwmac is null, try myip.ipip.net")
		getNetworkInfo()
	}

	if rate == 0 {
		log.Fatal("Error: rate > 0")
	}

	if dnsFile != "" {
		if logLevel != 1 {
			log.Println("Reading DNS server list...")
		}

		f, err := os.Open(dnsFile)
		if err != nil {
			log.Fatalf("Failed to open DNS file: %v", err)
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				dnsServers = append(dnsServers, ip)
			}
		}

		f.Close()
	}

	if dnsList != "" {
		dnsLists := strings.Split(strings.ToLower(dnsList), ";")
		for _, ip := range dnsLists {
			dnsServers = append(dnsServers, ip)
		}
	}

	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8"}
		if logLevel != 1 {
			log.Println("No DNS server specified, using default: 8.8.8.8")
		}
	}

	if logLevel != 1 {
		log.Printf("Total DNS server: %s\n", humanize.Comma(int64(len(dnsServers))))
	}

	if domainFile != "" {
		if logLevel != 1 {
			log.Println("Counting domain list...")
		}

		f, err := os.Open(domainFile)
		if err != nil {
			log.Fatalf("Failed to open domain list: %v", err)
		}

		s := bufio.NewScanner(f)
		for s.Scan() {
			totalCount++
		}
		f.Close()

		if totalCount == 0 {
			log.Fatal("Domain list file is empty")
		}
	}

	if domainList != "" {
		domainLists := strings.Split(strings.ToLower(domainList), ";")
		for _, domain := range domainLists {
			domains = append(domains, domain)
		}
	}

	if totalCount == 0 && len(domains) == 0 {
		domains = []string{"example.com"}
		if logLevel != 1 {
			log.Println("No domain specified, using default: example.com")
		}
	}

	totalCount += uint64(len(domains))

	if logLevel != 1 {
		log.Printf("Total domains to dig: %s\n", humanize.Comma(int64(totalCount)))
	}

	qDNSType = qtypeStr2Int(qType)

	if outputFile == "result-<date>.txt" {
		outputFile = fmt.Sprintf("result-%s.txt", time.Now().Format(time.ANSIC))
	}

	if dryRun {
		log.Printf("Dryrun mode, no actual sending...\n")
	} else {
		// Init net
		srcMAC_, _ := hex.DecodeString(strings.ReplaceAll(srcMAC, ":", ""))
		gtwMAC_, _ := hex.DecodeString(strings.ReplaceAll(gtwMAC, ":", ""))
		srcMACB = net.HardwareAddr(srcMAC_)
		gtwMACB = net.HardwareAddr(gtwMAC_)
		srcIPB = net.ParseIP(srcIP)
	}
}

func qtypeStr2Int(qtype string) layers.DNSType {
	switch strings.ToUpper(qtype) {
	case "A":
		return layers.DNSTypeA
	case "NS":
		return layers.DNSTypeNS
	default:
		log.Fatal("Only support A, NS")
	}
	return 0
}

func getNetworkInfo() {
	// Call the Python script
	cmd := exec.Command("python3", "network_info.py")

	// Get the output
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to call Python script: %v", err)
	}

	// Parse the JSON output
	var info NetworkInfo
	err = json.Unmarshal(output, &info)
	if err != nil {
		log.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Check for error messages
	if info.Error != "" {
		if pythonTry < 5 {
			pythonTry += 1
			log.Printf("Script returned an error: %s, try %d times", info.Error, pythonTry)
			getNetworkInfo()
			return
		} else {
			log.Fatalf("Script returned an error: %s, try 5 times", info.Error)
		}
	}

	// Print the results
	log.Printf("Network Interface: %s\n", info.Iface)
	log.Printf("Local IP: %s\n", info.SrcIPLocal)
	log.Printf("Public IP: %s\n", info.SrcIPPublic)
	log.Printf("Local MAC: %s\n", info.LocalMac)
	log.Printf("Gateway MAC: %s\n", info.GatewayMac)
	//log.Printf("Country: %s\n", info.Country)
	//log.Printf("Province: %s\n", info.Province)
	//log.Printf("City: %s\n", info.City)
	//log.Printf("ISP: %s\n", info.Operator)

	iface = info.Iface
	srcIP = info.SrcIPLocal
	//srcIPP = info.SrcIPPublic
	srcMAC = info.LocalMac
	gtwMAC = info.GatewayMac
	//cty = info.Country
	//prv = info.Province
	//city = info.City
	//isp = info.Operator
}

func generatePort(ip string) uint16 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	part1, _ := strconv.Atoi(parts[0])
	part2, _ := strconv.Atoi(parts[1])

	return uint16(part1<<8 + part2)
}

func generateTxID(ip string) uint16 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	part1, _ := strconv.Atoi(parts[2])
	part2, _ := strconv.Atoi(parts[3])

	return uint16(part1<<8 + part2)
}

func buildDNSQuery(qname, dnsServer string, qtype layers.DNSType) []byte {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMACB,
		DstMAC:       gtwMACB,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPB,
		DstIP:      net.ParseIP(dnsServer),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(generatePort(dnsServer)),
		DstPort:   layers.UDPPort(53),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	dnsLayer := &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           generateTxID(dnsServer),
		QR:           false,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(qname),
				Type:  qtype,
				Class: layers.DNSClassIN,
			},
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer, options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	outgoingPacket := buffer.Bytes()

	return outgoingPacket
}

func generatePackets() {
	if logLevel != 1 {
		log.Println("Starting query generating...")
	}

	idx := 0
	if domainFile != "" {
		f, _ := os.Open(domainFile)
		s := bufio.NewScanner(f)

		for s.Scan() {
			line := strings.ToLower(s.Text())

			domainType := strings.Split(line, ",")
			domain := domainType[0]
			qtype := qDNSType
			if len(domainType) == 2 {
				qtype = qtypeStr2Int(domainType[1])
			}

			ip := dnsServers[idx%len(dnsServers)]

			if dryRun {
				fmt.Printf("%s,%s\n", line, ip)
			} else {
				pkt := buildDNSQuery(domain, ip, qtype)
				if pkt != nil {
					for i := 0; i < int(try); i++ {
						packetChan <- pkt
					}
				}
			}

			idx++
		}

		f.Close()
	} else {
		for _, line := range domains {
			domainType := strings.Split(line, ",")
			domain := domainType[0]
			qtype := qDNSType
			if len(domainType) == 2 {
				qtype = qtypeStr2Int(domainType[1])
			}

			ip := dnsServers[idx%len(dnsServers)]

			if dryRun {
				fmt.Printf("%s,%s\n", line, ip)
			} else {
				pkt := buildDNSQuery(domain, ip, qtype)
				if pkt != nil {
					for i := 0; i < int(try); i++ {
						packetChan <- pkt
					}
				}
			}

			idx++
		}
	}

	if !dryRun {
		packetChan <- nil
	}
}

func sendPackets(done context.CancelFunc) {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting query sending...")
	}

	interval := time.Microsecond * time.Duration(1e6/int64(rate))
	handle, _ := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	defer handle.Close()
	err := handle.SetDirection(pcap.DirectionOut)
	if err != nil {
		log.Fatalf("Failed to SetDirection: %v", err)
	}

	var lastSendTime time.Time

	for {
		pkt := <-packetChan
		if pkt == nil {
			if logLevel != 1 {
				log.Println("All queries sent. Waiting 5 seconds before signaling receive thread...")
			}
			time.Sleep(time.Duration(waitingTime) * time.Second)

			done()
			break
		}

		now := time.Now()
		if !lastSendTime.IsZero() {
			elapsed := now.Sub(lastSendTime)
			remaining := interval - elapsed

			if remaining > 0 {
				for time.Since(now) < interval {
				}
			}
		}
		lastSendTime = time.Now()

		handle.WritePacketData(pkt)
		atomic.AddUint64(&sentCount, 1)

		if logLevel != 0 && logLevel != 1 {
			if sentCount%uint64(rate) == 0 {
				dur := time.Since(startTime).Seconds()
				left := float64(totalCount-sentCount) / float64(rate)

				log.Printf(
					"Probed %s/%s (%.1f%%, %spps), %s elapsed, est %s left.\n", humanize.Comma(int64(sentCount)),
					humanize.Comma(int64(totalCount)), float64(sentCount)/float64(totalCount)*100,
					humanize.Comma(int64(rate)), formatDuration(dur), formatDuration(left),
				)
			}
		}
	}
}

func recvPackets(ctx context.Context) {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting response receiving...")
	}

	handle, err := pcap.OpenLive(iface, 65536, false, time.Nanosecond)
	if err != nil {
		log.Fatalf("Failed to open interface: %v", err)
	}
	defer handle.Close()

	var filter = "udp src port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Failed to SetBPFFilter: %v", err)
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.Fatalf("Failed to SetDirection: %v", err)
	}

	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetRecvChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			if logLevel != 1 {
				log.Println("All responses received.")
			}

			storeChan <- ""

			return

		case packet := <-packetRecvChan:
			if err = parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}

			ip_ := ipv4.SrcIP.String()
			srcport_ := generatePort(ip_)
			txid_ := generateTxID(ip_)

			srcport := uint16(udp.DstPort)
			txid := dns_.ID

			if srcport != srcport_ || txid != txid_ {
				continue
			}

			if len(dns_.Questions) <= 0 {
				continue
			}

			flag_ := 0
			if dns_.ResponseCode != 3 {
				flag_ = 1
			}

			res := fmt.Sprintf("%s,%d", strings.ToLower(string(dns_.Questions[0].Name)), flag_)

			storeChan <- res
		}
	}
}

func storeResults() {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting result storing...")
	}

	f, _ := os.Create(outputFile)
	defer f.Close()
	w := bufio.NewWriter(f)

	for {
		res := <-storeChan
		if res == "" {
			if logLevel != 1 {
				log.Println("All results stored.")
			}

			break
		}

		w.WriteString(res + "\n")
		w.Flush()

		if logLevel == 1 || logLevel == 3 {
			fmt.Println(res)
		}

		atomic.AddUint64(&foundCount, 1)

		if logLevel != 0 && logLevel != 1 {
			if foundCount%uint64(rate) == 0 {
				log.Printf(
					"Resolved %s domain(s) (%.1f%%).\n", humanize.Comma(int64(foundCount)),
					float64(foundCount)/float64(sentCount)*100,
				)
			}
		}
	}
}

func showState() {
	dur := time.Since(startTime).Seconds()
	left := float64(totalCount-sentCount) / float64(rate)

	log.Printf("Current state:------------------------------\n")
	log.Printf(
		"Probed %s/%s (%.1f%%, %spps), %s elapsed, est %s left.\n", humanize.Comma(int64(sentCount)),
		humanize.Comma(int64(totalCount)), float64(sentCount)/float64(totalCount)*100, humanize.Comma(int64(rate)),
		formatDuration(dur), formatDuration(left),
	)
	log.Printf(
		"Resolved %s domain(s) (%.1f%%).\n", humanize.Comma(int64(foundCount)),
		float64(foundCount)/float64(sentCount)*100,
	)
}

func interactiveStatusReporter() {
	//if logLevel != 0 && logLevel != 1 {
	//	return
	//}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	inputChan := make(chan struct{})

	go func() {
		for {
			_, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
			if err == nil {
				inputChan <- struct{}{}
			}
		}
	}()

	for {
		select {
		case <-sigChan:
			fmt.Println("")
			showState()
			log.Println("Received interrupt signal (Ctrl+C). Exited.")

			os.Exit(0)
		case <-inputChan:
			showState()
		}
	}
}

func formatDuration(s float64) string {
	seconds := int(s)
	days := seconds / 86400
	seconds %= 86400
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	parts = append(parts, fmt.Sprintf("%ds", seconds))

	return strings.Join(parts, "")
}

func main() {
	initParams()

	startTime = time.Now()

	ctx, done := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(4)

	go func() { defer wg.Done(); recvPackets(ctx) }()
	go func() { defer wg.Done(); storeResults() }()
	go func() { defer wg.Done(); generatePackets() }()
	time.Sleep(1 * time.Second)
	go func() { defer wg.Done(); sendPackets(done) }()

	go interactiveStatusReporter()

	wg.Wait()

	duration := time.Since(startTime).Seconds()
	if logLevel != 1 {
		log.Printf(
			"Done. Cost time: %s. Resolved %s domain(s).\n", formatDuration(duration),
			humanize.Comma(int64(foundCount)),
		)
		log.Printf(
			"Saved to %s\n", outputFile,
		)
	}
}
