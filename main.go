package main

import (
	"bufio"
	"compress/gzip"
	"container/ring"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/time/rate"
)

// DNSType 定义 DNS 类型
type DNSType string

const (
	DNSTypeDoH         DNSType = "doh"
	DNSTypeDoT         DNSType = "dot"
	TimeFormatStandard         = "2006-01-02 15:04:05.000" // 标准时间格式，带毫秒
)

// Config 定义程序的配置文件结构
type Config struct {
	SPathsAll             []string        `json:"sPathsAll"`
	SPool                 []string        `json:"sPool"`
	ActivePaths           []string        `json:"activePaths"`
	Interval              int             `json:"interval"` // 同步间隔（分钟）
	ScanListTime          time.Time       `json:"scanListTime"`
	DNSType               DNSType         `json:"dnsType"`
	DNSServer             string          `json:"dnsServer"`
	DNSEnabled            bool            `json:"dnsEnabled"`
	LogSize               int             `json:"logSize"`
	BandwidthLimitEnabled bool            `json:"bandwidthLimitEnabled"`
	BandwidthLimitMBps    float64         `json:"bandwidthLimitMBps"`
	MaxConcurrency        int             `json:"maxConcurrency"`
	PathUpdateNotices     map[string]bool `json:"pathUpdateNotices"`
	ServerPathCounts      map[string]int  `json:"serverPathCounts"`
	LocalPathCounts       map[string]int  `json:"localPathCounts"`
	MemoryLimitEnabled    bool            `json:"memoryLimitEnabled"` //内存限制开关
	MemoryLimitMB         float64         `json:"memoryLimitMB"`      //内存限制（MB）
}

// LogEntry 定义日志条目结构
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	NanoTime  int64  `json:"-"` // 排序用，纳秒级
	Type      string `json:"type"`
	Message   string `json:"message"`
}

// SyncState 定义同步状态结构
type SyncState struct {
	Running   bool
	Trigger   chan struct{}
	LastStart time.Time
	SyncDone  chan struct{} // 通知主同步退出
}

// ServerInfo 定义服务器信息结构
type ServerInfo struct {
	URL          string
	ResponseTime time.Duration
}

// FileInfo 定义文件信息结构
type FileInfo struct {
	Path      string
	Timestamp int64
}

// FileInfoMap 定义文件信息映射类型
type FileInfoMap map[string]int64 // key: 路径, value: 时间戳

// LocalFileInfo 结构体整合路径计数等元数据
type LocalFileInfo struct {
	Files  FileInfoMap
	Counts map[string]int
}

type ServerFileInfo struct {
	Files  FileInfoMap    // 文件路径到时间戳的映射
	Counts map[string]int // 路径到文件数量的映射
}

// 全局变量
var (
	config     Config
	configMu   sync.RWMutex
	httpClient *http.Client
	logs       *ring.Ring
	logsMu     sync.Mutex
	syncState  = SyncState{
		Running:  true,
		Trigger:  make(chan struct{}, 1),
		SyncDone: make(chan struct{}),
	}
	//go:embed static/*
	staticFiles    embed.FS
	syncStateMu    sync.Mutex
	shanghaiLoc    *time.Location      // 东八区时区
	intervalChange = make(chan int, 1) // interval 变更通道
)

// CustomResolver 自定义 DNS 解析器
type CustomResolver struct {
	Type       DNSType
	Server     string
	HTTPClient *http.Client
}

// formatTime 将时间格式化为东八区
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(shanghaiLoc).Format(TimeFormatStandard)
}
func (r *CustomResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	server := r.Server
	if r.Type == DNSTypeDoH {
		if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
			server = "https://" + server
		}
		if !strings.HasSuffix(server, "/dns-query") {
			server += "/dns-query"
		}
		data, err := msg.Pack()
		if err != nil {
			return nil, err
		}
		resp, err := r.HTTPClient.Post(server, "application/dns-message", strings.NewReader(string(data)))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var reply dns.Msg
		if err := reply.Unpack(body); err != nil {
			return nil, err
		}
		return extractIPs(&reply), nil
	} else if r.Type == DNSTypeDoT {
		if strings.Contains(server, "://") {
			server = strings.SplitN(server, "://", 2)[1]
		}
		if !strings.Contains(server, ":") {
			server += ":853"
		}
		conn, err := tls.Dial("tcp", server, &tls.Config{
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		dnsConn := &dns.Conn{Conn: conn}
		if err := dnsConn.WriteMsg(msg); err != nil {
			return nil, err
		}
		reply, err := dnsConn.ReadMsg()
		if err != nil {
			return nil, err
		}
		return extractIPs(reply), nil
	}
	return net.DefaultResolver.LookupHost(ctx, hostname)
}
func extractIPs(msg *dns.Msg) []string {
	var ips []string
	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

// CustomDialer 使用自定义 DNS 解析
type CustomDialer struct {
	Resolver *CustomResolver
}

func (d *CustomDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := d.Resolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

// testDNS 测试 DNS 解析能力并返回可用模式
func testDNS(resolver *CustomResolver, defaultType DNSType) (DNSType, error) {
	testDomains := []string{"dash.cloudflare.com", "www.bing.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var primaryType, secondaryType DNSType
	if defaultType == DNSTypeDoT {
		primaryType = DNSTypeDoT
		secondaryType = DNSTypeDoH
	} else {
		primaryType = DNSTypeDoH
		secondaryType = DNSTypeDoT
	}

	resolver.Type = primaryType
	addLog("info", fmt.Sprintf("测试 %s 解析 (服务器: %s)", primaryType, resolver.Server))
	primarySuccess := true
	for _, domain := range testDomains {
		ips, err := resolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("%s 解析 %s 失败: %v", primaryType, domain, err))
			primarySuccess = false
			break
		}
		addLog("info", fmt.Sprintf("%s 解析 %s 成功: %v", primaryType, domain, ips))
	}
	if primarySuccess {
		return primaryType, nil
	}

	resolver.Type = secondaryType
	addLog("info", fmt.Sprintf("主模式 %s 失败，测试 %s 解析 (服务器: %s)", primaryType, secondaryType, resolver.Server))
	secondarySuccess := true
	for _, domain := range testDomains {
		ips, err := resolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("%s 解析 %s 失败: %v", secondaryType, domain, err))
			secondarySuccess = false
			break
		}
		addLog("info", fmt.Sprintf("%s 解析 %s 成功: %v", secondaryType, domain, ips))
	}
	if secondarySuccess {
		return secondaryType, nil
	}

	addLog("info", "自定义 DNS 不可用，测试本地 DNS")
	localSuccess := true
	for _, domain := range testDomains {
		ips, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err != nil || len(ips) == 0 {
			addLog("warning", fmt.Sprintf("本地 DNS 解析 %s 失败: %v", domain, err))
			localSuccess = false
			break
		}
		addLog("info", fmt.Sprintf("本地 DNS 解析 %s 成功: %v", domain, ips))
	}
	if localSuccess {
		return "", nil
	}

	return "", fmt.Errorf("所有 DNS 模式均不可用")
}

// initHttpClient 初始化 HTTP 客户端
func initHttpClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	addLog("info", "开始初始化 HTTP 客户端")
	configMu.RLock()
	dnsEnabled := config.DNSEnabled
	dnsType := config.DNSType
	dnsServer := config.DNSServer
	bandwidthLimitEnabled := config.BandwidthLimitEnabled
	bandwidthLimitMBps := config.BandwidthLimitMBps
	configMu.RUnlock()

	if dnsEnabled {
		dohClient := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
		resolver := &CustomResolver{
			Type:       dnsType,
			Server:     dnsServer,
			HTTPClient: dohClient,
		}
		testedType, err := testDNS(resolver, dnsType)
		configMu.Lock()
		if err != nil {
			addLog("warning", "所有 DNS 模式测试失败，将使用系统默认 DNS")
			config.DNSEnabled = false
		} else if testedType == "" {
			addLog("info", "自定义 DNS 不可用，使用系统默认 DNS")
			config.DNSEnabled = false
		} else {
			config.DNSType = testedType
			resolver.Type = testedType
			transport.DialContext = (&CustomDialer{Resolver: resolver}).DialContext
			addLog("success", fmt.Sprintf("DNS 配置生效: %s (服务器: %s)", config.DNSType, config.DNSServer))
		}
		configMu.Unlock()
	} else {
		addLog("info", "自定义 DNS 未启用，使用系统默认 DNS")
		transport.DialContext = nil
	}

	var finalTransport http.RoundTripper = transport
	if bandwidthLimitEnabled {
		// MB/s 转换为 bytes/s
		bytesPerSecond := bandwidthLimitMBps * 1024 * 1024
		limiter := rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond))
		finalTransport = &limitedTransport{
			limiter:      limiter,
			roundTripper: transport,
		}
		addLog("info", fmt.Sprintf("带宽限制启用: %.2f MB/s", bandwidthLimitMBps))
	} else {
		addLog("info", "带宽限制未启用")
	}

	httpClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: finalTransport,
	}
	addLog("info", "HTTP 客户端初始化完成")
}

// limitedTransport 实现带宽限制的 Transport
type limitedTransport struct {
	limiter      *rate.Limiter
	roundTripper http.RoundTripper
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.roundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedReader{
		reader:  resp.Body,
		limiter: t.limiter,
		ctx:     req.Context(),
	}
	return resp, nil
}

// limitedReader 限制读取速度的 io.ReadCloser
type limitedReader struct {
	reader  io.ReadCloser
	limiter *rate.Limiter
	ctx     context.Context
}

func (r *limitedReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err != nil {
		return n, err
	}
	err = r.limiter.WaitN(r.ctx, n)
	return n, err
}
func (r *limitedReader) Close() error {
	return r.reader.Close()
}

// addLog 添加日志到环形缓冲区
func addLog(logType, message string) {
	logsMu.Lock()
	defer logsMu.Unlock()
	now := time.Now()
	logs.Value = LogEntry{
		Timestamp: formatTime(now),
		NanoTime:  now.UnixNano(),
		Type:      logType,
		Message:   message,
	}
	logs = logs.Next()
}

// getLogs 获取日志条目，支持分页和搜索
func getLogs(limit, page int, filter, search string) ([]LogEntry, int) {
	logsMu.Lock()
	defer logsMu.Unlock()

	allLogs := make([]LogEntry, 0, config.LogSize)
	r := logs
	for i := 0; i < config.LogSize; i++ {
		if r.Value != nil {
			allLogs = append(allLogs, r.Value.(LogEntry))
		}
		r = r.Next()
	}

	if len(allLogs) == 0 {
		return []LogEntry{}, 0
	}

	// 按纳秒时间戳降序排序（最新日志在前）
	sort.Slice(allLogs, func(i, j int) bool {
		return allLogs[i].NanoTime > allLogs[j].NanoTime
	})

	var filteredLogs []LogEntry
	if filter != "" {
		for _, log := range allLogs {
			if log.Type == filter {
				filteredLogs = append(filteredLogs, log)
			}
		}
	} else {
		filteredLogs = allLogs
	}

	if search != "" {
		search = strings.ToLower(search)
		var searchedLogs []LogEntry
		for _, log := range filteredLogs {
			if strings.Contains(strings.ToLower(log.Message), search) ||
				strings.Contains(strings.ToLower(log.Timestamp), search) ||
				strings.Contains(strings.ToLower(log.Type), search) {
				searchedLogs = append(searchedLogs, log)
			}
		}
		filteredLogs = searchedLogs
	}

	total := len(filteredLogs)
	if total == 0 {
		return []LogEntry{}, 0
	}

	start := (page - 1) * limit
	if start >= total {
		return []LogEntry{}, total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return filteredLogs[start:end], total
}

// loadConfig 从 config.json 加载配置
func loadConfig() error {
	mediaDir := flag.Lookup("media").Value.String()
	configFilePath := filepath.Join(mediaDir, "config.json")
	configFile, err := os.Open(configFilePath)
	if err != nil {
		// 检查根目录的 config.json
		rootConfigPath := "config.json"
		rootConfigFile, rootErr := os.Open(rootConfigPath)
		if rootErr == nil {
			// 根目录存在 config.json，拷贝到 mediaDir
			defer rootConfigFile.Close()
			// 确保 mediaDir 存在
			if err := os.MkdirAll(mediaDir, 0755); err != nil {
				return fmt.Errorf("创建媒体目录 %s 失败：%v", mediaDir, err)
			}
			// 读取根目录 config.json 内容
			var rootConfig Config
			if err := json.NewDecoder(rootConfigFile).Decode(&rootConfig); err != nil {
				return fmt.Errorf("解析根目录配置文件 %s 失败：%v", rootConfigPath, err)
			}
			// 初始化 LocalPathCounts
			if rootConfig.LocalPathCounts == nil {
				rootConfig.LocalPathCounts = make(map[string]int)
			}
			// 保存到 mediaDir
			configMu.Lock()
			config = rootConfig
			configMu.Unlock()
			addLog("info", fmt.Sprintf("配置文件 %s 未找到，从根目录 %s 拷贝默认配置", configFilePath, rootConfigPath))
			return saveConfig()
		}
		// 根目录也没有 config.json，创建默认配置
		configMu.Lock()
		config = Config{
			Interval:              60, // 默认改为 60 分钟（1小时）
			DNSType:               DNSTypeDoH,
			DNSServer:             "https://1.1.1.1/dns-query",
			DNSEnabled:            true,
			LogSize:               1000,
			BandwidthLimitEnabled: false,
			BandwidthLimitMBps:    5.0,
			MaxConcurrency:        500,
			PathUpdateNotices:     make(map[string]bool),
			ServerPathCounts:      make(map[string]int),
			LocalPathCounts:       make(map[string]int), // 初始化 LocalPathCounts
			MemoryLimitEnabled:    false,                // 默认关闭内存限制
			MemoryLimitMB:         512.0,                // 默认 512MB
		}
		configMu.Unlock()
		addLog("info", fmt.Sprintf("配置文件 %s 和根目录配置文件均未找到，已创建默认配置", configFilePath))
		return saveConfig()
	}
	defer configFile.Close()

	var newConfig Config
	err = json.NewDecoder(configFile).Decode(&newConfig)
	if err != nil {
		return err
	}

	if newConfig.LogSize <= 0 {
		newConfig.LogSize = 1000
	}
	if newConfig.Interval <= 0 {
		newConfig.Interval = 60
	}
	if newConfig.MaxConcurrency <= 0 {
		newConfig.MaxConcurrency = 500
	}
	if newConfig.PathUpdateNotices == nil {
		newConfig.PathUpdateNotices = make(map[string]bool)
	}
	if newConfig.ServerPathCounts == nil {
		newConfig.ServerPathCounts = make(map[string]int)
	}
	if newConfig.LocalPathCounts == nil {
		newConfig.LocalPathCounts = make(map[string]int)
	}
	if newConfig.MemoryLimitMB <= 0 {
		newConfig.MemoryLimitMB = 512.0 // 默认 512MB
	}
	if !newConfig.MemoryLimitEnabled {
		newConfig.MemoryLimitEnabled = false
	}

	logsMu.Lock()
	currentSize := logs.Len()
	if currentSize != newConfig.LogSize {
		logsMu.Unlock()
		oldLogs, _ := getLogs(currentSize, 1, "", "")
		logsMu.Lock()
		newLogs := ring.New(newConfig.LogSize)
		for i := 0; i < len(oldLogs) && i < newConfig.LogSize; i++ {
			newLogs.Value = oldLogs[len(oldLogs)-1-i]
			newLogs = newLogs.Next()
		}
		logs = newLogs
		timestamp := formatTime(time.Now())
		logs.Value = LogEntry{Timestamp: timestamp, NanoTime: time.Now().UnixNano(), Type: "info", Message: fmt.Sprintf("日志缓冲区大小调整为 %d", newConfig.LogSize)}
		logs = logs.Next()
	}
	logsMu.Unlock()

	configMu.Lock()
	config = newConfig
	configMu.Unlock()

	addLog("info", "配置文件加载成功")
	return nil
}

// saveConfig 保存配置到 config.json
func saveConfig() error {
	mediaDir := flag.Lookup("media").Value.String()
	configFilePath := filepath.Join(mediaDir, "config.json")
	configFile, err := os.Create(configFilePath)
	if err != nil {
		return err
	}
	defer configFile.Close()
	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

// cleanFileName 清理文件名中的非法字符
func cleanFileName(name string) string {
	invalidChars := regexp.MustCompile(`/`)
	return invalidChars.ReplaceAllString(name, "_")
}

// pickBestServers 选择时间戳最新且响应最快的服务器，仅选择时间戳一致的备选服务器
func pickBestServers(pool []string) []ServerInfo {
	var wg sync.WaitGroup
	serverInfos := make([]ServerInfo, len(pool))
	var mu sync.Mutex
	type serverDetail struct {
		info         ServerInfo
		lastModified time.Time
	}
	details := make([]serverDetail, len(pool))

	// 并行请求所有服务器
	for i, url := range pool {
		wg.Add(1)
		go func(index int, serverURL string) {
			defer wg.Done()
			start := time.Now()
			resp, err := httpClient.Get(serverURL + "/.scan.list.gz")
			if err != nil || resp.StatusCode != 200 {
				mu.Lock()
				serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
				details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			// 解析 Last-Modified 时间戳
			lastModifiedStr := resp.Header.Get("Last-Modified")
			var lastModified time.Time
			if lastModifiedStr != "" {
				var err error
				lastModified, err = time.Parse(time.RFC1123, lastModifiedStr)
				if err != nil {
					addLog("warning", fmt.Sprintf("服务器 %s 解析 Last-Modified 失败：%v", serverURL, err))
					mu.Lock()
					serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
					details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
					mu.Unlock()
					return
				}
			} else {
				addLog("warning", fmt.Sprintf("服务器 %s 未提供 Last-Modified 头", serverURL))
				mu.Lock()
				serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: 0}
				details[index] = serverDetail{info: serverInfos[index], lastModified: time.Time{}}
				mu.Unlock()
				return
			}

			responseTime := time.Since(start)
			mu.Lock()
			serverInfos[index] = ServerInfo{URL: serverURL, ResponseTime: responseTime}
			details[index] = serverDetail{info: serverInfos[index], lastModified: lastModified}
			mu.Unlock()
		}(i, url)
	}
	wg.Wait()

	// 找到最新的 Last-Modified 时间戳
	var latestTime time.Time
	for _, detail := range details {
		if !detail.lastModified.IsZero() && (latestTime.IsZero() || detail.lastModified.After(latestTime)) {
			latestTime = detail.lastModified
		}
	}

	if latestTime.IsZero() {
		addLog("error", "没有服务器提供有效的 Last-Modified 时间戳")
		return []ServerInfo{}
	}

	// 选择时间戳等于最新的服务器
	var candidates []serverDetail
	for _, detail := range details {
		if !detail.lastModified.IsZero() && detail.lastModified.Equal(latestTime) {
			candidates = append(candidates, detail)
		}
	}

	if len(candidates) == 0 {
		addLog("error", "没有服务器具有最新时间戳")
		return []ServerInfo{}
	}

	// 按响应时间排序
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].info.ResponseTime < candidates[j].info.ResponseTime
	})

	// 选择最快的主服务器，最多 2 个备选服务器（总共最多 3 个）
	result := make([]ServerInfo, 0, 3)
	for i, candidate := range candidates {
		if i >= 3 {
			break
		}
		result = append(result, candidate.info)
	}

	if len(result) == 0 {
		addLog("error", "没有可用的服务器")
		return []ServerInfo{}
	}

	// 日志记录
	addLog("info", fmt.Sprintf("选择主服务器 %s（响应时间：%s，更新时间：%s）",
		result[0].URL, result[0].ResponseTime, formatTime(latestTime)))
	if len(result) > 1 {
		addLog("info", fmt.Sprintf("备用服务器1：%s（响应时间：%s）", result[1].URL, result[1].ResponseTime))
	}
	if len(result) > 2 {
		addLog("info", fmt.Sprintf("备用服务器2：%s（响应时间：%s）", result[2].URL, result[2].ResponseTime))
	}
	if len(candidates) > 3 {
		addLog("info", fmt.Sprintf("存在更多符合条件的服务器（共 %d 个），仅选择最快的 3 个", len(candidates)))
	}

	return result
}

// handleRefreshLocal 刷新本地文件数据并更新文件数量
func handleRefreshLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	mediaDir := flag.Lookup("media").Value.String()
	configMu.RLock()
	paths := config.SPathsAll
	configMu.RUnlock()

	// 使用新的内存Map方式扫描
	localMap, err := scanLocalFilesToMap(mediaDir, paths)
	if err != nil {
		addLog("error", fmt.Sprintf("刷新本地文件映射失败：%v", err))
		http.Error(w, "刷新本地文件映射失败", http.StatusInternalServerError)
		return
	}

	// 更新配置中的路径计数
	configMu.Lock()
	if config.LocalPathCounts == nil {
		config.LocalPathCounts = make(map[string]int)
	}

	for path, count := range localMap.Counts {
		config.LocalPathCounts[path] = count
	}

	// 清理不存在的路径
	for path := range config.LocalPathCounts {
		found := false
		for _, p := range paths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			delete(config.LocalPathCounts, path)
		}
	}

	if err := saveConfig(); err != nil {
		configMu.Unlock()
		addLog("error", fmt.Sprintf("保存配置文件失败：%v", err))
		http.Error(w, "保存配置文件失败", http.StatusInternalServerError)
		return
	}
	configMu.Unlock()

	addLog("success", "本地文件数量刷新完成")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// scanLocalFilesToMap 扫描本地文件并生成文件信息Map
func scanLocalFilesToMap(mediaDir string, paths []string) (*LocalFileInfo, error) {
	startTime := time.Now()
	addLog("info", fmt.Sprintf("开始扫描 %d 个路径", len(paths)))

	result := &LocalFileInfo{
		Files:  make(FileInfoMap),
		Counts: make(map[string]int),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 检查内存限制
	configMu.RLock()
	memoryLimitEnabled := config.MemoryLimitEnabled
	memoryLimitBytes := uint64(config.MemoryLimitMB * 1024 * 1024)
	configMu.RUnlock()

	// 并发扫描每个路径
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			dirPath := filepath.Join(mediaDir, p)
			count := 0

			err := filepath.Walk(dirPath, func(filePath string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}

				relativePath, _ := filepath.Rel(mediaDir, filePath)
				relativePath = filepath.ToSlash(relativePath)

				// 检查内存使用
				if memoryLimitEnabled {
					var memStats runtime.MemStats
					runtime.ReadMemStats(&memStats)
					if memStats.Alloc > memoryLimitBytes {
						addLog("error", fmt.Sprintf("内存使用超过限制（%.2f MB），停止扫描路径 %s", config.MemoryLimitMB, p))
						return fmt.Errorf("内存超限")
					}
				}

				mu.Lock()
				result.Files[relativePath] = info.ModTime().Unix()
				mu.Unlock()
				count++

				return nil
			})

			if err == nil {
				mu.Lock()
				result.Counts[p] = count
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()

	// 清理无效路径计数
	for path := range result.Counts {
		if !contains(paths, path) {
			delete(result.Counts, path)
		}
	}

	duration := time.Since(startTime)
	addLog("success", fmt.Sprintf("本地扫描完成，共 %d 个文件，耗时 %s",
		len(result.Files), formatDuration(duration)))
	return result, nil
}

// compareAndPrepareSync 对比内存Map和服务器Map，返回需要更新和删除的文件
func compareAndPrepareSync(localMap FileInfoMap, serverInfo *ServerFileInfo, paths []string) ([]FileInfo, []string, error) {
	addLog("info", "开始差异对比")

	toUpdate := make([]FileInfo, 0)
	toDelete := make([]string, 0)
	pathNotice := make(map[string]bool)

	// 检查服务器文件更新
	for path, serverTS := range serverInfo.Files {
		shouldSync := false
		for _, prefix := range paths {
			if strings.HasPrefix(path, prefix) {
				shouldSync = true
				break
			}
		}
		if !shouldSync {
			continue
		}

		localTS, exists := localMap[path]
		if !exists || serverTS-localTS > 600 { // 服务器比本地超过 10 分钟
			toUpdate = append(toUpdate, FileInfo{Path: path, Timestamp: serverTS})
		}
	}

	// 检查需要删除的文件
	for path := range localMap {
		shouldDelete := false
		for _, prefix := range paths {
			if strings.HasPrefix(path, prefix) {
				shouldDelete = true
				break
			}
		}
		if !shouldDelete {
			continue
		}

		if _, exists := serverInfo.Files[path]; !exists {
			toDelete = append(toDelete, path)
		}
	}

	// 更新路径变更通知
	for _, file := range toUpdate {
		rootDir := getRootDir(file.Path)
		if rootDir != "" && !contains(paths, rootDir) {
			pathNotice[rootDir] = true
		}
	}

	// 原子更新配置
	configMu.Lock()
	for k := range config.PathUpdateNotices {
		if !pathNotice[k] {
			delete(config.PathUpdateNotices, k)
		}
	}
	for k, v := range pathNotice {
		config.PathUpdateNotices[k] = v
	}
	saveConfig()
	configMu.Unlock()

	addLog("info", fmt.Sprintf("内存对比完成：需更新 %d 个文件，需删除 %d 个文件",
		len(toUpdate), len(toDelete)))
	return toUpdate, toDelete, nil
}

// 修改后的 downloadFile 函数，支持上下文取消
func downloadFile(ctx context.Context, file FileInfo, servers []ServerInfo, media, cleanedPath string) error {
	localPath := filepath.Join(media, cleanedPath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0777); err != nil {
		return fmt.Errorf("创建目录失败：%v", err)
	}

	var attemptErrors []string
	for i, server := range servers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			encodedUrlPath := url.PathEscape(file.Path)
			url := server.URL + "/" + encodedUrlPath
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 创建请求失败：%v", server.URL, err))
				continue
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 下载失败：%v", server.URL, err))
				if i < len(servers)-1 {
					continue
				}
				return fmt.Errorf("所有服务器下载 %s 失败：%s", file.Path, strings.Join(attemptErrors, "; "))
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound { // 404
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 返回 404", server.URL))
				// 提前退出，无需尝试其他服务器
				return fmt.Errorf("文件 %s 在服务器上不存在：%s", file.Path, strings.Join(attemptErrors, "; "))
			} else if resp.StatusCode != http.StatusOK {
				attemptErrors = append(attemptErrors, fmt.Sprintf("服务器 %s 返回状态码 %d", server.URL, resp.StatusCode))
				if i < len(servers)-1 {
					continue
				}
				return fmt.Errorf("所有服务器下载 %s 失败：%s", file.Path, strings.Join(attemptErrors, "; "))
			}

			// 下载成功
			out, err := os.Create(localPath + ".tmp")
			if err != nil {
				return fmt.Errorf("创建文件 %s 失败：%v", localPath, err)
			}
			_, err = io.Copy(out, resp.Body)
			out.Close()
			if err != nil {
				os.Remove(localPath + ".tmp")
				return fmt.Errorf("写入文件 %s 失败：%v", localPath, err)
			}
			if err := os.Rename(localPath+".tmp", localPath); err != nil {
				os.Remove(localPath + ".tmp")
