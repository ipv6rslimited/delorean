/*
**
** delorean
** A reverse IPv4 to IPv6 TLS SNI and HTTP proxy written in GoLang
**
** Distributed under the COOLER License.
**
** Copyright (c) 2024 IPv6.rs <https://ipv6.rs>
** All Rights Reserved
**
*/

package main

import (
  "bufio"
  "encoding/binary"
  "encoding/json"
  "fmt"
  "log"
  "net"
  "os"
  "os/signal"
  "strings"
  "sync"
  "syscall"
  "time"
  "github.com/ipv6rslimited/lrucache"
  "github.com/ipv6rslimited/peeker"
  "github.com/ipv6rslimited/peter"
)

type Config struct {
  Ports       []int  `json:"ports"`
  IP          string `json:"ip"`
  TTL         int    `json:"ttl"`
  Prefix      string `json:"prefix"`
}

type CacheEntry struct {
  Address     string
  Timestamp   time.Time
}

var (
  config      Config
  dnsCache =  lrucache.NewLRUCache(4096)
  servers     []net.Listener
  wg          sync.WaitGroup
  shutdown =  make(chan struct{})
  serverMutex sync.Mutex
  logger      *log.Logger
)

type nullWriter struct{}

func main() {
  enableLogging := false
  setLogger(enableLogging)

  logger.Println("Starting main function")
  loadConfig()
  handleSignals()

  for _, port := range config.Ports {
    logger.Printf("Starting server on port %d", port)
    go startServer(port)
  }

  select {}
}

func (nw nullWriter) Write(p []byte) (n int, err error) {
  return len(p), nil
}

func setLogger(enable bool) {
  if enable {
    logger = log.New(os.Stdout, "", log.LstdFlags)
  } else {
    logger = log.New(nullWriter{}, "", log.LstdFlags)
  }
}

func loadConfig() {
  logger.Println("Loading configuration")
  file, err := os.Open("proxy.conf")
  if err != nil {
    logger.Fatalf("Failed to open config file: %v", err)
  }
  defer file.Close()

  decoder := json.NewDecoder(file)
  if err := decoder.Decode(&config); err != nil {
    logger.Fatalf("Failed to decode config file: %v", err)
  }

  if len(config.Ports) == 0 || config.IP == "" || config.TTL == 0 || config.Prefix == "" {
    logger.Fatalf("Invalid configuration: %+v", config)
  }

  logger.Printf("Config loaded: %+v", config)
}

func handleSignals() {
  logger.Println("Setting up signal handling")
  signalChan := make(chan os.Signal, 1)
  signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

  go func() {
    for sig := range signalChan {
      switch sig {
      case syscall.SIGHUP:
        logger.Println("Received SIGHUP signal, reloading configuration")
        loadConfig()
        stopServers()
        for _, port := range config.Ports {
          go startServer(port)
        }
      case syscall.SIGINT, syscall.SIGTERM:
        logger.Println("Received SIGINT or SIGTERM signal, shutting down servers")
        stopServers()
        os.Exit(0)
      }
    }
  }()
}

func stopServers() {
  logger.Println("Stopping servers")
  serverMutex.Lock()
  defer serverMutex.Unlock()

  close(shutdown)
  for _, server := range servers {
    server.Close()
  }
  wg.Wait()
  servers = nil
  logger.Println("All servers stopped")
}

func startServer(port int) {
  listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.IP, port))
  if err != nil {
    logger.Printf("Failed to start server on port %d: %v", port, err)
    return
  }
  logger.Printf("Server started on %s:%d", config.IP, port)

  serverMutex.Lock()
  servers = append(servers, listener)
  serverMutex.Unlock()

  wg.Add(1)
  defer wg.Done()

  for {
    client, err := listener.Accept()
    if err != nil {
      select {
      case <-shutdown:
        logger.Printf("Shutting down server on port %d", port)
        return
      default:
        continue
      }
    }
    logger.Printf("Accepted connection from %s", client.RemoteAddr())
    go handleConnection(client)
  }
}

func handleConnection(client net.Conn) {
  defer client.Close()
  logger.Printf("Handling connection from %s", client.RemoteAddr())

  reader := bufio.NewReader(client)
  initialBytes, err := reader.Peek(5)
  if err != nil {
    logger.Printf("Failed to peek initial bytes: %v", err)
    return
  }

  var name string

  if isTLS(initialBytes) {
    logger.Println("Connection is TLS")
    name, err = getNameFromTLSConnection(reader)
  } else {
    logger.Println("Connection is HTTP")
    name, err = getNameFromHTTPConnection(reader)
  }

  if err != nil || name == "" {
    logger.Printf("Failed to get name from connection: %v", err)
    return
  }

  logger.Printf("Resolved name: %s", name)

  address, err := lookupWithCache(name)
  if err != nil {
    logger.Printf("Failed to lookup address: %v", err)
    return
  }

  logger.Printf("Resolved address: %s", address)

  backend, err := net.Dial("tcp", net.JoinHostPort(address, fmt.Sprint(client.LocalAddr().(*net.TCPAddr).Port)))
  if err != nil {
    logger.Printf("Failed to connect to backend: %v", err)
    return
  }

  bufferedData := make([]byte, reader.Buffered())
  _, err = reader.Read(bufferedData)
  if err != nil {
    logger.Printf("Failed to read buffered data: %v", err)
    backend.Close()
    return
  }

  _, err = backend.Write(bufferedData)
  if err != nil {
    logger.Printf("Failed to write buffered data to backend: %v", err)
    backend.Close()
    return
  }

  logger.Println("Starting data piping between client and backend")
  piper := peter.NewPeter(client, backend)
  piper.Start()
}

func getNameFromTLSConnection(reader *bufio.Reader) (string, error) {
  logger.Println("Extracting name from TLS connection")
  p := peeker.NewPeeker(reader)

  _, err := p.GetBytes(43)
  if err != nil {
    return "", fmt.Errorf("failed to read initial bytes: %w", err)
  }

  sessionIDLength, err := p.GetByte()
  if err != nil {
    return "", fmt.Errorf("failed to read session ID length: %w", err)
  }

  _, err = p.GetBytes(int(sessionIDLength))
  if err != nil {
    return "", fmt.Errorf("failed to read session ID: %w", err)
  }

  cipherSuitesLengthBytes, err := p.GetBytes(2)
  if err != nil {
    return "", fmt.Errorf("failed to read cipher suites length: %w", err)
  }
  cipherSuitesLength := binary.BigEndian.Uint16(cipherSuitesLengthBytes)

  _, err = p.GetBytes(int(cipherSuitesLength))
  if err != nil {
    return "", fmt.Errorf("failed to read cipher suites: %w", err)
  }

  compressionMethodsLength, err := p.GetByte()
  if err != nil {
    return "", fmt.Errorf("failed to read compression methods length: %w", err)
  }

  _, err = p.GetBytes(int(compressionMethodsLength))
  if err != nil {
    return "", fmt.Errorf("failed to read compression methods: %w", err)
  }

  extensionsLengthBytes, err := p.GetBytes(2)
  if err != nil {
    return "", fmt.Errorf("failed to read extensions length: %w", err)
  }

  extensionsLength := binary.BigEndian.Uint16(extensionsLengthBytes)
  extensionsEndIndex := p.Offset + int(extensionsLength)

  for p.Offset < extensionsEndIndex {
    extensionTypeBytes, err := p.GetBytes(2)
    if err != nil {
      return "", fmt.Errorf("failed to read extension type: %w", err)
    }

    extensionType := binary.BigEndian.Uint16(extensionTypeBytes)

    extensionLengthBytes, err := p.GetBytes(2)
    if err != nil {
      return "", fmt.Errorf("failed to read extension length: %w", err)
    }
    extensionLength := binary.BigEndian.Uint16(extensionLengthBytes)

    if extensionType == 0x0000 {
      if _, err := p.GetBytes(2); err != nil {
        return "", fmt.Errorf("failed to skip server name list length: %w", err)
      }

      serverNameType, err := p.GetByte()
      if err != nil {
        return "", fmt.Errorf("failed to read server name type: %w", err)
      }
      if serverNameType != 0 {
        break
      }

      serverNameLengthBytes, err := p.GetBytes(2)
      if err != nil {
        return "", fmt.Errorf("failed to read server name length: %w", err)
      }
      serverNameLength := binary.BigEndian.Uint16(serverNameLengthBytes)

      serverNameBytes, err := p.GetBytes(int(serverNameLength))
      if err != nil {
        return "", fmt.Errorf("failed to read server name: %w", err)
      }

      serverName := string(serverNameBytes)
      logger.Printf("Extracted server name from TLS: %s", serverName)
      return serverName, nil
    } else {
      _, err = p.GetBytes(int(extensionLength))
      if err != nil {
        return "", fmt.Errorf("failed to skip extension: %w", err)
      }
    }
  }
  return "", fmt.Errorf("SNI extension not found")
}

func getNameFromHTTPConnection(reader *bufio.Reader) (string, error) {
  logger.Println("Extracting name from HTTP connection")
  p := peeker.NewPeeker(reader)
  for {
    line, err := p.GetLine()
    if err != nil {
      return "", err
    }

    if strings.HasPrefix(line, "Host: ") {
      host := strings.TrimSpace(line[6:])
      logger.Printf("Extracted host from HTTP: %s", host)
      return host, nil
    }

    if len(line) == 0 {
      break
    }
  }
  return "", fmt.Errorf("host header not found")
}

func lookupWithCache(hostname string) (string, error) {
  logger.Printf("Looking up hostname: %s", hostname)
  if entry, found := dnsCache.Get(hostname); found {
    cacheEntry := entry.(CacheEntry)
    if time.Since(cacheEntry.Timestamp) < time.Duration(config.TTL)*time.Second {
      logger.Printf("Cache hit for hostname: %s, address: %s", hostname, cacheEntry.Address)
      return cacheEntry.Address, nil
    }
    go lookupRaw(hostname)
    logger.Printf("Cache stale for hostname: %s, using old address while refreshing", hostname)
    return cacheEntry.Address, nil
  }
  logger.Printf("Cache miss for hostname: %s", hostname)
  return lookupRaw(hostname)
}

func lookupRaw(hostname string) (string, error) {
  logger.Printf("Performing raw lookup for hostname: %s", hostname)
  addresses, err := net.LookupIP(hostname)
  if err != nil {
    logger.Printf("Raw lookup failed for hostname: %s, error: %v", hostname, err)
    return "", err
  }

  var ipv6rsAddress string
  for _, addr := range addresses {
    if addr.To4() == nil && addr.To16() != nil && strings.HasPrefix(addr.String(), config.Prefix) {
      ipv6rsAddress = addr.String()
      break
    }
  }

  if ipv6rsAddress == "" {
    logger.Printf("No IPv6rs addresses found for hostname: %s", hostname)
    return "", fmt.Errorf("no IPv6rs addresses found")
  }

  dnsCache.Put(hostname, CacheEntry{Address: ipv6rsAddress, Timestamp: time.Now()})
  logger.Printf("Raw lookup succeeded for hostname: %s, address: %s", hostname, ipv6rsAddress)
  return ipv6rsAddress, nil
}

func isTLS(data []byte) bool {
  return len(data) > 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x01
}
