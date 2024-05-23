/*
**
** delorean
** A reverse IPv4 to IPv6 TLS SNI and HTTP proxy written in GoLang
**
** Distributed under the COOL License.
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
  "io"
  "log"
  "net"
  "os"
  "os/signal"
  "strings"
  "sync"
  "syscall"
  "time"
  "github.com/ipv6rslimited/lrucache"
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
  config                Config
  dnsCache            = lrucache.NewLRUCache(4096)
  servers               []net.Listener
  wg                    sync.WaitGroup
  logger               *log.Logger
  shutdown              chan struct{}
  maxBufferedDataSize = 16384
  maxConnectTime      = 30
)

type nullWriter struct{}


func main() {
  enableLogging := false
  setLogger(enableLogging)

  logger.Println("Starting main function")
  loadConfig()
  handleSignals()

  startAllServers()

  wg.Wait()
}

func startAllServers() {
  logger.Println("Starting all servers")
  shutdown = make(chan struct{})
  for _, port := range config.Ports {
    wg.Add(1)
    go func(port int) {
      defer wg.Done()
      startServer(port)
    }(port)
  }
}

func handleSignals() {
  logger.Println("Setting up signal handling")
  signalChan := make(chan os.Signal, 1)
  signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

  go func() {
    for sig := range signalChan {
      switch sig {
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
  close(shutdown)

  for _, server := range servers {
    logger.Printf("Closing server on %s", server.Addr())
    server.Close()
  }
  servers = nil

  time.Sleep(2 * time.Second)

  wg.Wait()

  logger.Println("All servers stopped")
}

func startServer(port int) {
  listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.IP, port))
  if err != nil {
    logger.Printf("Failed to start server on port %d: %v", port, err)
    return
  }
  logger.Printf("Server started on %s:%d", config.IP, port)

  servers = append(servers, listener)

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

func handleConnection(client net.Conn) {
  defer client.Close()

  logger.Printf("Handling connection from %s", client.RemoteAddr())
  client.SetDeadline(time.Now().Add(time.Duration(maxConnectTime) * time.Second))

  reader := bufio.NewReader(client)
  initialBytes, err := reader.Peek(5)
  if err != nil {
    logger.Printf("Failed to peek initial bytes: %v", err)
    return
  }

  var name string
  var bufferedData []byte

  if isTLS(initialBytes) {
    logger.Println("Connection is TLS")
    name, bufferedData, err = getNameAndBufferFromTLSConnection(reader)
  } else {
    logger.Println("Connection is HTTP")
    name, bufferedData, err = getNameAndBufferFromHTTPConnection(reader)
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

  backend, err := net.DialTimeout("tcp", net.JoinHostPort(address, fmt.Sprint(client.LocalAddr().(*net.TCPAddr).Port)), time.Duration(maxConnectTime)*time.Second)
  if err != nil {
    logger.Printf("Failed to connect to backend: %v", err)
    return
  }
  defer backend.Close()

  client.SetDeadline(time.Time{})
  backend.SetDeadline(time.Time{})

  logger.Printf("Writing buffer: %x", bufferedData)
  _, err = backend.Write(bufferedData)
  if err != nil {
    logger.Printf("Failed to write buffered data to backend: %v", err)
    return
  }

  logger.Println("Starting data piping between client and backend")
  piper := peter.NewPeter(client, backend)
  piper.Start()
  defer logger.Println("Ending data piping between client and backend")
}

func getNameAndBufferFromHTTPConnection(reader *bufio.Reader) (string, []byte, error) {
  logger.Println("Extracting name from HTTP connection")
  bufferedData := make([]byte, 0, maxBufferedDataSize)
  var host string

  for {
    line, err := reader.ReadString('\n')
    if err != nil {
      if err == io.EOF {
        break
      }
      return "", nil, fmt.Errorf("failed to read line: %w", err)
    }

    bufferedData = append(bufferedData, []byte(line)...)
    if len(bufferedData) > maxBufferedDataSize {
      return "", nil, fmt.Errorf("buffered data exceeds maximum size")
    }

    line = strings.TrimRight(line, "\r\n")

    if strings.HasPrefix(line, "Host: ") {
      host = strings.TrimSpace(line[6:])
      logger.Printf("Extracted host from HTTP: %s", host)
    }

    if len(line) == 0 {
      break
    }
  }

  if host == "" {
    return "", nil, fmt.Errorf("host header not found")
  }

  remainingData := make([]byte, reader.Buffered())
  n, err := reader.Read(remainingData)
  if err != nil && err != io.EOF {
    return "", nil, fmt.Errorf("failed to read remaining data: %w", err)
  }

  if len(bufferedData)+n > maxBufferedDataSize {
    return "", nil, fmt.Errorf("remaining data exceeds maximum buffer size")
  }
  bufferedData = append(bufferedData, remainingData[:n]...)

  return host, bufferedData, nil
}

func getNameAndBufferFromTLSConnection(reader *bufio.Reader) (string, []byte, error) {
  logger.Println("Extracting name from TLS connection")

  bufferedData := make([]byte, 0, maxBufferedDataSize)

  initialBytes := make([]byte, 43)
  _, err := io.ReadFull(reader, initialBytes)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read initial bytes: %w", err)
  }
  bufferedData = append(bufferedData, initialBytes...)

  sessionIDLength, err := reader.ReadByte()
  if err != nil {
    return "", nil, fmt.Errorf("failed to read session ID length: %w", err)
  }
  bufferedData = append(bufferedData, sessionIDLength)

  sessionID := make([]byte, sessionIDLength)
  if len(bufferedData)+len(sessionID) > maxBufferedDataSize {
    return "", nil, fmt.Errorf("buffered data exceeds maximum size")
  }
  _, err = io.ReadFull(reader, sessionID)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read session ID: %w", err)
  }
  bufferedData = append(bufferedData, sessionID...)

  cipherSuitesLengthBytes := make([]byte, 2)
  _, err = io.ReadFull(reader, cipherSuitesLengthBytes)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read cipher suites length: %w", err)
  }
  bufferedData = append(bufferedData, cipherSuitesLengthBytes...)
  cipherSuitesLength := binary.BigEndian.Uint16(cipherSuitesLengthBytes)

  cipherSuites := make([]byte, cipherSuitesLength)
  if len(bufferedData)+len(cipherSuites) > maxBufferedDataSize {
    return "", nil, fmt.Errorf("buffered data exceeds maximum size")
  }
  _, err = io.ReadFull(reader, cipherSuites)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read cipher suites: %w", err)
  }
  bufferedData = append(bufferedData, cipherSuites...)

  compressionMethodsLength, err := reader.ReadByte()
  if err != nil {
    return "", nil, fmt.Errorf("failed to read compression methods length: %w", err)
  }
  bufferedData = append(bufferedData, compressionMethodsLength)

  compressionMethods := make([]byte, compressionMethodsLength)
  if len(bufferedData)+len(compressionMethods) > maxBufferedDataSize {
    return "", nil, fmt.Errorf("buffered data exceeds maximum size")
  }
  _, err = io.ReadFull(reader, compressionMethods)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read compression methods: %w", err)
  }
  bufferedData = append(bufferedData, compressionMethods...)

  extensionsLengthBytes := make([]byte, 2)
  _, err = io.ReadFull(reader, extensionsLengthBytes)
  if err != nil {
    return "", nil, fmt.Errorf("failed to read extensions length: %w", err)
  }
  bufferedData = append(bufferedData, extensionsLengthBytes...)
  extensionsLength := binary.BigEndian.Uint16(extensionsLengthBytes)
  extensionsEndIndex := int(extensionsLength)

  for extensionsEndIndex > 0 {
    extensionTypeBytes := make([]byte, 2)
    _, err = io.ReadFull(reader, extensionTypeBytes)
    if err != nil {
      return "", nil, fmt.Errorf("failed to read extension type: %w", err)
    }
    bufferedData = append(bufferedData, extensionTypeBytes...)
    extensionType := binary.BigEndian.Uint16(extensionTypeBytes)

    extensionLengthBytes := make([]byte, 2)
    _, err = io.ReadFull(reader, extensionLengthBytes)
    if err != nil {
      return "", nil, fmt.Errorf("failed to read extension length: %w", err)
    }
    bufferedData = append(bufferedData, extensionLengthBytes...)
    extensionLength := binary.BigEndian.Uint16(extensionLengthBytes)
    extensionsEndIndex -= 4 + int(extensionLength)

    if extensionType == 0x0000 {
      serverNameListLengthBytes := make([]byte, 2)
      _, err = io.ReadFull(reader, serverNameListLengthBytes)
      if err != nil {
        return "", nil, fmt.Errorf("failed to read server name list length: %w", err)
      }
      bufferedData = append(bufferedData, serverNameListLengthBytes...)

      serverNameType, err := reader.ReadByte()
      if err != nil {
        return "", nil, fmt.Errorf("failed to read server name type: %w", err)
      }
      bufferedData = append(bufferedData, serverNameType)
      if serverNameType != 0 {
        break
      }

      serverNameLengthBytes := make([]byte, 2)
      _, err = io.ReadFull(reader, serverNameLengthBytes)
      if err != nil {
        return "", nil, fmt.Errorf("failed to read server name length: %w", err)
      }
      bufferedData = append(bufferedData, serverNameLengthBytes...)
      serverNameLength := binary.BigEndian.Uint16(serverNameLengthBytes)

      serverNameBytes := make([]byte, serverNameLength)
      if len(bufferedData)+len(serverNameBytes) > maxBufferedDataSize {
        return "", nil, fmt.Errorf("buffered data exceeds maximum size")
      }
      _, err = io.ReadFull(reader, serverNameBytes)
      if err != nil {
        return "", nil, fmt.Errorf("failed to read server name: %w", err)
      }
      bufferedData = append(bufferedData, serverNameBytes...)

      serverName := string(serverNameBytes)
      logger.Printf("Extracted server name from TLS: %s", serverName)

      remainingData := make([]byte, reader.Buffered())
      n, err := reader.Read(remainingData)
      if err != nil && err != io.EOF {
        return "", nil, fmt.Errorf("failed to read remaining data: %w", err)
      }
      if len(bufferedData)+n > maxBufferedDataSize {
        return "", nil, fmt.Errorf("remaining data exceeds maximum buffer size")
      }
      bufferedData = append(bufferedData, remainingData[:n]...)

      return serverName, bufferedData, nil
    } else {
      extensionData := make([]byte, extensionLength)
      if len(bufferedData)+len(extensionData) > maxBufferedDataSize {
        return "", nil, fmt.Errorf("buffered data exceeds maximum size")
      }
      _, err = io.ReadFull(reader, extensionData)
      if err != nil {
        return "", nil, fmt.Errorf("failed to skip extension: %w", err)
      }
      bufferedData = append(bufferedData, extensionData...)
    }
  }
  return "", nil, fmt.Errorf("SNI extension not found")
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
