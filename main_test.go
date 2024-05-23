/*
**
** delorean tests
** Tests for delorean
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
  "bytes"
  "encoding/binary"
  "log"
  "net"
  "runtime"
  "sync"
  "testing"
  "time"
)

func init() {
  logger = log.New(nullWriter{}, "", log.LstdFlags)
}

func createFakeClientHelloPacket(serverName string) []byte {
  var packet bytes.Buffer

  packet.WriteByte(0x16)
  packet.WriteByte(0x03)
  packet.WriteByte(0x03)
  packet.Write([]byte{0x00, 0x00})

  var handshake bytes.Buffer
  handshake.WriteByte(0x01)
  handshake.Write([]byte{0x00, 0x00, 0x00})
  handshake.Write([]byte{0x03, 0x03})
  handshake.Write([]byte{
    0xb6, 0xb2, 0x6a, 0xfb, 0x55, 0x5e, 0x03, 0xd5,
    0x65, 0xa3, 0x6a, 0xf0, 0x5e, 0xa5, 0x43, 0x02,
    0x93, 0xb9, 0x59, 0xa7, 0x54, 0xc3, 0xdd, 0x78,
    0x57, 0x58, 0x34, 0xc5, 0x82, 0xfd, 0x53, 0xd1,
  })
  handshake.WriteByte(0x00)
  handshake.Write([]byte{0x00, 0x04})
  handshake.Write([]byte{
    0x00, 0x01,
    0x00, 0xff,
  })

  handshake.WriteByte(0x01)
  handshake.WriteByte(0x00)

  var extensions bytes.Buffer
  extensions.Write([]byte{0x00, 0x00})
  var sni bytes.Buffer
  sni.Write([]byte{0x00, 0x0c})
  sni.WriteByte(0x00)
  sniName := []byte(serverName)
  binary.Write(&sni, binary.BigEndian, uint16(len(sniName)))
  sni.Write(sniName)
  sniBytes := sni.Bytes()
  extensions.Write([]byte{0x00, 0x0e})
  extensions.Write(sniBytes)

  extensions.Write([]byte{
    0x00, 0x0d,
    0x00, 0x20,
    0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
    0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
    0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
    0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
  })

  extensions.Write([]byte{
    0x00, 0x0f,
    0x00, 0x01,
    0x01,
  })

  extensionsBytes := extensions.Bytes()
  handshake.Write([]byte{0x00, 0x00})
  extensionLengthFieldIndex := handshake.Len() - 2
  handshake.Write(extensionsBytes)
  binary.BigEndian.PutUint16(handshake.Bytes()[extensionLengthFieldIndex:], uint16(len(extensionsBytes)))

  handshakeBytes := handshake.Bytes()
  handshakeLength := len(handshakeBytes) - 4
  handshakeBytes[1] = byte(handshakeLength >> 16)
  handshakeBytes[2] = byte(handshakeLength >> 8)
  handshakeBytes[3] = byte(handshakeLength)

  packet.Write(handshakeBytes)

  recordLayerLength := len(packet.Bytes()) - 5
  packetBytes := packet.Bytes()
  binary.BigEndian.PutUint16(packetBytes[3:], uint16(recordLayerLength))

  log.Printf("Packet Data: %x\n", packet.Bytes())
  return packet.Bytes()
}

func TestGetNameAndBufferFromTLSConnection(t *testing.T) {
  serverName := "www.example.com"
  tlsData := createFakeClientHelloPacket(serverName)

  reader := bufio.NewReaderSize(bytes.NewReader(tlsData), 4096)
  name, _, err := getNameAndBufferFromTLSConnection(reader)
  if err != nil {
    t.Fatalf("Expected no error, got %v", err)
  }

  if name != serverName {
    t.Fatalf("Expected %s, got %s", serverName, name)
  }
}

func TestGetNameAndBufferFromHTTPConnection(t *testing.T) {
  httpData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
  reader := bufio.NewReader(bytes.NewReader(httpData))

  name, _, err := getNameAndBufferFromHTTPConnection(reader)
  if err != nil {
    t.Fatalf("Expected no error, got %v", err)
  }

  expectedName := "example.com"
  if name != expectedName {
    t.Fatalf("Expected %s, got %s", expectedName, name)
  }
}

func BenchmarkGetNameAndBufferFromTLSConnection(b *testing.B) {
  serverName := "www.example.com"
  tlsData := createFakeClientHelloPacket(serverName)

  for i := 0; i < b.N; i++ {
    reader := bufio.NewReaderSize(bytes.NewReader(tlsData), 4096)
    _, _, err := getNameAndBufferFromTLSConnection(reader)
    if err != nil {
      b.Fatalf("Expected no error, got %v", err)
    }
  }
}

func BenchmarkGetNameAndBufferFromHTTPConnection(b *testing.B) {
  httpData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

  for i := 0; i < b.N; i++ {
    reader := bufio.NewReader(bytes.NewReader(httpData))
    _, _, err := getNameAndBufferFromHTTPConnection(reader)
    if err != nil {
      b.Fatalf("Expected no error, got %v", err)
    }
  }
}

func StressTestServer(t *testing.T, serverFunc func(stop chan struct{})) {
  var wg sync.WaitGroup
  stop := make(chan struct{})
  serverReady := make(chan struct{})
  var failedConnections int
  var failedConnectionsMutex sync.Mutex

  wg.Add(1)
  go func() {
    defer wg.Done()
    serverFunc(stop)
    close(serverReady)
  }()

  time.Sleep(1 * time.Second)

  clientCount := 1000
  for i := 0; i < clientCount; i++ {
    wg.Add(1)
    go func(clientID int) {
      defer wg.Done()
      for {
        select {
        case <-stop:
          return
        default:
          conn, err := net.Dial("tcp", "127.0.0.1:8080")
          if err != nil {
            t.Logf("Client %d: Failed to connect: %v", clientID, err)
            failedConnectionsMutex.Lock()
            failedConnections++
            failedConnectionsMutex.Unlock()
            return
          }
          conn.Close()
        }
      }
    }(i)
  }

  close(stop)
  <-serverReady
  wg.Wait()

  t.Logf("Total failed connections: %d out of %d attempts", failedConnections, clientCount)
}

func TestStressServer(t *testing.T) {
  StressTestServer(t, func(stop chan struct{}) {
    listener, err := net.Listen("tcp", "127.0.0.1:8080")
    if err != nil {
      log.Fatalf("Failed to start server: %v", err)
    }
    defer listener.Close()

    var wg sync.WaitGroup

    for {
      select {
      case <-stop:
        listener.Close()
        wg.Wait()
        return
      default:
        conn, err := listener.Accept()
        if err != nil {
          if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            continue
          }
          log.Printf("Failed to accept connection: %v", err)
          continue
        }

        wg.Add(1)
        go func() {
          defer wg.Done()
          defer conn.Close()
          handleConnection(conn)
        }()
      }
    }
  })
}

func TestMemoryUsage(t *testing.T) {
  var m runtime.MemStats

  serverName := "www.example.com"
  tlsData := createFakeClientHelloPacket(serverName)

  runtime.ReadMemStats(&m)
  log.Printf("Memory before: Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", m.Alloc, m.TotalAlloc, m.Sys, m.NumGC)

  for i := 0; i < 1000; i++ {
    reader := bufio.NewReaderSize(bytes.NewReader(tlsData), 4096)
    _, _, err := getNameAndBufferFromTLSConnection(reader)
    if err != nil {
      t.Fatalf("Expected no error, got %v", err)
    }
  }

  runtime.ReadMemStats(&m)
  log.Printf("Memory after: Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", m.Alloc, m.TotalAlloc, m.Sys, m.NumGC)
}
