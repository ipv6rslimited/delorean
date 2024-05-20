# delorean

**delorean**, a reverse IPv4 to IPv6 TLS SNI and HTTP proxy written in GoLang, takes you back to the future if you're stuck on the old IPv4 internet.

## Features

- Multi-port
- Signal handling for graceful shutdown and configuration reload
- LRU cache for DNS lookups with a configurable TTL (Time-To-Live)
- Supports both TLS and HTTP connections to extract the hostname
- Backend connection based on IPv6 addresses with a specific prefix
- Concurrency and multithreading to handle multiple clients efficiently
- Lazy DNS cache reloading to minimize lookup delays
- Extensive unit tests to ensure reliability and performance
- Simple and readable codebase (like all our repos)

## Use case

We use this in production on the [IPv6.rs](https://ipv6.rs) network, proxying thousands of websites. We open sourced this as part of our commitment to transparency. You should know how your packets are being handled.

## Test results

These tests were performed in a Virtual Machine running on a 4 year old laptop.

```
$ go test -v main.go main_test.go
=== RUN   TestGetNameFromTLSConnection
2024/05/19 18:43:39 Packet Data: 16030300720100006e0303b6b26afb555e03d565a36af05ea5430293b959a754c3dd78575834c582fd53d1000004000100ff010000410000000e000c00000f7777772e6578616d706c652e636f6d000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101
--- PASS: TestGetNameFromTLSConnection (0.00s)
=== RUN   TestGetNameFromHTTPConnection
--- PASS: TestGetNameFromHTTPConnection (0.00s)
=== RUN   TestStressServer
    main_test.go:196: Total failed connections: 0 out of 1000 attempts
--- PASS: TestStressServer (11.02s)
=== RUN   TestMemoryUsage
2024/05/19 18:43:50 Packet Data: 16030300720100006e0303b6b26afb555e03d565a36af05ea5430293b959a754c3dd78575834c582fd53d1000004000100ff010000410000000e000c00000f7777772e6578616d706c652e636f6d000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101
2024/05/19 18:43:50 Memory before: Alloc = 10226432 TotalAlloc = 888812720 Sys = 48059656 NumGC = 126
2024/05/19 18:43:50 Memory after: Alloc = 14402464 TotalAlloc = 892988752 Sys = 48059656 NumGC = 126
--- PASS: TestMemoryUsage (0.00s)
PASS
ok  	command-line-arguments	11.021s
```

```
$ free -h
               total        used        free      shared  buff/cache   available
Mem:            15Gi       1.2Gi       8.5Gi       335Mi       5.9Gi        13Gi
Swap:          2.0Gi          0B       2.0Gi
```

```
$ nproc
4
```

## License

Copyright (c) 2024 [IPv6rs Limited <https://ipv6.rs>](https://ipv6.rs)

All Rights Reserved.

COOLER License.


