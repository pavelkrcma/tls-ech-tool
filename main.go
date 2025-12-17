package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	requestTimeout = 5 * time.Second
	dnsServerTLS   = "1.1.1.1:853" // Cloudflare DNS over TLS
	dnsServerPlain = "1.1.1.1:53"  // Cloudflare DNS over UDP
)

func main() {
	verbose := flag.Bool("v", false, "verbose output")
	outputFile := flag.String("o", "", "save response body to file")
	sni := flag.String("sni", "", "custom SNI value")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <URL>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	urlStr := args[0]
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	// Parse URL to extract hostname
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Error parsing URL: %v", err)
	}
	hostname := parsedURL.Hostname()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Skip certificate verification for testing
	}

	// Set custom SNI if provided
	if *sni != "" {
		tlsConfig.ServerName = *sni
	}

	// Always attempt to fetch and use ECH
	echConfig := fetchECHConfig(hostname, *verbose)
	if echConfig != nil {
		tlsConfig.EncryptedClientHelloConfigList = echConfig
		if *verbose {
			printECHConfig(echConfig)
		}
	} else if *verbose {
		fmt.Println("* ECH config not available, proceeding without ECH")
	}

	// Create HTTP client with custom TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: requestTimeout,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	if *verbose {
		fmt.Printf("* Connecting to %s\n", urlStr)

		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				fmt.Printf("* Connection established (reused: %v)\n", info.Reused)
			},
			TLSHandshakeStart: func() {
				fmt.Println("* TLS handshake starting...")
			},
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				if err != nil {
					fmt.Printf("* TLS handshake failed: %v\n", err)
					return
				}
				fmt.Printf("* TLS handshake complete\n")
				fmt.Printf("* TLS version: %s\n", tlsVersionToString(state.Version))
				fmt.Printf("* Cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
				fmt.Printf("* Server certificate: %s\n", state.PeerCertificates[0].Subject.CommonName)
				if echConfig != nil {
					if state.ECHAccepted {
						fmt.Println("* ECH accepted by server")
					} else {
						fmt.Println("* ECH not accepted (server may not support it)")
					}
				}
			},
			GotFirstResponseByte: func() {
				fmt.Println("* Received first response byte")
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Print response details
	if *verbose {
		fmt.Printf("\n< HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("< %s: %s\n", key, value)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Status: %s\n", resp.Status)
	}

	// Read and save response body only if -o flag is provided
	if *outputFile != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response: %v", err)
		}

		err = os.WriteFile(*outputFile, body, 0644)
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}

		if *verbose {
			fmt.Printf("* Response body saved to %s (%d bytes)\n", *outputFile, len(body))
		}
	} else {
		fmt.Println("* Response body not downloaded (use -o to save)")
	}
}

func fetchECHConfig(hostname string, verbose bool) []byte {
	c := new(dns.Client)

	// comment the next line and use the dnsServerPlain constant to use DNS over UDP instead of TLS
	c.Net = "tcp-tls" // Use DNS over TLS

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeHTTPS)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, dnsServerTLS)
	if err != nil {
		if verbose {
			fmt.Printf("* Warning: Failed to fetch ECH config via DNS: %v\n", err)
		}
		return nil
	}

	for _, ans := range r.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, svcParam := range https.Value {
				// ECH is SVCB parameter key 5
				if svcParam.Key() == dns.SVCB_ECHCONFIG {
					echConfig := svcParam.String()
					// Remove the "ech=" prefix if present
					echConfig = strings.TrimPrefix(echConfig, "ech=")
					decoded, err := base64.StdEncoding.DecodeString(echConfig)
					if err != nil {
						if verbose {
							fmt.Printf("* Warning: Failed to decode ECH config: %v\n", err)
						}
						continue
					}

					if verbose {
						fmt.Printf("* ECH config fetched from DNS (%d bytes)\n", len(decoded))
					}
					return decoded
				}
			}
		}
	}

	if verbose {
		fmt.Println("* No ECH config found in DNS HTTPS records")
	}
	return nil
}

// printECHConfig parses and displays the ECHConfig structure
func printECHConfig(data []byte) {
	if len(data) < 4 {
		fmt.Println("  * ECH config too short")
		return
	}

	offset := 0

	if len(data) < offset+2 {
		fmt.Println("  * Invalid ECHConfigList")
		return
	}
	listLength := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	fmt.Printf("  * ECHConfigList length: %d bytes\n", listLength)

	configNum := 1
	for offset < len(data) {
		fmt.Printf("  * ECHConfig #%d:\n", configNum)

		if len(data) < offset+2 {
			break
		}
		version := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		fmt.Printf("    - Version: 0x%04x", version)
		if version == 0xfe0d {
			fmt.Println(" (ECH draft-13)")
		} else {
			fmt.Println()
		}

		if len(data) < offset+2 {
			break
		}
		length := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		fmt.Printf("    - Length: %d bytes\n", length)

		if len(data) < offset+int(length) {
			fmt.Println("    - Warning: Truncated ECHConfig")
			break
		}

		configStart := offset

		if len(data) < offset+1 {
			break
		}
		configID := data[offset]
		offset++
		fmt.Printf("    - Config ID: %d\n", configID)

		if len(data) < offset+2 {
			break
		}
		kemID := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		fmt.Printf("    - KEM ID: 0x%04x, %s\n", kemID, getKEMName(kemID))

		if len(data) < offset+2 {
			break
		}
		pubKeyLen := binary.BigEndian.Uint16(data[offset:])
		offset += 2

		// Skip public_key
		if len(data) < offset+int(pubKeyLen) {
			break
		}
		fmt.Printf("    - Public Key: %d bytes\n", pubKeyLen)
		offset += int(pubKeyLen)

		if len(data) < offset+2 {
			break
		}
		cipherSuitesLen := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		fmt.Printf("    - Cipher Suites: %d bytes (%d suites)\n", cipherSuitesLen, cipherSuitesLen/4)

		// Parse cipher suites (4 bytes each: 2 for KDF, 2 for AEAD)
		for i := 0; i < int(cipherSuitesLen)/4; i++ {
			if len(data) < offset+4 {
				break
			}
			kdfID := binary.BigEndian.Uint16(data[offset:])
			aeadID := binary.BigEndian.Uint16(data[offset+2:])
			fmt.Printf("      Suite %d: KDF=0x%04x (%s), AEAD=0x%04x (%s)\n",
				i+1, kdfID, getKDFName(kdfID), aeadID, getAEADName(aeadID))
			offset += 4
		}

		if len(data) < offset+1 {
			break
		}
		maxNameLen := data[offset]
		offset++
		if maxNameLen == 0 {
			fmt.Printf("    - Maximum Name Length: no limit/default\n")
		} else {
			fmt.Printf("    - Maximum Name Length: %d\n", maxNameLen)
		}

		if len(data) < offset+1 {
			break
		}
		publicNameLen := data[offset]
		offset++

		if len(data) < offset+int(publicNameLen) {
			break
		}
		publicName := string(data[offset : offset+int(publicNameLen)])
		offset += int(publicNameLen)
		fmt.Printf("    - Public Name: %s\n", publicName)

		if len(data) < offset+2 {
			break
		}
		extensionsLen := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		fmt.Printf("    - Extensions: %d bytes\n", extensionsLen)

		// Skip extensions
		offset += int(extensionsLen)

		// Ensure we've consumed exactly 'length' bytes for this config
		offset = configStart + int(length)
		configNum++
	}
}

// https://www.iana.org/assignments/hpke/hpke.xhtml
func getKEMName(id uint16) string {
	switch id {
	case 0x0010:
		return "DHKEM(P-256, HKDF-SHA256)"
	case 0x0011:
		return "DHKEM(P-384, HKDF-SHA384)"
	case 0x0012:
		return "DHKEM(P-521, HKDF-SHA512)"
	case 0x0020:
		return "DHKEM(X25519, HKDF-SHA256)"
	case 0x0021:
		return "DHKEM(X448, HKDF-SHA512)"
	default:
		return "Unknown"
	}
}

func getKDFName(id uint16) string {
	switch id {
	case 0x0001:
		return "HKDF-SHA256"
	case 0x0002:
		return "HKDF-SHA384"
	case 0x0003:
		return "HKDF-SHA512"
	default:
		return "Unknown"
	}
}

func getAEADName(id uint16) string {
	switch id {
	case 0x0001:
		return "AES-128-GCM"
	case 0x0002:
		return "AES-256-GCM"
	case 0x0003:
		return "ChaCha20Poly1305"
	default:
		return "Unknown"
	}
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
