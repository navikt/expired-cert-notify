package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"time"
)

var caBundlePath, slackToken, slackChannel string

func main() {
	flag.StringVar(&caBundlePath, "ca-bundle-path", os.Getenv("CA_BUNDLE_PATH"), "Path to the ca bundle file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	certs, err := os.ReadFile(caBundlePath)
	if err != nil {
		logger.Error("reading cabundle file", "path", caBundlePath, "error", err)
		os.Exit(1)
	}

	block := &pem.Block{}
	for {
		block, certs = pem.Decode([]byte(certs))
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("parsing certificate", "error", err)
			continue
		}

		if expiredOrExpiresWithinAWeek(cert) {
      logger.Error("expired or expiring cert", "cert", fmt.Sprintf("Issuer: %v, Subject: %v, NotAfter: %v", cert.Issuer, cert.Subject, cert.NotAfter))
		}
	}
}

func expiredOrExpiresWithinAWeek(cert *x509.Certificate) bool {
	return math.Floor(cert.NotAfter.Sub(time.Now()).Hours()/24) < 7
}
