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

	"github.com/slack-go/slack"
)

var caBundlePath, slackToken, slackChannel string

func main() {
	flag.StringVar(&caBundlePath, "ca-bundle-path", os.Getenv("CA_BUNDLE_PATH"), "Path to the ca bundle file")
	flag.StringVar(&slackToken, "slack-token", os.Getenv("SLACK_TOKEN"), "The slack token")
	flag.StringVar(&slackChannel, "slack-channel", os.Getenv("SLACK_CHANNEL"), "The slack channel")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	slackClient := slack.New(slackToken)
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
			if err := notifyCertExpires(cert, slackClient, logger); err != nil {
				logger.Error("notifying certificate expired", "error", err)
			}
		}
	}
}

func expiredOrExpiresWithinAWeek(cert *x509.Certificate) bool {
	return math.Floor(cert.NotAfter.Sub(time.Now()).Hours()/24) < 7
}

func notifyCertExpires(cert *x509.Certificate, slackClient *slack.Client, logger *slog.Logger) error {
	logger.Info("sending slack notification regarding expiring certificate",
		"Issuer", cert.Issuer.CommonName,
		"Subject", cert.Subject.CommonName,
		"NotAfter", cert.NotAfter.String(),
	)

	if false {
		_, _, err := slackClient.PostMessage(slackChannel, slack.MsgOptionAttachments(slack.Attachment{
			Title: ":warning: Certificate expired or expiring within a week",
			Color: "yellow",
			Text: fmt.Sprintf(
				"Issuer: %v, Subject: %v, NotAfter: %v",
				cert.Issuer.CommonName, cert.Subject.CommonName, cert.NotAfter,
			),
		}))
		if err != nil {
			return err
		}
	}

	return nil
}
