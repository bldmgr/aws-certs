package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

type CertImportConfig struct {
	CertFile       string
	PrivateKeyFile string
	ChainFile      string
	Region         string
	Profile        string
	Tags           map[string]string
}

func main() {
	var cfg CertImportConfig
	var tagString string

	// Define command line flags
	flag.StringVar(&cfg.CertFile, "cert", "", "Path to certificate file (PEM format) - REQUIRED")
	flag.StringVar(&cfg.PrivateKeyFile, "key", "", "Path to private key file (PEM format) - REQUIRED")
	flag.StringVar(&cfg.ChainFile, "chain", "", "Path to certificate chain file (PEM format) - OPTIONAL")
	flag.StringVar(&cfg.Region, "region", "", "AWS region (defaults to AWS_REGION or us-east-1)")
	flag.StringVar(&cfg.Profile, "profile", "", "AWS profile to use (defaults to default profile)")
	flag.StringVar(&tagString, "tags", "", "Tags in format 'key1=value1,key2=value2'")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AWS Certificate Manager Import CLI\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Import SSL/TLS certificates into AWS Certificate Manager\n\n")
		fmt.Fprintf(os.Stderr, "Required Options:\n")
		fmt.Fprintf(os.Stderr, "  -cert string    Path to certificate file (PEM format)\n")
		fmt.Fprintf(os.Stderr, "  -key string     Path to private key file (PEM format)\n\n")
		fmt.Fprintf(os.Stderr, "Optional Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -cert cert.pem -key private-key.pem\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -cert cert.pem -key key.pem -chain chain.pem -region us-west-2\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -cert cert.pem -key key.pem -tags 'Environment=prod,Application=web'\n", os.Args[0])
	}

	flag.Parse()

	// Validate required arguments
	if cfg.CertFile == "" || cfg.PrivateKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Both -cert and -key are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Parse tags if provided
	if tagString != "" {
		cfg.Tags = parseTags(tagString)
	}

	// Import the certificate
	if err := importCertificate(cfg); err != nil {
		log.Fatalf("Failed to import certificate: %v", err)
	}
}

func parseTags(tagString string) map[string]string {
	tags := make(map[string]string)
	pairs := strings.Split(tagString, ",")

	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			if key != "" && value != "" {
				tags[key] = value
			}
		}
	}

	return tags
}

func readFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	return data, nil
}

func validatePEMFormat(data []byte, fileType string) error {
	content := string(data)
	if !strings.Contains(content, "BEGIN") || !strings.Contains(content, "END") {
		return fmt.Errorf("%s file does not appear to be in PEM format", fileType)
	}
	return nil
}

func importCertificate(cfg CertImportConfig) error {
	fmt.Printf("Reading certificate files...\n")

	// Read certificate file
	certData, err := readFile(cfg.CertFile)
	if err != nil {
		return err
	}
	if err := validatePEMFormat(certData, "certificate"); err != nil {
		return err
	}
	fmt.Printf("✓ Certificate file read successfully\n")

	// Read private key file
	keyData, err := readFile(cfg.PrivateKeyFile)
	if err != nil {
		return err
	}
	if err := validatePEMFormat(keyData, "private key"); err != nil {
		return err
	}
	fmt.Printf("✓ Private key file read successfully\n")

	// Read certificate chain file (optional)
	var chainData []byte
	if cfg.ChainFile != "" {
		chainData, err = readFile(cfg.ChainFile)
		if err != nil {
			return err
		}
		if err := validatePEMFormat(chainData, "certificate chain"); err != nil {
			return err
		}
		fmt.Printf("✓ Certificate chain file read successfully\n")
	}

	// Load AWS configuration
	fmt.Printf("Initializing AWS client...\n")

	var awsCfg aws.Config
	if cfg.Profile != "" {
		awsCfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithSharedConfigProfile(cfg.Profile),
			config.WithRegion(cfg.Region),
		)
	} else {
		awsCfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(cfg.Region),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create ACM client
	client := acm.NewFromConfig(awsCfg)

	fmt.Printf("✓ AWS ACM client initialized (region: %s)\n", awsCfg.Region)

	// Prepare import input
	input := &acm.ImportCertificateInput{
		Certificate: certData,
		PrivateKey:  keyData,
	}

	if chainData != nil {
		input.CertificateChain = chainData
	}

	// Add tags if provided
	if len(cfg.Tags) > 0 {
		var tags []types.Tag
		for key, value := range cfg.Tags {
			tags = append(tags, types.Tag{
				Key:   aws.String(key),
				Value: aws.String(value),
			})
		}
		input.Tags = tags
		fmt.Printf("✓ Tags prepared: %d tags\n", len(tags))
	}

	// Import the certificate
	fmt.Printf("Importing certificate to ACM...\n")

	result, err := client.ImportCertificate(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to import certificate: %w", err)
	}

	fmt.Printf("✅ Certificate imported successfully!\n")
	fmt.Printf("Certificate ARN: %s\n", aws.ToString(result.CertificateArn))

	return nil
}
