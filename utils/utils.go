package utils

import (
	"fmt"
	"context"
	"os"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"archive/zip"
	"encoding/json"
	"strings"
	"crypto/sha256"
	"encoding/hex"
	"crypto/x509"
	"crypto/ecdsa"
	"encoding/pem"
	"net/http"

	"google.golang.org/api/option"
	"cloud.google.com/go/storage"
)


func DownloadFromGCS(serviceAccountKeyFilePath string, bucketName string, objectName string, filePath string) error {
	// Create a context
	ctx := context.Background()

	// Authenticate using the service account key file
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(serviceAccountKeyFilePath))
	if err != nil {
		return fmt.Errorf("Failed to authenticate to GCS: %v", err)
	}

	// Remove the existing file if it exists
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Failed to remove existing file: %v", err)
	}

	reader, err := client.Bucket(bucketName).Object(objectName).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("Failed to open object: %v", err)
	}
	defer reader.Close()

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("Failed to create file: %v", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, reader); err != nil {
		return fmt.Errorf("Failed to download the file: %v", err)
	}

	fmt.Printf("File downloaded successfully: %s\n", filePath)

	// Close the client
	client.Close()

	return nil
}


func UnzipFile(zipFile, destDir string) error {
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		filePath := filepath.Join(destDir, file.Name)

		// Remove the existing file if it exists
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Failed to remove existing file: %v", err)
		}

		writer, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create file: %v", err)
		}

		reader, err := file.Open()
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to open file inside zip: %v", err)
		}

		if _, err = io.Copy(writer, reader); err != nil {
			writer.Close()
			reader.Close()
			return fmt.Errorf("failed to extract file from zip: %v", err)
		}

		writer.Close()
		reader.Close()
	}

	fmt.Println("File unzipped successfully")

	return nil
}


type sbom struct {
	Packages          []struct {
		Spdxid    string `json:"SPDXID"`
		Checksums []struct {
			Algorithm     string `json:"algorithm"`
			ChecksumValue string `json:"checksumValue"`
		} `json:"checksums"`
		DownloadLocation string `json:"downloadLocation"`
		ExternalRefs     []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceLocator  string `json:"referenceLocator"`
			ReferenceType     string `json:"referenceType"`
		} `json:"externalRefs"`
		FilesAnalyzed         bool   `json:"filesAnalyzed"`
		Name                  string `json:"name"`
		PackageFileName       string `json:"packageFileName"`
		PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
		SourceInfo            string `json:"sourceInfo,omitempty"`
		Supplier              string `json:"supplier"`
		VersionInfo           string `json:"versionInfo"`
	} `json:"packages"`
}


func GetSigURL(jsonFile string, key string) (string, error) {
	// Read the JSON file
	data, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read JSON file: %v", err)
	}

	// Create a map to hold the JSON data
	var jsonData map[string]interface{}

	// Unmarshal the JSON data into the map
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return "", fmt.Errorf("Failed to unmarshal JSON data: %v", err)
	}

	// Access the value of the "sbom" key
	sbomValue := jsonData["sbom"].(string)

	var sbomData *sbom
	if err = json.Unmarshal([]byte(sbomValue), &sbomData); err != nil {
		log.Fatalf("Failed to unmarshal 'sbom' data: %v", err)
	}

	var sigURL string
	for _, val := range sbomData.Packages[0].ExternalRefs {
		if val.ReferenceCategory == "OTHER" {
			sigURL = val.ReferenceLocator
		}
	}

	return  sigURL, nil
}


func ExtractBucketAndObject(url string) (bucketName, objectName string, err error) {
	// Remove the "gs://" prefix
	url = strings.TrimPrefix(url, "gs://")

	// Split the URL into parts
	parts := strings.SplitN(url, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid URL format")
	}

	return parts[0], parts[1], nil
}


func VerifyDigest(dataFilePath, destDir string) (bool, error) {
	// generate sha256 hash
	packageFile, err := os.Open(dataFilePath)
	if err != nil {
		return false, err
	}
	defer packageFile.Close()

	dataDigest := sha256.New()
	if _, err := io.Copy(dataDigest, packageFile); err != nil {
		return false, err
	}

	digest := hex.EncodeToString(dataDigest.Sum(nil))

	fileContent, err := ioutil.ReadFile(filepath.Join(destDir, "digest.txt"))
	if err != nil {
		return false, err
	}
	text := string(fileContent)
	actualDigest := getFieldFromLine(text, ":")

	if digest == actualDigest {
		return true, nil
	} else {
		return false, nil
	}
}


func VerifySignatures(destDir string) (*x509.Certificate, bool, error) {
	// Step 1: Extract signature and convert to binary
	signatureFilePath := filepath.Join(destDir, "signature.txt")
	signatureBytes, err := extractAndConvertToBinary(signatureFilePath)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to decode signature hex: %v", err)
	}

	// Step 2: Extract digest and convert to binary 
	digestFilePath := filepath.Join(destDir, "digest.txt")
	digestBytes, err := extractAndConvertToBinary(digestFilePath)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to decode digest hex: %v", err)
	}

	// Step 3: Extract public key
	certPath := filepath.Join(destDir, "cert.pem")
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to read cert.pem: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, false, fmt.Errorf("Failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to parse certificate: %v", err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, false, fmt.Errorf("Failed to parse ECDSA public key")
	}

	return cert, ecdsa.VerifyASN1(pubKey, digestBytes, signatureBytes), nil
}


func DownloadRootCert(rootCertPath string) error {
	file, err := os.Create(rootCertPath)
	if err != nil {
		return fmt.Errorf("Failed to create file: %v", err)
	}
	defer file.Close()

	// Send a GET request to the URL
	url := "https://privateca-content-6333d504-0000-2df7-afd6-30fd38154590.storage.googleapis.com/a2c725a592f1d586f1f8/ca.crt"
	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("Failed to download: %v", err)
	}
	defer response.Body.Close()

	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to download: recieved status code %d", response.StatusCode)
	}

	// Copy the response body to the file
	_, err = io.Copy(file, response.Body)
	if err != nil {
		return err
	}

	return nil
}


func VerifyCertificate(rootCertPath, certChainPath string, cert *x509.Certificate) ([][]*x509.Certificate, bool, error) {
	rootBytes, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to read CA file: %v", err)
	}

	chainBytes, err := ioutil.ReadFile(certChainPath)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to read certificate chain file: %v", err)
	}

	// Create a certificate pool and add the CA certificate to it
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootBytes)

	// Create a certificate verifier with the pool and intermediate certificates
	verifier := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
	}

	// Add the intermediate certificates to the verifier
	verifier.Intermediates.AppendCertsFromPEM(chainBytes)

	chains, err := cert.Verify(verifier)
	if err != nil {
		fmt.Println(err)
		return nil, false, nil
	}

	return chains, true, nil
}


func extractAndConvertToBinary(inputFilePath string) ([]byte, error) {
	hexValue, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the input file: %v", err)
	}

	field := getFieldFromLine(string(hexValue), ":")
	dataBytes, err := hex.DecodeString(field)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode the hex: %v", err)
	}

	return dataBytes, nil
}


// extract the field value from a line based on the delimiter
func getFieldFromLine(line, delimiter string) string {
	fields := strings.Split(line, delimiter)
	if len(fields) > 1 {
		return strings.TrimSpace(fields[1])
	}
	return ""
}