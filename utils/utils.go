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
