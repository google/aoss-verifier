// Copyright 2023 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"log"
	"unicode"
	"time"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var verifyMetadataCmd = &cobra.Command{
	Use:   "verify-metadata",
	Short: "Verify metadata",
	Long:  "Verify metadata by providing the language, package ID, version and the metadata type",
	Run: func(cmd *cobra.Command, args []string) {
		if err := verifyMetadata(cmd, args); err != nil {
			log.Fatalf("Failed to verify: %v", err)
		}
	},
}


func init() {
	rootCmd.AddCommand(verifyMetadataCmd)

	verifyMetadataCmd.Flags().StringP("metadata_type", "t", "", "Metadata Type")
	verifyMetadataCmd.Flags().StringP("language", "l", "", "Language")
	verifyMetadataCmd.Flags().StringP("package_id", "i", "", "Package ID")
	verifyMetadataCmd.Flags().StringP("version", "v", "", "Version")
	verifyMetadataCmd.Flags().StringP("temp_downloads_path", "d", "", "temp downloads directory path")
	verifyMetadataCmd.Flags().String("service_account_key_file_path", "", "Path to the service account key file")
	verifyMetadataCmd.Flags().Bool("disable_certificate_verification", false, "Disable matching the leaf certificate to the root certificate through the certificate chain")
	verifyMetadataCmd.Flags().Bool("disable_deletes", false, "Disable deleting the downloaded files")
}


func verifyMetadata(cmd *cobra.Command, args []string) error {
	language, _ := cmd.Flags().GetString("language")
	for _, char := range language {
		if unicode.IsUpper(char) {
			return fmt.Errorf("Language must be all lowercase")
		}
	}

    packageID, _ := cmd.Flags().GetString("package_id")
    version, _ := cmd.Flags().GetString("version")
	disableCertificateVerification, _ := cmd.Flags().GetBool("disable_certificate_verification")
	disableDeletes, _ := cmd.Flags().GetBool("disable_deletes")

	metadata_type, _ := cmd.Flags().GetString("metadata_type")
	if metadata_type != "buildinfo" && metadata_type != "vexinfo" && metadata_type != "healthinfo" {
		return fmt.Errorf("Metadata type should be either of buildinfo, vexinfo, healthinfo")
	}

    serviceAccountKeyFilePath, _ := cmd.Flags().GetString("service_account_key_file_path")
	// if the user didn't use the --service_account_key_file flag
	if serviceAccountKeyFilePath == "" {
		// Read config file
		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("Failed to read config file: %v", err)
		}

		serviceAccountKeyFilePath = viper.GetString("service_account_key_file")
	}

	// Check if the service account key file exists
	if _, err := os.Stat(serviceAccountKeyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("service account key file not found at %s", serviceAccountKeyFilePath)
	}

	// Check if the service account key file has a JSON extension
	if !strings.HasSuffix(serviceAccountKeyFilePath, ".json") {
		return fmt.Errorf("service account key file must be in JSON format\nUse set-config to update")
	}

	// Create temporary downloads directory
	downloadsDir, _ := cmd.Flags().GetString("temp_downloads_path")
	if downloadsDir == "" {
		downloadsDir = "tmp_downloads"
	}
	if _, err := os.Stat(downloadsDir); os.IsNotExist(err) {
		if err := os.Mkdir(downloadsDir, os.ModePerm); err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	destDir := fmt.Sprintf("%s-%s-%s", packageID, version, time.Now().Format("2006_01_02_15:04:05"))
	destDir = filepath.Join(downloadsDir, destDir)
	if err := os.Mkdir(destDir, os.ModePerm); err != nil {
        return fmt.Errorf("%v", err)
    }

	// Authenticate to GCS and download metadata
	bucketName := "cloud-aoss-metadata"
	metadata := fmt.Sprintf("%s.zip", metadata_type)
	objectName := fmt.Sprintf("%s/%s/%s/%s", language, packageID, version, metadata)
	zipFilePath := filepath.Join(destDir, metadata)
	if err := downloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, zipFilePath); err != nil {
		return fmt.Errorf("%v", err)
	}
	if err := unzipFile(zipFilePath, destDir); err != nil {
		return fmt.Errorf("%v", err)
	}

	sigzipPath := filepath.Join(destDir, "signature.zip")
	if err := unzipFile(sigzipPath, destDir); err != nil {
		return fmt.Errorf("%v", err)
	}

	cert, err := parseCertificate(destDir)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// verify certificates
	if !disableCertificateVerification {
		// Download root certificate
		rootCertPath := filepath.Join(destDir, "ca.crt")
		if err := downloadRootCert(rootCertPath); err == nil {
			fmt.Printf("File downloaded at %s\n", rootCertPath)
		} else {
			return fmt.Errorf("%v", err)
		}
		
		// Verify the leaf certificate with the cert chain and the root certificate
		certChainPath := filepath.Join(destDir, "certChain.pem")
		if ok, err := verifyCertificate(rootCertPath, certChainPath, cert); ok {
			fmt.Printf("Certificates verified successfully!\n")
		} else {
			fmt.Printf("Unsuccessfufl Certificate Verification\n")
			if err != nil {
				return fmt.Errorf("%v", err)
			}
		}
	}

	jsonFile := fmt.Sprintf("%sInfo.json", strings.TrimSuffix(metadata, "info.zip"))
	metadataPath := filepath.Join(destDir, jsonFile)
	// verify data integrity
	ok, err := verifyDigest(metadataPath, destDir)
	if !ok {
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return fmt.Errorf("Incorrect Digest")
	}

	// verify authenticity
	ok, err = verifySignatures(destDir, cert)
	if ok {
		fmt.Println("Metadata Signature Verified successfully!")
	} else {
		fmt.Println("Unsuccessful Metadata Signature Verification")
		if err != nil {
			return fmt.Errorf("%v", err)
		}
	}
	
	if !disableDeletes {
		destDir = strings.TrimSuffix(destDir, "/package_signatures")
		if err := os.RemoveAll(destDir); err != nil {
			return fmt.Errorf("%v", err)
		}
	}
	
	return nil
}