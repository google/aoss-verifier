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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const metadataTypeFlagName = "metadata_type"

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

	verifyMetadataCmd.Flags().StringP(metadataTypeFlagName, "t", "", "Metadata Type")
	verifyMetadataCmd.Flags().StringP(languageFlagName, "l", "", "Language")
	verifyMetadataCmd.Flags().StringP(packageIdFlagName, "i", "", "Package ID")
	verifyMetadataCmd.Flags().StringP(versionFlagName, "v", "", "Version")
	verifyMetadataCmd.Flags().StringP(artifactPathFlagName, "p", "", "Data file path")
	verifyMetadataCmd.Flags().StringP(tempDownloadsPathFlagName, "d", "", "temp downloads directory path")
	verifyMetadataCmd.Flags().String(serviceAccountKeyFilePathFlagName, "", "Path to the service account key file")
	verifyMetadataCmd.Flags().Bool(disableCertificateVerificationFlagName, false, "Disable matching the leaf certificate to the root certificate through the certificate chain")
	verifyMetadataCmd.Flags().Bool(disableDeletesFlagName, false, "Disable deleting the downloaded files")
}

// verify-metadata follows the following workflow:
// 1. Download the metadata zip file from GCS.
// 2. If not disabled, download the root certificate and match it with the leaf certificate and the certificate chain.
// 3. Verify the sha256 digest of the metadata and its signatures using the public key and the certificate.
func verifyMetadata(cmd *cobra.Command, args []string) error {
	language, err := cmd.Flags().GetString(languageFlagName)
	if err != nil {
		return err
	}
	for _, char := range language {
		if unicode.IsUpper(char) {
			return fmt.Errorf("language must be all lowercase")
		}
	}

	packageID, err := cmd.Flags().GetString(packageIdFlagName)
	if err != nil {
		return err
	}

	version, err := cmd.Flags().GetString(versionFlagName)
	if err != nil {
		return err
	}

	disableCertificateVerification, err := cmd.Flags().GetBool(disableCertificateVerificationFlagName)
	if err != nil {
		return err
	}

	artifactPath, err := cmd.Flags().GetString(artifactPathFlagName)
	if err != nil {
		return err
	}

	disableDeletes, err := cmd.Flags().GetBool(disableDeletesFlagName)
	if err != nil {
		return err
	}

	serviceAccountKeyFilePath, err := cmd.Flags().GetString(serviceAccountKeyFilePathFlagName)
	if err != nil {
		return err
	}
	// If the user didn't use the --service_account_key_file flag
	if serviceAccountKeyFilePath == "" {
		// Read config file.
		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("failed to read config file: %v", err)
		}

		serviceAccountKeyFilePath = viper.GetString("service_account_key_file")
	}

	// Check if the service account key file exists.
	if _, err := os.Stat(serviceAccountKeyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("service account key file not found at %s", serviceAccountKeyFilePath)
	}

	// Check if the service account key file has a JSON extension.
	if !strings.HasSuffix(serviceAccountKeyFilePath, ".json") {
		return fmt.Errorf("service account key file must be in JSON format\nUse set-config to update")
	}

	// Create temporary downloads directory.
	downloadsDir, err := cmd.Flags().GetString(tempDownloadsPathFlagName)
	if err != nil {
		return err
	}
	if downloadsDir == "" {
		downloadsDir = "tmp_downloads"
	}
	if _, err := os.Stat(downloadsDir); os.IsNotExist(err) {
		if err := os.Mkdir(downloadsDir, os.ModePerm); err != nil {
			return err
		}
	}

	destDir := fmt.Sprintf("%s-%s-%s", packageID, version, time.Now().Format("2006_01_02_15:04:05"))
	destDir = filepath.Join(downloadsDir, destDir)
	if err := os.Mkdir(destDir, os.ModePerm); err != nil {
		return err
	}

	if err := verifyPremiumMetadata(cmd, serviceAccountKeyFilePath, destDir, artifactPath, language, packageID, version, disableCertificateVerification, disableDeletes); err == nil {
		return nil
	} else if err := verifyNONPremiumMetadata(cmd, serviceAccountKeyFilePath, destDir, language, packageID, version, disableCertificateVerification, disableDeletes); err != nil {
		return err
	}

	return nil

}

func verifyPremiumMetadata(cmd *cobra.Command, serviceAccountKeyFilePath, destDir, artifactPath, language, packageID, version string, disableCertificateVerification, disableDeletes bool) error {
	rootBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %v", err)
	}
	var jsonData *amalgamView
	if err = json.Unmarshal(rootBytes, &jsonData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON data: %v", err)
	}

	views := []struct {
		Name             string
		Info             string
		SignatureDetails SigDetails
	}{
		{"BuildInfo", jsonData.BuildInfo, jsonData.BuildInfoSignature},
		{"HealthInfo", jsonData.HealthInfo, jsonData.HealthInfoSignature},
		{"VexInfo", jsonData.VexInfo, jsonData.VexInfoSignature},
	}

	for _, v := range views {
		if v.Info == "" {
			continue
		}
		cert, err := parseCertificate([]byte(v.SignatureDetails.CertInfo.Cert))
		if err != nil {
			return err
		}

		// Verify certificates.
		if !disableCertificateVerification {
			// Download root certificate.
			certPath := filepath.Join(destDir, "ca.crt")
			if err := downloadRootCert(certPath); err == nil {
				cmd.Printf("File downloaded at %s\n", certPath)
			} else {
				return err
			}

			if ok, err := verifyCertificate([]byte(v.SignatureDetails.CertInfo.CertChain), certPath, cert); ok {
				cmd.Printf("%s certificates verified successfully!\n", v.Name)
			} else {
				cmd.Printf("Unsuccessful Certificate Verification of %s\n", v.Name)
				if err != nil {
					return err
				}
			}
		}

		// Verify data integrity.
		ok, err := verifyDigest([]byte(v.Info), v.SignatureDetails.Digest[0].Digest)
		if !ok {
			if err != nil {
				return err
			}
			return fmt.Errorf("incorrect Digest of %v", v.Name)
		}

		// Verify authenticity.
		sig, err := hex.DecodeString(v.SignatureDetails.Signature[0].Signature)
		if err != nil {
			return fmt.Errorf("failed to decode signature of %v: %v", v.Name, err)
		}
		dig, err := hex.DecodeString(v.SignatureDetails.Digest[0].Digest)
		if err != nil {
			return fmt.Errorf("failed to decode digest of %v: %v", v.Name, err)
		}
		ok, err = verifySignatures([]byte(sig), []byte(dig), cert)
		if ok {
			cmd.Printf("%s Metadata Signature Verified successfully!\n", v.Name)
		} else {
			cmd.Printf("%s Unsuccessful Metadata Signature Verification\n", v.Name)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

func verifyNONPremiumMetadata(cmd *cobra.Command, serviceAccountKeyFilePath, destDir, language, packageID, version string, disableCertificateVerification, disableDeletes bool) error {
	metadata_type, err := cmd.Flags().GetString(metadataTypeFlagName)
	if err != nil {
		return err
	}
	if metadata_type != "buildinfo" && metadata_type != "vexinfo" && metadata_type != "healthinfo" {
		return fmt.Errorf("metadata type should be either of buildinfo, vexinfo, healthinfo")
	}

	// Authenticate to GCS and download metadata.
	metadata := fmt.Sprintf("%s.zip", metadata_type)
	objectName := fmt.Sprintf("%s/%s/%s/%s", language, packageID, version, metadata)
	zipFilePath := filepath.Join(destDir, metadata)
	if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, metadataBuckets[1], objectName, zipFilePath); err != nil {
		return err
	} else {
		cmd.Printf("File downloaded at %s\n", zipFilePath)
	}
	if err := unzipFile(zipFilePath, destDir); err != nil {
		return err
	}

	sigzipPath := filepath.Join(destDir, "signature.zip")
	if err := unzipFile(sigzipPath, destDir); err != nil {
		return err
	}

	certBytes, err := os.ReadFile(filepath.Join(destDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("failed to read cert.pem: %v", err)
	}
	cert, err := parseCertificate(certBytes)
	if err != nil {
		return err
	}

	// Verify certificates.
	if !disableCertificateVerification {
		// Download root certificate.
		rootCertPath := filepath.Join(destDir, "ca.crt")
		if err := downloadRootCert(rootCertPath); err == nil {
			cmd.Printf("File downloaded at %s\n", rootCertPath)
		} else {
			return err
		}

		chainBytes, err := os.ReadFile(filepath.Join(destDir, "certChain.pem"))
		if err != nil {
			return fmt.Errorf("failed to read certificate chain file: %v", err)
		}
		if ok, err := verifyCertificate(chainBytes, rootCertPath, cert); ok {
			cmd.Printf("Certificates verified successfully!\n")
		} else {
			cmd.Printf("Unsuccessful Certificate Verification\n")
			if err != nil {
				return err
			}
		}
	}

	jsonFile := fmt.Sprintf("%sInfo.json", strings.TrimSuffix(metadata, "info.zip"))
	metadataPath := filepath.Join(destDir, jsonFile)

	// Verify data integrity.
	fileContent, err := os.ReadFile(filepath.Join(destDir, "digest.txt"))
	if err != nil {
		return err
	}

	digestBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %v", err)
	}
	ok, err := verifyDigest(digestBytes, getFieldFromLine(string(fileContent), ":"))
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("incorrect Digest")
	}

	// Verify authenticity.
	// Extract signature and convert to binary.
	signatureBytes, err := extractAndConvertToBinary(filepath.Join(destDir, "signature.txt"))
	if err != nil {
		return fmt.Errorf("failed to decode signature hex: %v", err)
	}

	// Extract digest and convert to binary.
	digestBytes, err = extractAndConvertToBinary(filepath.Join(destDir, "digest.txt"))
	if err != nil {
		return fmt.Errorf("failed to decode digest hex: %v", err)
	}
	ok, err = verifySignatures(signatureBytes, digestBytes, cert)
	if ok {
		cmd.Println("Metadata Signature Verified successfully!")
	} else {
		cmd.Println("Unsuccessful Metadata Signature Verification")
		if err != nil {
			return err
		}
	}

	if !disableDeletes {
		destDir = strings.TrimSuffix(destDir, "/package_signatures")
		if err := os.RemoveAll(destDir); err != nil {
			return err
		}
	}

	return nil
}
