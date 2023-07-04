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
	"os"
	"strings"
	"unicode"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"io/ioutil"
)


var verifyPackageCmd = &cobra.Command{
	Use:   "verify-package",
	Short: "Verify a package",
	Long:  "Verify a package by providing the language, package ID, version, and data file path.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := verifyPackage(cmd, args); err != nil {
			log.Fatalf("Failed to verify: %v", err)
		}
	},
}


func init() {
	rootCmd.AddCommand(verifyPackageCmd)

	verifyPackageCmd.Flags().StringP("language", "l", "", "Language")
	verifyPackageCmd.Flags().StringP("package_id", "i", "", "Package ID")
	verifyPackageCmd.Flags().StringP("version", "v", "", "Version")
	verifyPackageCmd.Flags().StringP("artifact_path", "p", "", "Data file path")
	verifyPackageCmd.Flags().StringP("temp_downloads_path", "d", "", "temp downloads directory path")

	verifyPackageCmd.Flags().Bool("verify_build_provenance", false, "Verify build provenance")
	verifyPackageCmd.Flags().String("service_account_key_file_path", "", "Path to the service account key file")
	verifyPackageCmd.Flags().Bool("disable_certificate_verification", false, "Disable matching the leaf certificate to the root certificate through the certificate chain")
}


func verifyPackage(cmd *cobra.Command, args []string) error {
    language, _ := cmd.Flags().GetString("language")
	for _, char := range language {
		if unicode.IsUpper(char) {
			return fmt.Errorf("Language must be all lowercase")
		}
	}

    packageID, _ := cmd.Flags().GetString("package_id")
    version, _ := cmd.Flags().GetString("version")
    artifactPath, _ := cmd.Flags().GetString("artifact_path")

	// Check if the package exists
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return fmt.Errorf("package not found at %s", artifactPath)
	}

    verifyBuildProvenance, _ := cmd.Flags().GetBool("verify_build_provenance")
    serviceAccountKeyFilePath, _ := cmd.Flags().GetString("service_account_key_file_path")
	disableCertificateVerification, _ := cmd.Flags().GetBool("disable_certificate_verification")

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
	objectName := fmt.Sprintf("%s/%s/%s/buildinfo.zip", language, packageID, version)
	zipFilePath := filepath.Join(destDir, "buildinfo.zip")
	if err := downloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, zipFilePath); err != nil {
		return fmt.Errorf("%v", err)
	}
	if err := unzipFile(zipFilePath, destDir); err != nil {
		return fmt.Errorf("%v", err)
	}

	jsonfile := filepath.Join(destDir, "buildInfo.json")
	sigURL, cryptokey, buildProvSig, err := parseBuildInfoJSON(jsonfile)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Authenticate to GCS and download package signature
	bucketName, objectName, err = extractBucketAndObject(sigURL)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	sigzipPath := filepath.Join(destDir, "package_signature.zip")
	if err := downloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, sigzipPath); err != nil {
		return fmt.Errorf("%v", err)
	}

	destDir = filepath.Join(destDir, "package_signatures")
	if err := os.Mkdir(destDir, os.ModePerm); err != nil {
        return fmt.Errorf("%v", err)
    }
	if err := unzipFile(sigzipPath, destDir); err != nil {
		return fmt.Errorf("%v", err)
	}

	cert, err := parseCertificate(destDir)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

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

	// verify data integrity
	ok, err := verifyDigest(artifactPath, destDir)
	if !ok {
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return fmt.Errorf("Incorrect Digest")
	}

	// verify authenticity
	ok, err = verifySignatures(destDir, cert)
	if ok {
		fmt.Println("Signature Verified successfully!")
	} else {
		fmt.Println("Unsuccessful Signature Verification")
		if err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	// Verify build provenance
	if verifyBuildProvenance {
		// Download build provenance public key
		objectName = fmt.Sprintf("keys/%s-public.pem", cryptokey) 
		publicKeyPath := filepath.Join(destDir, "public.pem")
		buildProvSigPath := filepath.Join(destDir, "signature.sig")
		if err := downloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, publicKeyPath); err != nil {
			return fmt.Errorf("%v", err)
		}

		if err := ioutil.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
			return fmt.Errorf("%v", err)
		}

		_, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, artifactPath)
		if err != nil {
			return fmt.Errorf("%v", err)
		}

		if length := len(stderror); stderror[ length - 3 : length - 1] == "OK" {
			fmt.Println("Build Provenance verified successfully!")
		} else {
			fmt.Println("Unsuccessful verification of build provenance")
		}
	}
	
	return nil
}