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

const (
	languageFlagName                       = "language"
	packageIdFlagName                      = "package_id"
	versionFlagName                        = "version"
	artifactPathFlagName                   = "artifact_path"
	tempDownloadsPathFlagName              = "temp_downloads_path"
	verifyBuildProvenanceFlagName          = "verify_build_provenance"
	serviceAccountKeyFilePathFlagName      = "service_account_key_file_path"
	disableCertificateVerificationFlagName = "disable_certificate_verification"
	disableDeletesFlagName                 = "disable_deletes"
)

var metadataBuckets = []string{"assuredoss-metadata", "cloud-aoss-metadata"}

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

	verifyPackageCmd.Flags().StringP(languageFlagName, "l", "", "Language")
	verifyPackageCmd.Flags().StringP(packageIdFlagName, "i", "", "Package ID")
	verifyPackageCmd.Flags().StringP(versionFlagName, "v", "", "Version")
	verifyPackageCmd.Flags().StringP(artifactPathFlagName, "p", "", "Data file path")
	verifyPackageCmd.Flags().StringP(tempDownloadsPathFlagName, "d", "", "temp downloads directory path")

	verifyPackageCmd.Flags().Bool(verifyBuildProvenanceFlagName, false, "Verify build provenance")
	verifyPackageCmd.Flags().String(serviceAccountKeyFilePathFlagName, "", "Path to the service account key file")
	verifyPackageCmd.Flags().Bool(disableCertificateVerificationFlagName, false, "Disable matching the leaf certificate to the root certificate through the certificate chain")
	verifyPackageCmd.Flags().Bool(disableDeletesFlagName, false, "Disable deleting the downloaded files")
}

// verify-package follows the following workflow:
// 1. Download metadata from GCS.
// 2. If not disabled, download the root certificate and match it with the leaf certificate and the certificate chain.
// 3. Verify the sha256 digest of the package and the package signatures using the public key and the certificate.
// 4. Optionally verify build provenance using the cosign tool, if --verify_build_provenance is used.
func verifyPackage(cmd *cobra.Command, args []string) error {
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

	artifactPath, err := cmd.Flags().GetString(artifactPathFlagName)
	if err != nil {
		return err
	}

	// Check if the package exists.
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return fmt.Errorf("package not found at %s", artifactPath)
	}

	verifyBuildProvenance, err := cmd.Flags().GetBool(verifyBuildProvenanceFlagName)
	if err != nil {
		return err
	}

	serviceAccountKeyFilePath, err := cmd.Flags().GetString(serviceAccountKeyFilePathFlagName)
	if err != nil {
		return err
	}

	disableCertificateVerification, err := cmd.Flags().GetBool(disableCertificateVerificationFlagName)
	if err != nil {
		return err
	}

	disableDeletes, err := cmd.Flags().GetBool(disableDeletesFlagName)
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

	return verifyPremiumPackage(cmd, destDir, serviceAccountKeyFilePath, artifactPath, language, packageID, version, disableDeletes, verifyBuildProvenance, disableCertificateVerification)
}

func verifyPremiumPackage(cmd *cobra.Command, destDir, serviceAccountKeyFilePath, artifactPath, language, packageID, version string, disableDeletes, verifyBuildProvenance, disableCertificateVerification bool) error {
	// Authenticate to GCS and download metadata.
	obj := fmt.Sprintf("%s/%s/%s/metadata.json", language, packageID, version)
	jsonFile := filepath.Join(destDir, fmt.Sprintf("%s_%s_%s_metadata.json", language, packageID, version))
	if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, metadataBuckets[0], obj, jsonFile); err != nil {
		return verifyNONPremiumPackage(cmd, destDir, serviceAccountKeyFilePath, artifactPath, language, packageID, version, disableDeletes, verifyBuildProvenance, disableCertificateVerification)
	} else {
		cmd.Printf("File downloaded at %s\n", jsonFile)
	}

	bytes, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	var jsonData *amalgamView
	if err = json.Unmarshal(bytes, &jsonData); err != nil {
		return verifyNONPremiumPackage(cmd, destDir, serviceAccountKeyFilePath, artifactPath, language, packageID, version, disableDeletes, verifyBuildProvenance, disableCertificateVerification)
	}

	spdxID := ""
	if language == "java" {
		spdxID = fmt.Sprintf("SPDXRef-Package-%v-%v.jar", strings.Split(packageID, ":")[1], version)
	} else if language == "python" {
		spdxID = fmt.Sprintf("SPDXRef-Package-%v-%v-py3-none-any.whl", packageID, version)
	} else if language == "javascript" || jsonData.HealthInfo == "" {
		cmd.Printf("%s %s is not built by AOSS.\n", packageID, version)
		return nil
	}

	sigDetails, provenancePublicKey, buildProvSig, err := parsePremiumBuildInfoJSON(jsonFile, spdxID)
	if err != nil {
		return err
	}

	cert, err := parseCertificate([]byte(sigDetails.CertInfo.Cert))
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

		if ok, err := verifyCertificate([]byte(sigDetails.CertInfo.CertChain), certPath, cert); ok {
			cmd.Printf("Certificates verified successfully!\n")
		} else {
			cmd.Printf("Unsuccessful Certificate Verification\n")
			if err != nil {
				return err
			}
		}
	}

	// Verify data integrity.
	bytes, err = os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read artifact file: %v", err)
	}
	ok, err := verifyDigest(bytes, sigDetails.Digest[0].Digest)
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("incorrect Digest")
	}

	// Verify authenticity.
	sig, err := hex.DecodeString(sigDetails.Signature[0].Signature)
	if err != nil {
		return fmt.Errorf("failed to decode the hex: %v", err)
	}
	dig, err := hex.DecodeString(sigDetails.Digest[0].Digest)
	if err != nil {
		return fmt.Errorf("failed to decode the hex: %v", err)
	}
	ok, err = verifySignatures([]byte(sig), []byte(dig), cert)
	if ok {
		cmd.Println("Signature Verified successfully!")
	} else {
		cmd.Println("Unsuccessful Signature Verification")
		if err != nil {
			return err
		}
	}

	// Verify build provenance.
	if verifyBuildProvenance {
		publicKeyPath := filepath.Join(destDir, "public.pem")
		buildProvSigPath := filepath.Join(destDir, "signature.sig")

		if err := os.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(publicKeyPath, []byte(provenancePublicKey), 0644); err != nil {
			return err
		}

		_, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, artifactPath)
		if err != nil {
			return err
		}

		if length := len(stderror); stderror[length-3:length-1] == "OK" {
			cmd.Println("Build Provenance verified successfully!")
		} else {
			cmd.Println("Unsuccessful verification of build provenance")
		}
	}

	if !disableDeletes {
		destDir = strings.TrimSuffix(destDir, "/metadata.json")
		if err := os.RemoveAll(destDir); err != nil {
			return err
		}
	}
	return nil
}

func verifyNONPremiumPackage(cmd *cobra.Command, destDir, serviceAccountKeyFilePath, artifactPath, language, packageID, version string, disableDeletes, verifyBuildProvenance, disableCertificateVerification bool) error {
	// Authenticate to GCS and download metadata.
	obj := fmt.Sprintf("%s/%s/%s/buildinfo.zip", language, packageID, version)
	zip := filepath.Join(destDir, "buildinfo.zip")
	if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, metadataBuckets[1], obj, zip); err != nil {
		return err
	} else {
		cmd.Printf("File downloaded at %s\n", zip)
	}

	if err := unzipFile(zip, destDir); err != nil {
		return err
	}

	spdxID := ""
	if language == "java" {
		spdxID = fmt.Sprintf("SPDXRef-Package-%v-%v.jar", strings.Split(packageID, ":")[1], version)
	} else {
		spdxID = fmt.Sprintf("SPDXRef-Package-%v-%v-py3-none-any.whl", packageID, version)
	}

	sigURL, cryptokey, buildProvSig, err := parseBuildInfoJSON(filepath.Join(destDir, "buildInfo.json"), spdxID)
	if err != nil {
		return err
	}

	// Authenticate to GCS and download package signature.
	bucket, obj, err := extractBucketAndObject(sigURL)
	if err != nil {
		return err
	}
	sigzipPath := filepath.Join(destDir, "package_signature.zip")
	if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, bucket, obj, sigzipPath); err != nil {
		return err
	} else {
		cmd.Printf("File downloaded at %s\n", sigzipPath)
	}

	destDir = filepath.Join(destDir, "package_signatures")
	if err := os.Mkdir(destDir, os.ModePerm); err != nil {
		return err
	}
	if err := unzipFile(sigzipPath, destDir); err != nil {
		return err
	}

	bytes, err := os.ReadFile(filepath.Join(destDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("failed to read cert.pem: %v", err)
	}
	cert, err := parseCertificate(bytes)
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

		cb, err := os.ReadFile(filepath.Join(destDir, "certChain.pem"))
		if err != nil {
			return fmt.Errorf("failed to read certificate chain file: %v", err)
		}
		if ok, err := verifyCertificate(cb, certPath, cert); ok {
			cmd.Printf("Certificates verified successfully!\n")
		} else {
			cmd.Printf("Unsuccessful Certificate Verification\n")
			if err != nil {
				return err
			}
		}
	}

	// Verify data integrity.
	b, err := os.ReadFile(filepath.Join(destDir, "digest.txt"))
	if err != nil {
		return err
	}
	dig, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %v", err)
	}
	ok, err := verifyDigest(dig, getFieldFromLine(string(b), ":"))
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("incorrect Digest")
	}

	// Verify authenticity.
	sig, err := extractAndConvertToBinary(filepath.Join(destDir, "signature.txt"))
	if err != nil {
		return fmt.Errorf("failed to decode signature hex: %v", err)
	}
	dig, err = extractAndConvertToBinary(filepath.Join(destDir, "digest.txt"))
	if err != nil {
		return fmt.Errorf("failed to decode digest hex: %v", err)
	}
	ok, err = verifySignatures(sig, dig, cert)
	if ok {
		cmd.Println("Signature Verified successfully!")
	} else {
		cmd.Println("Unsuccessful Signature Verification")
		if err != nil {
			return err
		}
	}

	// Verify build provenance.
	if verifyBuildProvenance {
		// Download build provenance public key.
		obj = fmt.Sprintf("keys/%s-public.pem", cryptokey)
		publicKeyPath := filepath.Join(destDir, "public.pem")
		buildProvSigPath := filepath.Join(destDir, "signature.sig")
		if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, bucket, obj, publicKeyPath); err != nil {
			return err
		} else {
			cmd.Printf("File downloaded at %s\n", publicKeyPath)
		}

		if err := os.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
			return err
		}

		_, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, artifactPath)
		if err != nil {
			return err
		}

		if length := len(stderror); stderror[length-3:length-1] == "OK" {
			cmd.Println("Build Provenance verified successfully!")
		} else {
			cmd.Println("Unsuccessful verification of build provenance")
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
