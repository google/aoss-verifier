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

// packageVerificationOptions defines the options for verifyStandardPackage and verifyPremiumPackage functions.
type packageVerificationOptions struct {
	destDir                        string
	serviceAccountKeyFilePath      string
	artifactPath                   string
	language                       string
	packageID                      string
	version                        string
	disableDeletes                 bool
	verifyBuildProvenance          bool
	disableCertificateVerification bool
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

	return verifyPremiumPackage(cmd, packageVerificationOptions{
		destDir:                        destDir,
		serviceAccountKeyFilePath:      serviceAccountKeyFilePath,
		artifactPath:                   artifactPath,
		language:                       language,
		packageID:                      packageID,
		version:                        version,
		disableDeletes:                 disableDeletes,
		verifyBuildProvenance:          verifyBuildProvenance,
		disableCertificateVerification: disableCertificateVerification,
	})
}

func verifyPremiumPackage(cmd *cobra.Command, opts packageVerificationOptions) error {
	// Authenticate to GCS and download metadata.
	obj := fmt.Sprintf("%s/%s/%s/metadata.json", opts.language, opts.packageID, opts.version)
	jsonFile := filepath.Join(opts.destDir, fmt.Sprintf("%s_%s_%s_metadata.json", opts.language, opts.packageID, opts.version))
	if err := downloadFromGCS(cmd.Context(), opts.serviceAccountKeyFilePath, metadataBuckets[0], obj, jsonFile); err != nil {
		return verifyStandardPackage(cmd, opts)
	} else {
		cmd.Printf("File downloaded at %s\n", jsonFile)
	}

	bytes, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	var jsonData *amalgamView
	if err = json.Unmarshal(bytes, &jsonData); err != nil {
		return verifyStandardPackage(cmd, opts)
	}
	suffix := ""

	if opts.language == "javascript" || len(jsonData.HealthInfo) == 0 {
		cmd.Printf("%s %s is not built by AOSS.\n", opts.packageID, opts.version)
		return nil
	} else if opts.language == "java" {
		suffix = ".jar"
	} else if opts.language == "python" {
		suffix = ".whl"
	}

	sigDetails, provenancePublicKey, buildProvSig, err := parsePremiumBuildInfoJSON(jsonFile, suffix)
	if err != nil {
		return err
	}
	cert, err := parseCertificate([]byte(sigDetails.CertInfo.Cert))
	if err != nil {
		return err
	}

	// Verify certificates.
	if !opts.disableCertificateVerification {
		// Download root certificate.
		certPath := filepath.Join(opts.destDir, "ca.crt")
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
	bytes, err = os.ReadFile(opts.artifactPath)
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
	if opts.verifyBuildProvenance {
		publicKeyPath := filepath.Join(opts.destDir, "public.pem")
		buildProvSigPath := filepath.Join(opts.destDir, "signature.sig")

		if err := os.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(publicKeyPath, []byte(provenancePublicKey), 0644); err != nil {
			return err
		}

		_, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, opts.artifactPath)
		if err != nil {
			return err
		}

		if length := len(stderror); stderror[length-3:length-1] == "OK" {
			cmd.Println("Build Provenance verified successfully!")
		} else {
			cmd.Println("Unsuccessful verification of build provenance")
		}
	}

	if !opts.disableDeletes {
		opts.destDir = strings.TrimSuffix(opts.destDir, "/metadata.json")
		if err := os.RemoveAll(opts.destDir); err != nil {
			return err
		}
	}
	return nil
}

func verifyStandardPackage(cmd *cobra.Command, opts packageVerificationOptions) error {
	// Authenticate to GCS and download metadata.
	obj := fmt.Sprintf("%s/%s/%s/buildinfo.zip", opts.language, opts.packageID, opts.version)
	zip := filepath.Join(opts.destDir, "buildinfo.zip")
	if err := downloadFromGCS(cmd.Context(), opts.serviceAccountKeyFilePath, metadataBuckets[1], obj, zip); err != nil {
		cmd.Printf("%s %s is not built by AOSS.\n", opts.packageID, opts.version)
		return nil
	} else {
		cmd.Printf("File downloaded at %s\n", zip)
	}

	if err := unzipFile(zip, opts.destDir); err != nil {
		return err
	}

	suffix := ""
	if opts.language == "java" {
		suffix = ".jar"
	} else {
		suffix = ".whl"
	}

	sigURL, cryptokey, buildProvSig, err := parseBuildInfoJSON(filepath.Join(opts.destDir, "buildInfo.json"), suffix)
	if err != nil {
		return err
	}

	// Authenticate to GCS and download package signature.
	bucket, obj, err := extractBucketAndObject(sigURL)
	if err != nil {
		return err
	}
	sigzipPath := filepath.Join(opts.destDir, "package_signature.zip")
	if err := downloadFromGCS(cmd.Context(), opts.serviceAccountKeyFilePath, bucket, obj, sigzipPath); err != nil {
		return err
	} else {
		cmd.Printf("File downloaded at %s\n", sigzipPath)
	}

	opts.destDir = filepath.Join(opts.destDir, "package_signatures")
	if err := os.Mkdir(opts.destDir, os.ModePerm); err != nil {
		return err
	}
	if err := unzipFile(sigzipPath, opts.destDir); err != nil {
		return err
	}

	bytes, err := os.ReadFile(filepath.Join(opts.destDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("failed to read cert.pem: %v", err)
	}
	cert, err := parseCertificate(bytes)
	if err != nil {
		return err
	}

	// Verify certificates.
	if !opts.disableCertificateVerification {
		// Download root certificate.
		certPath := filepath.Join(opts.destDir, "ca.crt")
		if err := downloadRootCert(certPath); err == nil {
			cmd.Printf("File downloaded at %s\n", certPath)
		} else {
			return err
		}

		cb, err := os.ReadFile(filepath.Join(opts.destDir, "certChain.pem"))
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
	b, err := os.ReadFile(filepath.Join(opts.destDir, "digest.txt"))
	if err != nil {
		return err
	}
	dig, err := os.ReadFile(opts.artifactPath)
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
	sig, err := extractAndConvertToBinary(filepath.Join(opts.destDir, "signature.txt"))
	if err != nil {
		return fmt.Errorf("failed to decode signature hex: %v", err)
	}
	dig, err = extractAndConvertToBinary(filepath.Join(opts.destDir, "digest.txt"))
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
	if opts.verifyBuildProvenance {
		// Download build provenance public key.
		obj = fmt.Sprintf("keys/%s-public.pem", cryptokey)
		publicKeyPath := filepath.Join(opts.destDir, "public.pem")
		buildProvSigPath := filepath.Join(opts.destDir, "signature.sig")
		if err := downloadFromGCS(cmd.Context(), opts.serviceAccountKeyFilePath, bucket, obj, publicKeyPath); err != nil {
			return err
		} else {
			cmd.Printf("File downloaded at %s\n", publicKeyPath)
		}

		if err := os.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
			return err
		}

		_, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, opts.artifactPath)
		if err != nil {
			return err
		}

		if length := len(stderror); stderror[length-3:length-1] == "OK" {
			cmd.Println("Build Provenance verified successfully!")
		} else {
			cmd.Println("Unsuccessful verification of build provenance")
		}
	}

	if !opts.disableDeletes {
		opts.destDir = strings.TrimSuffix(opts.destDir, "/package_signatures")
		if err := os.RemoveAll(opts.destDir); err != nil {
			return err
		}
	}

	return nil
}
