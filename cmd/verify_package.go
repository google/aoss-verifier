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
    "io/ioutil"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)


const (
    languageFlagName = "language"
    packageIdFlagName = "package_id"
    versionFlagName = "version"
    artifactPathFlagName = "artifact_path"
    tempDownloadsPathFlagName = "temp_downloads_path"
    verifyBuildProvenanceFlagName = "verify_build_provenance"
    serviceAccountKeyFilePathFlagName = "service_account_key_file_path"
    disableCertificateVerificationFlagName = "disable_certificate_verification"
    disableDeletesFlagName = "disable_deletes"

    metadataBucketName = "cloud-aoss-metadata"
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
// 1. Download buildinfo.zip from GCS and extract signature zip URL from buildInfo.json.
// 2. Download signature zip from GCS.
// 3. If not disabled, download the root certificate and match it with the leaf certificate and the certificate chain.
// 4. Verify the sha256 digest of the package and the package signatures using the public key and the certificate.
// 5. Optionally verify build provenance using the cosign tool, if --verify_build_provenance is used.
func verifyPackage(cmd *cobra.Command, args []string) error {
    language, err := cmd.Flags().GetString(languageFlagName)
    if err != nil {
        return err
    }
    for _, char := range language {
        if unicode.IsUpper(char) {
            return fmt.Errorf("Language must be all lowercase")
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
            return fmt.Errorf("Failed to read config file: %v", err)
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

    // Authenticate to GCS and download metadata.
    objectName := fmt.Sprintf("%s/%s/%s/buildinfo.zip", language, packageID, version)
    zipFilePath := filepath.Join(destDir, "buildinfo.zip")
    if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, metadataBucketName, objectName, zipFilePath); err != nil {
        return err
    } else {
        cmd.Printf("File downloaded at %s\n", zipFilePath)
    }

    if err := unzipFile(zipFilePath, destDir); err != nil {
        return err
    }

    jsonfile := filepath.Join(destDir, "buildInfo.json")
    spdxID := fmt.Sprintf("SPDXRef-Package-%v-%v.jar", strings.Split(packageID, ":")[1], version)
    sigURL, cryptokey, buildProvSig, err := parseBuildInfoJSON(jsonfile, spdxID)
    if err != nil {
        return err
    }

    // Authenticate to GCS and download package signature.
    bucketName, objectName, err := extractBucketAndObject(sigURL)
    if err != nil {
        return err
    }
    sigzipPath := filepath.Join(destDir, "package_signature.zip")
    if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, bucketName, objectName, sigzipPath); err != nil {
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

    cert, err := parseCertificate(destDir)
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

        if ok, err := verifyCertificate(destDir, rootCertPath, cert); ok {
            cmd.Printf("Certificates verified successfully!\n")
        } else {
            cmd.Printf("Unsuccessful Certificate Verification\n")
            if err != nil {
                return err
            }
        }
    }

    // Verify data integrity.
    ok, err := verifyDigest(artifactPath, destDir)
    if !ok {
        if err != nil {
            return err
        }
        return fmt.Errorf("Incorrect Digest")
    }

    // Verify authenticity.
    ok, err = verifySignatures(destDir, cert)
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
        objectName = fmt.Sprintf("keys/%s-public.pem", cryptokey) 
        publicKeyPath := filepath.Join(destDir, "public.pem")
        buildProvSigPath := filepath.Join(destDir, "signature.sig")
        if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, bucketName, objectName, publicKeyPath); err != nil {
            return err
        } else {
            cmd.Printf("File downloaded at %s\n", publicKeyPath)
        }

        if err := ioutil.WriteFile(buildProvSigPath, buildProvSig, 0644); err != nil {
            return err
        }

        _, stderror, _, err := verifyBuildProv(publicKeyPath, buildProvSigPath, artifactPath)
        if err != nil {
            return err
        }

        if length := len(stderror); stderror[ length - 3 : length - 1] == "OK" {
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