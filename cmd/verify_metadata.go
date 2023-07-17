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

    disableCertificateVerification, err := cmd.Flags().GetBool(disableCertificateVerificationFlagName)
    if err != nil {
        return err
    }

    disableDeletes, err := cmd.Flags().GetBool(disableDeletesFlagName)
    if err != nil {
        return err
    }

    metadata_type, err := cmd.Flags().GetString(metadataTypeFlagName)
    if err != nil {
        return err
    }
    if metadata_type != "buildinfo" && metadata_type != "vexinfo" && metadata_type != "healthinfo" {
        return fmt.Errorf("Metadata type should be either of buildinfo, vexinfo, healthinfo")
    }

    serviceAccountKeyFilePath, err := cmd.Flags().GetString(serviceAccountKeyFilePathFlagName)
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
    metadata := fmt.Sprintf("%s.zip", metadata_type)
    objectName := fmt.Sprintf("%s/%s/%s/%s", language, packageID, version, metadata)
    zipFilePath := filepath.Join(destDir, metadata)
    if err := downloadFromGCS(cmd.Context(), serviceAccountKeyFilePath, metadataBucketName, objectName, zipFilePath); err != nil {
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

    jsonFile := fmt.Sprintf("%sInfo.json", strings.TrimSuffix(metadata, "info.zip"))
    metadataPath := filepath.Join(destDir, jsonFile)

    // Verify data integrity.
    ok, err := verifyDigest(metadataPath, destDir)
    if !ok {
        if err != nil {
            return err
        }
        return fmt.Errorf("Incorrect Digest")
    }

    // Verify authenticity.
    ok, err = verifySignatures(destDir, cert)
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