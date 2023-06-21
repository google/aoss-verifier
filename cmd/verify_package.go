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
	verifyPackageCmd.Flags().StringP("data_file_path", "p", "", "Data file path")
	verifyPackageCmd.Flags().StringP("downloads_path", "d", "", "Downloads directory path")

	verifyPackageCmd.Flags().Bool("verify_build_provenance", false, "Verify build provenance")
	verifyPackageCmd.Flags().String("service_account_key_file_path", "", "Path to the service account key file")
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
    dataFilePath, _ := cmd.Flags().GetString("data_file_path")
	// Check if the package exists
	if _, err := os.Stat(dataFilePath); os.IsNotExist(err) {
		return fmt.Errorf("package not found at %s", dataFilePath)
	}

    // verifyBuildProvenance, _ := cmd.Flags().GetBool("verify_build_provenance")
    serviceAccountKeyFilePath, _ = cmd.Flags().GetString("service_account_key_file_path")

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

	// make downloads, downloads/package_signatures
	downloadsDir, _ := cmd.Flags().GetString("downloads_path")
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

	// authenticate to gcloud storage and download metadata
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
	key := "sbom"
	sigURL, err := getSigURL(jsonfile, key)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// authenticate to gcloud storage and download package signature
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

	// verify data integrity
	ok, err := verifyDigest(dataFilePath, destDir)
	if ok {
		fmt.Println("Digest Verified successfully!")
	} else {
		fmt.Println("Unsuccessful Digest Verification")
		if err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	// verify authenticity
	// that this digest is actually from the intended sender
	// checks whether the provided signature is valid for the given digest using the public key extracted from cert.pem
	// if successful, the data has not been tampered with and was signed by the corresponding private key.
	cert, ok, err := verifySignatures(destDir)
	if ok {
		fmt.Println("Signature Verified successfully!")
	} else {
		fmt.Println("Unsuccessful Signature Verification")
		if err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	// download root certificate
	rootCertPath := filepath.Join(destDir, "ca.crt")
	if err := downloadRootCert(rootCertPath); err == nil {
		fmt.Printf("File downloaded at %s\n", rootCertPath)
	} else {
		return fmt.Errorf("%v", err)
	}
	
	// verify the leaf certificate with the cert chain and the root certificate
	certChainPath := filepath.Join(destDir, "certChain.pem")
	if ok, err := verifyCertificate(rootCertPath, certChainPath, cert); ok {
		fmt.Printf("Cerficates verified successfully!\n")
	} else {
		fmt.Printf("Unsuccessfufl Certificate Verification\n")
		if err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	return nil
}