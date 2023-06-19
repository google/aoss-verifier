package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"aoss-verifier/utils"
)


var verifyPackageCmd = &cobra.Command{
	Use:   "verify-package",
	Short: "Verify a package",
	Long:  "Verify a package by providing the language, package ID, version, and data file path.",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO
		verifyPackage(cmd, args)		
		// if err := verifyPackage(cmd, args); err != nil {
		// 	log.Fatalf("Failed to verify: %v", err)
		// }
	},
}


func init() {
	rootCmd.AddCommand(verifyPackageCmd)

	verifyPackageCmd.Flags().StringP("language", "l", "", "Language")
	verifyPackageCmd.Flags().StringP("package_id", "p", "", "Package ID")
	verifyPackageCmd.Flags().StringP("version", "v", "", "Version")
	verifyPackageCmd.Flags().StringP("data_file_path", "d", "", "Data file path")

	verifyPackageCmd.Flags().Bool("verify_build_provenance", false, "Verify build provenance")
	verifyPackageCmd.Flags().String("service_account_key_file_path", "", "Path to the service account key file")
}


func verifyPackage(cmd *cobra.Command, args []string) {
    language, _ := cmd.Flags().GetString("language")
	for _, char := range language {
		if unicode.IsUpper(char) {
			log.Fatalf("Language must be all lowercase")
		}
	}

    packageID, _ := cmd.Flags().GetString("package_id")
    version, _ := cmd.Flags().GetString("version")
    // dataFilePath, _ := cmd.Flags().GetString("data_file_path")
    // verifyBuildProvenance, _ := cmd.Flags().GetBool("verify_build_provenance")
    serviceAccountKeyFilePath, _ = cmd.Flags().GetString("service_account_key_file_path")

	// if the user didn't use the --service_account_key_file flag
	if serviceAccountKeyFilePath == "" {
		// Read config file
		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		serviceAccountKeyFilePath = viper.GetString("service_account_key_file")
	}

	// Check if the service account key file exists
	if _, err := os.Stat(serviceAccountKeyFilePath); os.IsNotExist(err) {
		log.Fatalf("service account key file not found at %s", serviceAccountKeyFilePath)
	}

	// Check if the service account key file has a JSON extension
	if !strings.HasSuffix(serviceAccountKeyFilePath, ".json") {
		log.Fatal("service account key file must be in JSON format\nUse set-config to update")
	}

	// WILL HAVE TO MAKE downloads, downloads/package_signatures

	// authenticate to gcloud storage and download metadata
	bucketName := "cloud-aoss-metadata"
	objectName := fmt.Sprintf("%s/%s/%s/buildinfo.zip", language, packageID, version)
	// "java/com.google.errorprone:error_prone_annotations/2.15.0/buildinfo.zip"
	filePath := "./downloads/buildinfo.zip"
	if err := utils.DownloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, filePath); err != nil {
		log.Fatal(err)
	}
	
	zipfile := "./downloads/buildinfo.zip"
	destDir := "./downloads"
	if err := utils.UnzipFile(zipfile, destDir); err != nil {
		log.Fatal(err)
	}

	jsonfile := "./downloads/buildInfo.json"
	key := "sbom"
	// TODO: extract the bucket-name and object-name from this url
	sigURL, err := utils.GetSigURL(jsonfile, key)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(sigURL)

	// authenticate to gcloud storage and download package signature
	bucketName, objectName, err = utils.ExtractBucketAndObject(sigURL)
	fmt.Println(bucketName)
	fmt.Println(objectName)
	if err != nil {
		log.Fatal(err)
	}
	filePath = "./downloads/package_signature.zip"
	if err := utils.DownloadFromGCS(serviceAccountKeyFilePath, bucketName, objectName, filePath); err != nil {
		log.Fatal(err)
	}

	zipfile = "./downloads/package_signature.zip"
	destDir = "./downloads/package_signatures"
	if err := utils.UnzipFile(zipfile, destDir); err != nil {
		log.Fatal(err)
	}

}