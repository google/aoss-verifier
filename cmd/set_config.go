package cmd

import (
	"fmt"
	"log"
	"os/user"
	"path/filepath"
	"os"
	"bufio"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var (
	configFilePath string
	serviceAccountKeyFilePath string
	homeDir string
	
	setConfigCmd = &cobra.Command{
		Use:   "set-config service_account_key_file",
		Short: "Set the configuration settings",
		Long:  "Set the configuration settings by providing the path to the service account key file.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := setConfig(cmd, args); err != nil {
				log.Fatalf("Failed to set config: %v\nUse -h for more information\n", err)
			}
		},
	}
)


func init() {
	rootCmd.AddCommand(setConfigCmd)

	// Get the user's home directory
	usr, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get user's home directory: %v", err)
	}
	homeDir = usr.HomeDir

	// Set the configuration file name and location
	viper.SetConfigName(".aoss-verifier")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(homeDir)

	// Set the config file path to the user's home directory
	configFilePath = filepath.Join(homeDir, ".aoss-verifier.yaml")
}


func setConfig(cmd *cobra.Command, args []string) error {
	// if no argument is passed
	if len(args) == 0 {
		return fmt.Errorf("Please specify the service account key file path")
	}

	if len(args) != 1 {
		return fmt.Errorf("Incorrect usage")
	}

	// if config file exists already, os.Create will truncate and update
	f, err := os.Create(configFilePath)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

	// path is relative to the current directory
	w := bufio.NewWriter(f)
	if _, err = fmt.Fprintf(w, "service_account_key_file: %v", args[0]); err != nil {
		log.Fatal(err)
	}
	w.Flush()

	fmt.Println("Config updated successfully")

	return nil
}