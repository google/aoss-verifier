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
	"os/user"
	"path/filepath"
	"os"
	"bufio"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var (
	configFilePath string
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
	// Check if the service account key file path is provided
	if len(args) == 0 {
		return fmt.Errorf("Please specify the service account key file path")
	}

	if len(args) != 1 {
		return fmt.Errorf("Incorrect usage")
	}

	// if config file exists already, os.Create will truncate and update
	file, err := os.Create(configFilePath)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

	// Write the service account key file path to the config file
	writer := bufio.NewWriter(file)
	if _, err = fmt.Fprintf(writer, "service_account_key_file: %v", args[0]); err != nil {
		log.Fatal(err)
	}
	writer.Flush()

	fmt.Println("aoss-verifier config updated successfully")

	return nil
}