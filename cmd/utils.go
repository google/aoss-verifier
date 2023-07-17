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
    "context"
    "os"
    "io"
    "io/ioutil"
    "path/filepath"
    "archive/zip"
    "encoding/json"
    "strings"
    "crypto/sha256"
    "encoding/hex"
    "encoding/base64"
    "crypto/x509"
    "crypto/ecdsa"
    "encoding/pem"
    "net/http"
    "os/exec"
    "bytes"
    "errors"

    "google.golang.org/api/option"
    "cloud.google.com/go/storage"
)


const rootCertURL = "https://privateca-content-6333d504-0000-2df7-afd6-30fd38154590.storage.googleapis.com/a2c725a592f1d586f1f8/ca.crt"


// The 'sbom' key in the buildInfo.json contains package information
// from where the signature zip URL is extracted.
type sbom struct {
    Packages []struct {
        Spdxid                string `json:"SPDXID"`
        ExternalRefs     	  []struct {
            ReferenceCategory	string `json:"referenceCategory"`
            ReferenceLocator  	string `json:"referenceLocator"`
        } `json:"externalRefs"`
    } `json:"packages"`
}


func downloadFromGCS(serviceAccountKeyFilePath string, bucketName string, objectName string, filePath string) error {
    ctx := context.Background()

    // Authenticate using the service account key file.
    client, err := storage.NewClient(ctx, option.WithCredentialsFile(serviceAccountKeyFilePath))
    if err != nil {
        return fmt.Errorf("Failed to authenticate to GCS: %v", err)
    }

    reader, err := client.Bucket(bucketName).Object(objectName).NewReader(ctx)
    if err != nil {
        return fmt.Errorf("Failed to open object: %v", err)
    }
    defer reader.Close()

    file, err := os.Create(filePath)
    if err != nil {
        return fmt.Errorf("Failed to create file: %v", err)
    }
    defer file.Close()

    if _, err := io.Copy(file, reader); err != nil {
        return fmt.Errorf("Failed to download the file: %v", err)
    }

    // Close the client.
    client.Close()

    return nil
}


func unzipFile(zipFile, destDir string) error {
    reader, err := zip.OpenReader(zipFile)
    if err != nil {
        return fmt.Errorf("failed to open zip file: %v", err)
    }
    defer reader.Close()

    for _, file := range reader.File {
        filePath := filepath.Join(destDir, file.Name)
        if err := copyZipFileContent(filePath, file); err != nil {
            return err
        }
    }

    return nil
}


func copyZipFileContent(filePath string, file *zip.File) error {
    writer, err := os.Create(filePath)
    defer writer.Close()
    if err != nil {
        return fmt.Errorf("failed to create file: %v", err)
    }

    reader, err := file.Open()
    defer reader.Close()
    if err != nil {
        return fmt.Errorf("failed to open file inside zip: %v", err)
    }

    if _, err = io.Copy(writer, reader); err != nil {
        return fmt.Errorf("failed to extract file from zip: %v", err)
    }

    return nil
}


func parseBuildInfoJSON(jsonFile string) (signatureURL, gcpKmsKey string, buildProvSig []byte, err error) {
    // Read the JSON file.
    data, err := ioutil.ReadFile(jsonFile)
    if err != nil {
        return "", "", nil, fmt.Errorf("Failed to read JSON file: %v", err)
    }

    // Create a map to hold the JSON data.
    var jsonData map[string]interface{}
    if err := json.Unmarshal(data, &jsonData); err != nil {
        return "", "", nil, fmt.Errorf("Failed to unmarshal JSON data: %v", err)
    }

    // Access the value of the "sbom" key.
    key := "sbom"
    sbomValue := jsonData[key].(string)

    var sbomData *sbom
    if err = json.Unmarshal([]byte(sbomValue), &sbomData); err != nil {
        return "", "", nil, fmt.Errorf("Failed to unmarshal 'sbom' data: %v", err)
    }

    // Get url of the signature zip of the package.
    for _, element := range sbomData.Packages {
        if strings.HasPrefix(element.Spdxid, "SPDXRef-Package") {
            for _, val := range element.ExternalRefs {
                if val.ReferenceCategory == "OTHER" {
                    signatureURL = val.ReferenceLocator
                }
            }
        }
    }

    // Get signature, key for build provenance.
    buildDetailsArray := jsonData["buildDetails"].([] interface{})
    gcpKmsKey, buildProvSig = getGcpKmsKeyAndBuildProvSig(buildDetailsArray)
    
    return  signatureURL, gcpKmsKey, buildProvSig, nil
}


func getGcpKmsKeyAndBuildProvSig(buildDetailsArray []interface{}) (gcpKmsKey string, buildProvSig []byte) {
    for _, element := range buildDetailsArray {
        buildDetailsData := element.(map[string]interface{})
        envelopeData := buildDetailsData["envelope"].(map[string]interface{})
        sigData := envelopeData["signatures"].([] interface{})
        for _, item := range sigData {
            sigDataMap := item.(map[string]interface{})
            for label, value := range sigDataMap {
                if label == "keyid" {
                    gcpKmsKey = strings.TrimPrefix(value.(string), "gcpkms://")
                    fields := strings.Split(gcpKmsKey, "/")
                    for index, str := range fields {
                        if str == "cryptoKeys" {
                            gcpKmsKey = fields[index + 1]
                            break
                        }
                    }
                } else {
                    buildProvSig, _ = base64.StdEncoding.DecodeString(value.(string))
                }
            }
        }
    }

    return gcpKmsKey, buildProvSig
}


func extractBucketAndObject(url string) (bucketName, objectName string, err error) {
    // Remove the "gs://" prefix.
    url = strings.TrimPrefix(url, "gs://")

    // Split the URL into parts.
    parts := strings.SplitN(url, "/", 2)
    if len(parts) != 2 {
        return "", "", fmt.Errorf("invalid URL format")
    }

    return parts[0], parts[1], nil
}


func verifyDigest(artifactPath, destDir string) (ok bool, err error) {
    // Generate sha256 hash.
    packageFile, err := os.Open(artifactPath)
    if err != nil {
        return false, err
    }
    defer packageFile.Close()

    dataDigest := sha256.New()
    if _, err := io.Copy(dataDigest, packageFile); err != nil {
        return false, err
    }

    digest := hex.EncodeToString(dataDigest.Sum(nil))

    fileContent, err := ioutil.ReadFile(filepath.Join(destDir, "digest.txt"))
    if err != nil {
        return false, err
    }
    text := string(fileContent)
    actualDigest := getFieldFromLine(text, ":")

    if digest == actualDigest {
        return true, nil
    } else {
        return false, nil
    }
}


func verifySignatures(destDir string, cert *x509.Certificate) (ok bool, err error) {
    // Extract signature and convert to binary.
    signatureFilePath := filepath.Join(destDir, "signature.txt")
    signatureBytes, err := extractAndConvertToBinary(signatureFilePath)
    if err != nil {
        return false, fmt.Errorf("Failed to decode signature hex: %v", err)
    }

    // Extract digest and convert to binary.
    digestFilePath := filepath.Join(destDir, "digest.txt")
    digestBytes, err := extractAndConvertToBinary(digestFilePath)
    if err != nil {
        return false, fmt.Errorf("Failed to decode digest hex: %v", err)
    }

    // Extract public key.
    pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
        return false, fmt.Errorf("Failed to parse ECDSA public key")
    }

    return ecdsa.VerifyASN1(pubKey, digestBytes, signatureBytes), nil
}


func parseCertificate(destDir string) (certificate *x509.Certificate, err error) {
    certPath := filepath.Join(destDir, "cert.pem")
    certBytes, err := ioutil.ReadFile(certPath)
    if err != nil {
        return nil, fmt.Errorf("Failed to read cert.pem: %v", err)
    }
    block, _ := pem.Decode(certBytes)
    if block == nil {
        return nil, fmt.Errorf("Failed to decode certificate PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("Failed to parse certificate: %v", err)
    }

    return cert, nil
}


func downloadRootCert(rootCertPath string) error {
    file, err := os.Create(rootCertPath)
    if err != nil {
        return fmt.Errorf("Failed to create file: %v", err)
    }
    defer file.Close()

    // Send a GET request to the URL.
    response, err := http.Get(rootCertURL)
    if err != nil {
        return fmt.Errorf("Failed to download: %v", err)
    }
    defer response.Body.Close()

    // Check the response status code.
    if response.StatusCode != http.StatusOK {
        return fmt.Errorf("Failed to download: recieved status code %d", response.StatusCode)
    }

    // Copy the response body to the file.
    _, err = io.Copy(file, response.Body)
    if err != nil {
        return err
    }

    return nil
}


func verifyCertificate(destDir, rootCertPath string, cert *x509.Certificate) (ok bool, err error) {
    rootBytes, err := ioutil.ReadFile(rootCertPath)
    if err != nil {
        return false, fmt.Errorf("Failed to read CA file: %v", err)
    }

    // Verify the leaf certificate with the cert chain and the root certificate.
    certChainPath := filepath.Join(destDir, "certChain.pem")
    chainBytes, err := ioutil.ReadFile(certChainPath)
    if err != nil {
        return false, fmt.Errorf("Failed to read certificate chain file: %v", err)
    }

    // Create a certificate pool and add the CA certificate to it.
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(rootBytes)

    // Create a certificate verifier with the pool and intermediate certificates.
    verifier := x509.VerifyOptions{
        Roots:         pool,
        Intermediates: x509.NewCertPool(),
    }

    // Add the intermediate certificates to the verifier.
    verifier.Intermediates.AppendCertsFromPEM(chainBytes)

    if _, err := cert.Verify(verifier); err != nil {
        return false, err
    }

    return true, nil
}


func verifyBuildProv(publicKeyPath, buildProvSigPath, artifactPath string) (stdoutput, stderror string, exitCode int, err error) {
    var stdout, stderr bytes.Buffer
    cosignCmd := exec.Command("cosign", "verify-blob-attestation",
        "--insecure-ignore-tlog",
        "--key", publicKeyPath,
        "--signature", buildProvSigPath,
        "--type", "slsaprovenance",
        "--check-claims=true",
        artifactPath,
    )

    cosignCmd.Stdout = &stdout
    cosignCmd.Stderr = &stderr

    err = cosignCmd.Run()

    exitCode = 0
    var exitError *exec.ExitError
    if errors.As(err, &exitError) {
        exitCode = exitError.ExitCode()
    }

    return stdout.String(), stderr.String(), exitCode, err
}


func extractAndConvertToBinary(inputFilePath string) (Bytes []byte, err error) {
    hexValue, err := ioutil.ReadFile(inputFilePath)
    if err != nil {
        return nil, fmt.Errorf("Failed to read the input file: %v", err)
    }

    field := getFieldFromLine(string(hexValue), ":")
    dataBytes, err := hex.DecodeString(field)
    if err != nil {
        return nil, fmt.Errorf("Failed to decode the hex: %v", err)
    }

    return dataBytes, nil
}


// Extract the field value from a line based on the delimiter.
func getFieldFromLine(line, delimiter string) string {
    fields := strings.Split(line, delimiter)
    if len(fields) > 1 {
        return strings.TrimSpace(fields[1])
    }
    return ""
}