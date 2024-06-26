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
    "archive/zip"
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "cloud.google.com/go/storage"
    "google.golang.org/api/option"
)

const rootCertURL = "https://privateca-content-6333d504-0000-2df7-afd6-30fd38154590.storage.googleapis.com/a2c725a592f1d586f1f8/ca.crt"

type buildInfo struct {
    BuildDetails []struct {
        Envelope struct {
            Signatures []struct {
                Sig   string `json:"sig"`
                Keyid string `json:"keyid"`
            } `json:"signatures"`
        } `json:"envelope"`
    } `json:"buildDetails"`
    Sbom string `json:"sbom"`
}

type premiumBuildInfo struct {
    BuildDetails []struct {
        BuildProvenances []struct {
            Envelope struct {
                Signatures []struct {
                    Sig   string `json:"sig"`
                    Keyid string `json:"keyid"`
                } `json:"signatures"`
            } `json:"envelope"`
            ProvenancePublicKey string `json:"provenancePublicKey"`
        } `json:"buildProvenances"`
    } `json:"buildDetails"`
    Sbom string `json:"sbom"`
}

type amalgamView struct {
    BuildInfo           string     `json:"buildInfo"`
    VexInfo             string     `json:"vexInfo"`
    HealthInfo          string     `json:"healthInfo"`
    BuildInfoSignature  SigDetails `json:"buildInfoSignature"`
    HealthInfoSignature SigDetails `json:"healthInfoSignature"`
    VexInfoSignature    SigDetails `json:"vexInfoSignature"`
}

type SigDetails struct {
    CertInfo struct {
        Cert      string `json:"cert"`
        CertChain string `json:"certChain"`
    } `json:"certInfo"`
    Digest []struct {
        Digest    string `json:"digest"`
        Algorithm string `json:"Algorithm"`
    } `json:"digest"`
    Signature []struct {
        Signature string `json:"signature"`
        Algorithm string `json:"Algorithm"`
    } `json:"signature"`
}

// The 'sbom' key in the buildInfo.json contains package
// info from where the signature zip URL is extracted.
type sbom struct {
    Packages []struct {
        Spdxid       string `json:"SPDXID"`
        ExternalRefs []struct {
            ReferenceCategory string `json:"referenceCategory"`
            ReferenceLocator  string `json:"referenceLocator"`
        } `json:"externalRefs"`
        Annotations []struct {
            Comment string `json:"comment"`
        } `json:"annotations"`
    } `json:"packages"`
}

func downloadFromGCS(ctx context.Context, serviceAccountKeyFilePath string, bucketName string, objectName string, filePath string) error {
    // Authenticate using the service account key file.
    client, err := storage.NewClient(ctx, option.WithCredentialsFile(serviceAccountKeyFilePath))
    if err != nil {
        return fmt.Errorf("failed to authenticate to GCS: %v", err)
    }
    // Close the client.
    defer client.Close()

    reader, err := client.Bucket(bucketName).Object(objectName).NewReader(ctx)
    if err != nil {
        return fmt.Errorf("failed to open object: %v", err)
    }
    defer reader.Close()

    file, err := os.Create(filePath)
    if err != nil {
        return fmt.Errorf("failed to create file: %v", err)
    }
    defer file.Close()

    if _, err := io.Copy(file, reader); err != nil {
        return fmt.Errorf("failed to download the file: %v", err)
    }

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
    if err != nil {
        return fmt.Errorf("failed to create file: %v", err)
    }
    defer writer.Close()

    reader, err := file.Open()
    if err != nil {
        return fmt.Errorf("failed to open file inside zip: %v", err)
    }
    defer reader.Close()

    if _, err = io.Copy(writer, reader); err != nil {
        return fmt.Errorf("failed to extract file from zip: %v", err)
    }

    return nil
}

func parseBuildInfoJSON(jsonFile, suffix string) (sigURL, gcpKmsKey string, buildProvSig []byte, err error) {
    // Read the JSON file.
    data, err := os.ReadFile(jsonFile)
    if err != nil {
        return "", "", nil, fmt.Errorf("failed to read JSON file: %v", err)
    }

    var jsonData *buildInfo
    if err = json.Unmarshal(data, &jsonData); err != nil {
        return "", "", nil, fmt.Errorf("ailed to unmarshal JSON data: %v", err)
    }

    var sbomData *sbom
    if err = json.Unmarshal([]byte(jsonData.Sbom), &sbomData); err != nil {
        return "", "", nil, fmt.Errorf("failed to unmarshal 'sbom' data: %v", err)
    }

    // Get url of the signature zip of the package.
    for _, element := range sbomData.Packages {
        if strings.HasSuffix(element.Spdxid, suffix) {
            for _, val := range element.ExternalRefs {
                if val.ReferenceCategory == "OTHER" {
                    sigURL = val.ReferenceLocator
                }
            }
        }
    }

    // Get build provenance signatures and public key.
    if len(jsonData.BuildDetails) < 1 {
        return "", "", nil, fmt.Errorf("couldn't get build details")
    }
    if len(jsonData.BuildDetails[0].Envelope.Signatures) < 1 {
        return "", "", nil, fmt.Errorf("couldn't get build provenance signatures")
    }

    envelopeSig := jsonData.BuildDetails[0].Envelope.Signatures[0]
    buildProvSig, _ = base64.StdEncoding.DecodeString(envelopeSig.Sig)
    gcpKmsKey = strings.TrimPrefix(envelopeSig.Keyid, "gcpkms://")
    fields := strings.Split(gcpKmsKey, "/")
    for index, str := range fields {
        if str == "cryptoKeys" {
            gcpKmsKey = fields[index+1]
            break
        }
    }

    return sigURL, gcpKmsKey, buildProvSig, nil
}

func parsePremiumBuildInfoJSON(jsonFile, suffix string) (sigDetails *SigDetails, provenancePublicKey string, buildProvSig []byte, err error) {
    // Read the JSON file.
    data, err := os.ReadFile(jsonFile)
    if err != nil {
        return nil, "", nil, fmt.Errorf("failed to read JSON file: %v", err)
    }

    var amalgamView *amalgamView
    if err = json.Unmarshal(data, &amalgamView); err != nil {
        return nil, "", nil, fmt.Errorf("failed to unmarshal JSON data: %v", err)
    }

    var jsonData *premiumBuildInfo
    if err = json.Unmarshal([]byte(amalgamView.BuildInfo), &jsonData); err != nil {
        return nil, "", nil, fmt.Errorf("failed to unmarshal buildInfo JSON data: %v", err)
    }
    var sbomData *sbom
    if err = json.Unmarshal([]byte(jsonData.Sbom), &sbomData); err != nil {
        return nil, "", nil, fmt.Errorf("failed to unmarshal 'sbom' data %v: %v", jsonData.Sbom, err)
    }

    // Get signature Details of the package.
    for _, element := range sbomData.Packages {
        if strings.HasSuffix(element.Spdxid, suffix) {
            comment := element.Annotations[0].Comment
            if err = json.Unmarshal([]byte(comment), &sigDetails); err != nil {
                return nil, "", nil, fmt.Errorf("failed to unmarshal JSON data: %v", err)
            }
        }
    }

    // Get build provenance signatures and public key.
    if len(jsonData.BuildDetails) < 1 {
        return nil, "", nil, fmt.Errorf("couldn't get build details")
    }
    if len(jsonData.BuildDetails[0].BuildProvenances) < 1 {
        return nil, "", nil, fmt.Errorf("couldn't get build provenance details")
    }
    if len(jsonData.BuildDetails[0].BuildProvenances[0].Envelope.Signatures) < 1 {
        return nil, "", nil, fmt.Errorf("couldn't get build provenance signature")
    }

    envelopeSig := jsonData.BuildDetails[0].BuildProvenances[0].Envelope.Signatures[0]
    buildProvSig, _ = base64.StdEncoding.DecodeString(envelopeSig.Sig)
    provenancePublicKey = jsonData.BuildDetails[0].BuildProvenances[0].ProvenancePublicKey

    return sigDetails, provenancePublicKey, buildProvSig, nil
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

func verifyDigest(digestBytes []byte, actualDigest string) (ok bool, err error) {

    dataDigest := sha256.New()
    if _, err := io.WriteString(dataDigest, string(digestBytes)); err != nil {
        return false, err
    }

    digest := hex.EncodeToString(dataDigest.Sum(nil))
    if digest == actualDigest {
        return true, nil
    }
    return false, nil
}

func verifySignatures(signatureBytes, digestBytes []byte, cert *x509.Certificate) (ok bool, err error) {
    // Extract public key.
    pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
        return false, fmt.Errorf("failed to parse ECDSA public key")
    }

    return ecdsa.VerifyASN1(pubKey, digestBytes, signatureBytes), nil
}

func parseCertificate(certBytes []byte) (certificate *x509.Certificate, err error) {
    block, _ := pem.Decode(certBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode certificate PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate: %v", err)
    }

    return cert, nil
}

func downloadRootCert(rootCertPath string) error {
    file, err := os.Create(rootCertPath)
    if err != nil {
        return fmt.Errorf("failed to create file: %v", err)
    }
    defer file.Close()

    // Send a GET request to the URL.
    response, err := http.Get(rootCertURL)
    if err != nil {
        return fmt.Errorf("failed to download: %v", err)
    }
    defer response.Body.Close()

    // Check the response status code.
    if response.StatusCode != http.StatusOK {
        return fmt.Errorf("failed to download: recieved status code %d", response.StatusCode)
    }

    // Copy the response body to the file.
    _, err = io.Copy(file, response.Body)
    if err != nil {
        return err
    }

    return nil
}

func verifyCertificate(chainBytes []byte, rootCertPath string, cert *x509.Certificate) (ok bool, err error) {
    bytes, err := os.ReadFile(rootCertPath)
    if err != nil {
        return false, fmt.Errorf("failed to read CA file: %v", err)
    }

    // Create a certificate pool and add the CA certificate to it.
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(bytes)

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
    hexValue, err := os.ReadFile(inputFilePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read the input file: %v", err)
    }

    field := getFieldFromLine(string(hexValue), ":")
    bytes, err := hex.DecodeString(field)
    if err != nil {
        return nil, fmt.Errorf("failed to decode the hex: %v", err)
    }

    return bytes, nil
}

// Extract the field value from a line based on the delimiter.
func getFieldFromLine(line, delimiter string) string {
    fields := strings.Split(line, delimiter)
    if len(fields) > 1 {
        return strings.TrimSpace(fields[1])
    }
    return ""
}
