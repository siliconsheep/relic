// AWS Lambda limits:
// Payload: 6MB (synchronous)
// Execution time: 15min

package main

import (
  "fmt"
  "errors"
  "crypto"
  "os"
  "io"
  "io/ioutil"
  "bytes"
  "strings"
  "context"
	"encoding/json"
  "encoding/base64"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

  "github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/signers"
  "github.com/sassoftware/relic/token"
	"github.com/sassoftware/relic/token/open"
  "github.com/sassoftware/relic/lib/passprompt"

  _ "github.com/sassoftware/relic/signers/apk"
	_ "github.com/sassoftware/relic/signers/appmanifest"
	_ "github.com/sassoftware/relic/signers/appx"
	_ "github.com/sassoftware/relic/signers/cab"
	_ "github.com/sassoftware/relic/signers/cat"
	_ "github.com/sassoftware/relic/signers/deb"
	_ "github.com/sassoftware/relic/signers/jar"
	_ "github.com/sassoftware/relic/signers/msi"
	_ "github.com/sassoftware/relic/signers/pecoff"
	_ "github.com/sassoftware/relic/signers/pgp"
	_ "github.com/sassoftware/relic/signers/pkcs"
	_ "github.com/sassoftware/relic/signers/ps"
	_ "github.com/sassoftware/relic/signers/rpm"
	_ "github.com/sassoftware/relic/signers/starman"
	_ "github.com/sassoftware/relic/signers/vsix"
	_ "github.com/sassoftware/relic/signers/xap"
)

type Response events.APIGatewayProxyResponse
type Request events.APIGatewayProxyRequest

type SigningRequest struct {
  FileName      string  `json:"filename"`
	Data          string  `json:"data"`
	Key           string 	`json:"key"`
	Timestamp     bool   	`json:"timestamp"`
}

type SigningResponse struct {
  FileName      string  `json:"filename"`
	Data          string  `json:"data"`
	Success       bool 	  `json:"success"`
}

type ErrorResponse struct {
	Message       string  `json:"message"`
	Success       bool 	  `json:"success"`
}

const (
  WarmStartCheckFile string   = "/tmp/.warmStart"
  CertsDir string             = "/tmp/certs"
  DataDir string              = "/tmp/data"
  CertsS3Bucket string        = "fe-sign-certs"
  CertsS3BucketRegion string  = "eu-west-1"
  CertsS3Prefix string        = "certs/"
  HashAlgorithm crypto.Hash   = crypto.SHA256
)

var (
  initErr     error
  warmStart   bool
  relicConfig *config.Config
  tokenMap    map[string]token.Token
)

func init() {
    if _, err := os.Stat(WarmStartCheckFile); err != nil {
        fmt.Println("[Init] Starting initialization routine")
        warmStart = false
        initErr = downloadCerts(CertsDir)
        if initErr != nil {
            fmt.Println(err)
            return
        }
        relicConfig, initErr = generateConfig()
        if initErr != nil {
            fmt.Println(err)
            return
        }
        //fmt.Printf("[Init] Generated config: \n%#v\n", *relicConfig)

        cfgJson, _ := json.Marshal(*relicConfig)
        fmt.Printf("[Init] Generated config: \n----\n%s\n-----\n", string(cfgJson))

        wsFile, _ := os.Create(WarmStartCheckFile)
        wsFile.Close()
        os.MkdirAll(DataDir, 0775)
    } else {
      warmStart = true
      fmt.Println("[Init] Warm start detected, skipping initialization")
    }
}

func downloadCerts(certsDir string) (error) {
    sess, _ := session.NewSession(&aws.Config{
        Region: aws.String(CertsS3BucketRegion)},
    )
    query := &s3.ListObjectsV2Input{
  		Bucket: aws.String(CertsS3Bucket),
      Prefix: aws.String(CertsS3Prefix),
  	}
  	svc := s3.New(sess)

  	// Flag used to check if we need to go further
  	truncatedListing := true

  	for truncatedListing {
  		resp, err := svc.ListObjectsV2(query)

  		if err != nil {
  			return err
  		}

  		err = downloadCertsChunk(resp, svc)
      if err != nil {
  			return err
  		}
  		query.ContinuationToken = resp.NextContinuationToken
  		truncatedListing = *resp.IsTruncated
  	}

    return nil
}

func downloadCertsChunk(bucketObjectsList *s3.ListObjectsV2Output, s3Client *s3.S3) (error) {
    fmt.Printf("[Init] Found %d files in bucket %s\n", len(bucketObjectsList.Contents), CertsS3Bucket)
  	for _, key := range bucketObjectsList.Contents {
    		destFilename := *key.Key
        destFilename = destFilename[len(CertsS3Prefix):]
    		if strings.HasSuffix(*key.Key, "/") {
          fmt.Printf("[Init] Skipping directory entry %s\n", *key.Key)
    			continue
    		}

    		if strings.Contains(*key.Key, "/") {
            var dirTree string

        		s3FileFullPathList := strings.Split(*key.Key, "/")

        		for _, dir := range s3FileFullPathList[1:len(s3FileFullPathList)-1] {
        			dirTree += "/" + dir
        		}
            fmt.Printf("[Init] Creating folder structure %s\n", dirTree)
            os.MkdirAll(CertsDir+"/"+dirTree, 0775)
    		}
        fmt.Printf("[Init] Downloading file %s\n", *key.Key)
    		out, err := s3Client.GetObject(&s3.GetObjectInput{
    			Bucket: aws.String(CertsS3Bucket),
    			Key:    key.Key,
    		})
    		if err != nil {
    			return err
    		}

    		destFilePath := CertsDir + "/" + destFilename
    		destFile, err := os.Create(destFilePath)
    		if err != nil {
    			return err
    		}

    		bytes, err := io.Copy(destFile, out.Body)
    		if err != nil {
    			return err
    		}
        fmt.Printf("[Init] Downloaded cert %s (%d bytes)\n", destFilePath, bytes)
    		out.Body.Close()
    		destFile.Close()
  	}

    return nil
}

func generateConfig() (*config.Config, error) {
    fmt.Println("[Init] Generating Relic config")
    tokenCfg := config.TokenConfig{
      Type:         "file",
    }
    timestampCfg := config.TimestampConfig{
      URLs:         []string{
        "http://sha256timestamp.ws.symantec.com/sha256/timestamp",
        "http://timestamp.globalsign.com/scripts/timstamp.dll",
      },
    	Timeout:  60,
    }
    keyCfgs := make(map[string]*config.KeyConfig)

    dirs, err := ioutil.ReadDir(CertsDir)
  	if err != nil {
  		return nil, err
  	}

  	for _, dir := range dirs {
  		  if dir.IsDir() {
            keyName := dir.Name()
            fmt.Printf("Checking if folder %s contains certificates to use\n", keyName)
            if _, err := os.Stat(fmt.Sprintf("%s/%s/cert.key", CertsDir, keyName)); err != nil {
                fmt.Printf("No private key found in %s/%s\n", CertsDir, keyName)
                continue
            }
            if _, err := os.Stat(fmt.Sprintf("%s/%s/cert.key", CertsDir, keyName)); err != nil {
              fmt.Printf("No public key found in %s/%s\n", CertsDir, keyName)
                continue
            }
            fmt.Printf("Valid certificate found in %s/%s\n", CertsDir, keyName)
            keyCfgs[keyName] = &config.KeyConfig{
              Token:            "signing_token",
            	X509Certificate:  fmt.Sprintf("%s/%s/cert.pem", CertsDir, keyName),
            	KeyFile:          fmt.Sprintf("%s/%s/cert.key", CertsDir, keyName),
            	Timestamp:        true,
            }
        }
  	}

    cfg := &config.Config{
        Tokens: map[string]*config.TokenConfig{
          "signing_token": &tokenCfg,
        },
        Keys: keyCfgs,
        Timestamp: &timestampCfg,
    }

    return cfg, cfg.Normalize("<env>")
}

func openToken(tokenName string) (token.Token, error) {
	tok, ok := tokenMap[tokenName]
	if ok {
		return tok, nil
	}

	prompt := new(passprompt.PasswordPrompt)
	tok, err := open.Token(relicConfig, tokenName, prompt)
	if err != nil {
		return nil, err
	}
	if tokenMap == nil {
		tokenMap = make(map[string]token.Token)
	}
	tokenMap[tokenName] = tok
	return tok, nil
}

func openTokenByKey(keyName string) (token.Token, error) {
	if keyName == "" {
		return nil, errors.New("--key is a required parameter")
	}
	keyConf, err := relicConfig.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	tok, err := openToken(keyConf.Token)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func Sign(signReq SigningRequest) (SigningResponse, error){
  var signResp SigningResponse

  key := signReq.Key
  decodedData, err := base64.StdEncoding.DecodeString(signReq.Data)
  if err != nil {
		return signResp, err
	}

  tempFile, err := ioutil.TempFile(DataDir, "*_"+signReq.FileName)
  tempFileName := tempFile.Name()
  if err != nil {
		return signResp, err
	}
  defer os.Remove(tempFileName)

  if _, err := tempFile.Write(decodedData); err != nil {
		return signResp, err
	}
  tempFile.Close()

	mod, err := signers.ByFile(tempFileName, "")
	if err != nil {
		return signResp, err
	}
	if mod.Sign == nil {
		return signResp, errors.New("can't sign this type of file")
	}

  fmt.Printf("Selected signer %s for file %s", mod.Name, signReq.FileName)

	token, err := openTokenByKey(key)
	if err != nil {
		return signResp, err
	}
	cert, opts, err := SignInit(context.Background(), mod, token, key, HashAlgorithm, nil)
	if err != nil {
		return signResp, err
	}
	opts.Path = tempFileName

  tempFile, err = os.OpenFile(tempFileName, os.O_RDWR, 0)
	if err != nil {
		return signResp, err
	}
  defer tempFile.Close()

	// transform the input, sign the stream, and apply the result
	transform, err := mod.GetTransform(tempFile, *opts)
	if err != nil {
		return signResp, err
	}
	stream, err := transform.GetReader()
	if err != nil {
		return signResp, err
	}
	blob, err := mod.Sign(stream, cert, *opts)
	if err != nil {
		return signResp, err
	}
	mimeType := opts.Audit.GetMimeType()
	if err := transform.Apply(tempFileName, mimeType, bytes.NewReader(blob)); err != nil {
		return signResp, err
	}
	// if needed, do a final fixup step
	if mod.Fixup != nil {
    f, err := os.OpenFile(tempFileName, os.O_RDWR, 0)
		if err != nil {
			return signResp, err
		}
		defer f.Close()
		if err := mod.Fixup(f); err != nil {
			return signResp, err
		}
	}

  tempFile, err = os.Open(tempFileName)
  if err != nil {
    return signResp, err
  }
  defer tempFile.Close()
  tempFileInfo, err := tempFile.Stat()
  if err != nil {
    return signResp, err
  }

  tempFileSize := tempFileInfo.Size()
  buffer := make([]byte, tempFileSize)

  _, err = tempFile.Read(buffer)
  if err != nil {
    return signResp, err
  }

  signResp.FileName = signReq.FileName
  signResp.Data = base64.StdEncoding.EncodeToString(buffer)
  signResp.Success = true

	return signResp, nil
}

func Fail(errMessage string) (Response){
  body := ErrorResponse{errMessage, false}
  jsonBody, _ := json.Marshal(body)

  return Response{
    StatusCode:      404,
		IsBase64Encoded: false,
		Body:            string(jsonBody),
		Headers:         map[string]string{
		    "Content-Type": "application/json",
    },
  }
}

func Handler(request Request) (Response, error) {
  var signReq SigningRequest
  err := json.Unmarshal([]byte(request.Body), &signReq)

  if err != nil {
		return Fail("Could not parse request"), err
	}

  signedData, err := Sign(signReq)

  if err != nil {
		return Fail(fmt.Sprintf("Failed to sign file %s", signReq.FileName)), err
	}

	body, err := json.Marshal(signedData)

  if err != nil {
		return Fail("Could not format response"), err
	}

	resp := Response{
		StatusCode:      200,
		IsBase64Encoded: false,
		Body:            string(body),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

  fmt.Printf("[fe-sign] Signed file %s | Timestamped: %s | Warm Start: %s\n",
    signReq.FileName, formatBool(signReq.Timestamp), formatBool(warmStart))

	return resp, nil
}

func formatBool(boolVal bool) string {
    if boolVal {
      return "Yes"
    }  else {
      return "No"
    }
}

func main() {
	lambda.Start(Handler)
}
