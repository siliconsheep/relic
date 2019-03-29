package main

import (
  "fmt"
  //"errors"
  //"crypto"
  "os"
  "strings"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
  "github.com/aws/aws-sdk-go/service/s3/s3manager"
  //"github.com/sassoftware/relic/internal/signinit"
	//"github.com/sassoftware/relic/signers"
)

type Response events.APIGatewayProxyResponse
type Request events.APIGatewayProxyRequest

// AWS Lambda limits:
// Payload: 6MB (synchronous)
// Execution time: 15min

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

func getCerts() (string, error){
  bucket := "fe-sign-certs"
  //cert_files := []string{"g", "h", "i"}
  //item := "as_sign.pem"
  var result []string

  sess, _ := session.NewSession(&aws.Config{
        Region: aws.String("eu-west-1")},
    )

  downloader := s3manager.NewDownloader(sess)

  params := &s3.ListObjectsInput{
      Bucket: aws.String(bucket),
  }

  svc := s3.New(sess)
  resp, _ := svc.ListObjects(params)

  for _, key := range resp.Contents {
      file, err := os.Create("/tmp/"+*key.Key)
      if err != nil {
          return "", err
      }

      defer file.Close()


      numBytes, err := downloader.Download(file,
          &s3.GetObjectInput{
              Bucket: aws.String(bucket),
              Key:    aws.String(*key.Key),
          })

      if err != nil {
          return "", err
      }

      result = append(result, fmt.Sprintf("Downloaded '%s' (%d bytes)", file.Name(), numBytes))
  }

  return strings.Join(result, ", "), nil
}

// func getBucketObjects(sess *session.Session, bucket string) ([]string, error){
//   result := make([]string, 0)
//
//   query := &s3.ListObjectsV2Input{
// 		Bucket: aws.String(bucket),
// 	}
// 	svc := s3.New(sess)
//
// 	// Flag used to check if we need to go further
// 	truncatedListing := true
//
// 	for truncatedListing {
// 		resp, err := svc.ListObjectsV2(query)
//
// 		if err != nil {
// 			return result, err
// 		}
// 		// Get all files
// 		chunk_result := getObjectsAll(resp, svc, bucket)
//     result = append(result, chunk_result...)
// 		// Set continuation token
// 		query.ContinuationToken = resp.NextContinuationToken
// 		truncatedListing = *resp.IsTruncated
// 	}
//
//   return result, nil
// }
//
// func getObjectsAll(bucketObjectsList *s3.ListObjectsV2Output, s3Client *s3.S3, bucket string) (chunk_result []string) {
// 	//fmt.Println("One ring to rule them all")
// 	// Iterate through the files inside the bucket
// 	for _, key := range bucketObjectsList.Contents {
// 		fmt.Println(*key.Key)
// 		destFilename := *key.Key
// 		if strings.HasSuffix(*key.Key, "/") {
// 			fmt.Println("Got a directory")
// 			continue
// 		}
//
// 		if strings.Contains(*key.Key, "/") {
//             var dirTree string
// 			// split
// 			s3FileFullPathList := strings.Split(*key.Key, "/")
// 			// fmt.Println(s3FileFullPathList)
// 			// fmt.Println("destFilename " + destFilename)
// 			for _, dir := range s3FileFullPathList[:len(s3FileFullPathList)-1] {
// 				dirTree += "/" + dir
// 			}
//             os.MkdirAll("/tmp/"+dirTree, 0775)
// 		}
// 		out, err := s3Client.GetObject(&s3.GetObjectInput{
// 			Bucket: aws.String(bucket),
// 			Key:    key.Key,
// 		})
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		destFilePath := "/tmp/" + destFilename
// 		destFile, err := os.Create(destFilePath)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		_, err = io.Copy(destFile, out.Body)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
//
// 		out.Body.Close()
// 		destFile.Close()
//
//     chunk_result = append(chunk_result, destFilename)
// 	}
//
//   return chunk_result
// }

func Sign(signReq SigningRequest) (SigningResponse, error){
  var signResp SigningResponse

  cert, err := getCerts()
  if err!= nil {
    return signResp, err
  }

  signResp.FileName = signReq.FileName
  signResp.Data = cert

  return signResp, nil

  // fileName := signReq.FileName
  // key := signReq.Key
  //
  // return signResp, nil
  //
  // if fileName == "" || key == "" {
	// 	return errors.New("--file and --key are required")
	// }
  //
	// mod, err := signers.ByFile(fileName, "")
	// if err != nil {
	// 	return err
	// }
	// if mod.Sign == nil {
	// 	return errors.New(errors.New("can't sign this type of file"))
	// }
  //
	// hash := crypto.SHA256
  //
	// token, err := openTokenByKey(argKeyName)
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// cert, opts, err := signinit.Init(context.Background(), mod, token, argKeyName, hash, flags)
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// opts.Path = argFile
	// infile, err := os.OpenFile(argFile, os.O_RDWR, 0)
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// defer infile.Close()
	// if argIfUnsigned {
	// 	if signed, err := mod.IsSigned(infile); err != nil {
	// 		return shared.Fail(err)
	// 	} else if signed {
	// 		fmt.Fprintf(os.Stderr, "skipping already-signed file: %s\n", argFile)
	// 		return nil
	// 	}
	// 	if _, err := infile.Seek(0, 0); err != nil {
	// 		return shared.Fail(fmt.Errorf("failed to rewind input file: %s", err))
	// 	}
	// }
	// // transform the input, sign the stream, and apply the result
	// transform, err := mod.GetTransform(infile, *opts)
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// stream, err := transform.GetReader()
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// blob, err := mod.Sign(stream, cert, *opts)
	// if err != nil {
	// 	return shared.Fail(err)
	// }
	// mimeType := opts.Audit.GetMimeType()
	// if err := transform.Apply(argOutput, mimeType, bytes.NewReader(blob)); err != nil {
	// 	return shared.Fail(err)
	// }
	// // if needed, do a final fixup step
	// if mod.Fixup != nil {
	// 	f, err := os.OpenFile(argOutput, os.O_RDWR, 0)
	// 	if err != nil {
	// 		return shared.Fail(err)
	// 	}
	// 	defer f.Close()
	// 	if err := mod.Fixup(f); err != nil {
	// 		return shared.Fail(err)
	// 	}
	// }
	// if err := signinit.PublishAudit(opts.Audit); err != nil {
	// 	return err
	// }
	// fmt.Fprintln(os.Stderr, "Signed", argFile)
	// return nil
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
			"Content-Type":           "application/json",
		},
	}

	return resp, nil
}

func main() {
	lambda.Start(Handler)
}
