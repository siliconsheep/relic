/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package signrpm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sassoftware/go-rpmutils"
	"golang.org/x/crypto/openpgp/packet"
)

type SigInfo struct {
	Header    *rpmutils.RpmHeader
	PublicKey *packet.PublicKey
	Timestamp time.Time
	KeyName   string
}

func defaultOpts(opts *rpmutils.SignatureOptions) *rpmutils.SignatureOptions {
	var newOpts rpmutils.SignatureOptions
	if opts != nil {
		newOpts = *opts
	}
	if newOpts.Hash == 0 {
		newOpts.Hash = crypto.SHA256
	}
	if newOpts.CreationTime.IsZero() {
		newOpts.CreationTime = time.Now().UTC().Round(time.Second)
	}
	return &newOpts
}

type jsonInfo struct {
	Fingerprint string    `json:"fingerprint"`
	HeaderSig   []byte    `json:"header_sig"`
	Md5         string    `json:"md5"`
	Nevra       string    `json:"nevra"`
	PayloadSig  []byte    `json:"payload_sig"`
	Sha1        string    `json:"sha1"`
	Timestamp   time.Time `json:"timestamp"`
}

func (info *SigInfo) Dump(stream io.Writer) {
	var jinfo jsonInfo
	jinfo.HeaderSig, _ = info.Header.GetBytes(rpmutils.SIG_RSA)
	jinfo.PayloadSig, _ = info.Header.GetBytes(rpmutils.SIG_PGP)
	jinfo.Fingerprint = fmt.Sprintf("%X", info.PublicKey.Fingerprint)
	nevra, _ := info.Header.GetNEVRA()
	jinfo.Nevra = nevra.String()
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	jinfo.Md5 = fmt.Sprintf("%x", md5)
	jinfo.Sha1, _ = info.Header.GetString(rpmutils.SIG_SHA1)
	jinfo.Timestamp = info.Timestamp

	enc := json.NewEncoder(stream)
	enc.SetIndent("", "  ")
	enc.Encode(&jinfo)
	stream.Write([]byte{'\n'})
}

func (info *SigInfo) LogTo(stream io.Writer) {
	nevra, _ := info.Header.GetNEVRA()
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	sha1, _ := info.Header.GetString(rpmutils.SIG_SHA1)
	fmt.Fprintf(stream, "Signed %s using %s(%X) md5=%X sha1=%s\n", nevra, info.KeyName, info.PublicKey.Fingerprint, md5, sha1)
}

func SignRpmStream(stream io.Reader, key *packet.PrivateKey, opts *rpmutils.SignatureOptions) (*SigInfo, error) {
	opts = defaultOpts(opts)
	header, err := rpmutils.SignRpmStream(stream, key, opts)
	if err != nil {
		return nil, err
	}
	return &SigInfo{Header: header, PublicKey: &key.PublicKey, Timestamp: opts.CreationTime}, nil
}

func SignRpmFile(infile *os.File, outpath string, key *packet.PrivateKey, opts *rpmutils.SignatureOptions) (*SigInfo, error) {
	opts = defaultOpts(opts)
	header, err := rpmutils.SignRpmFile(infile, outpath, key, opts)
	if err != nil {
		return nil, err
	}
	return &SigInfo{Header: header, PublicKey: &key.PublicKey, Timestamp: opts.CreationTime}, nil
}
