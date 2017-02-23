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

package token

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signjar"
	"github.com/spf13/cobra"
)

var SignJarCmd = &cobra.Command{
	Use:   "sign-jar",
	Short: "Sign a Jar JAR using a X509 key in a token",
	RunE:  signJarCmd,
}

var SignJarManifestCmd = &cobra.Command{
	Use:   "sign-jar-manifest",
	Short: "Sign a Jar JAR manifest using a X509 key in a token",
	RunE:  signJarManifestCmd,
}

var (
	argSignFileOutput  string
	argKeyAlias        string
	argSectionsOnly    bool
	argInlineSignature bool
)

func init() {
	shared.RootCmd.AddCommand(SignJarCmd)
	shared.AddDigestFlag(SignJarCmd)
	addAuditFlags(SignJarCmd)
	SignJarCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignJarCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input JAR file to sign")
	SignJarCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file for JAR. Defaults to same as input.")
	SignJarCmd.Flags().StringVar(&argKeyAlias, "key-alias", "RELIC", "Alias to use for the signed manifest")
	SignJarCmd.Flags().BoolVar(&argSectionsOnly, "sections-only", false, "Don't compute hash of entire manifest")
	SignJarCmd.Flags().BoolVar(&argInlineSignature, "inline-signature", false, "Include .SF inside the signature block")

	shared.RootCmd.AddCommand(SignJarManifestCmd)
	shared.AddDigestFlag(SignJarManifestCmd)
	addAuditFlags(SignJarManifestCmd)
	SignJarManifestCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignJarManifestCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input manifest file to sign")
	SignJarManifestCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file for signature (.RSA or .EC)")
	SignJarManifestCmd.Flags().StringVar(&argSignFileOutput, "out-sf", "", "Write .SF file")
	SignJarManifestCmd.Flags().BoolVar(&argSectionsOnly, "sections-only", false, "Don't compute hash of entire manifest")
	SignJarManifestCmd.Flags().BoolVar(&argInlineSignature, "inline-signature", false, "Include .SF inside the signature block")
}

func signJarCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if argFile == "-" || argOutput == "-" {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	inz, err := zip.OpenReader(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	manifest, err := signjar.DigestJar(&inz.Reader, hash)
	if err != nil {
		return shared.Fail(err)
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	sigfile, err := signjar.DigestManifest(manifest, hash, argSectionsOnly)
	if err != nil {
		return shared.Fail(err)
	}
	pkcs, audit, err := signAndTimestamp(sigfile, key, hash, "jar", !argInlineSignature)
	if err != nil {
		return shared.Fail(err)
	}

	if argOutput == "" {
		argOutput = argFile
	}
	w, err := atomicfile.WriteAny(argOutput)
	if err != nil {
		return shared.Fail(err)
	}
	defer w.Close()
	if err := signjar.UpdateJar(w, &inz.Reader, argKeyAlias, key.Public(), manifest, sigfile, pkcs); err != nil {
		return shared.Fail(err)
	}
	inz.Close()
	if err := w.Commit(); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return shared.Fail(audit.Commit())
}

func signJarManifestCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" || argOutput == "" {
		return errors.New("--key, --file and --output are required")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	var manifest []byte
	if argFile == "-" {
		manifest, err = ioutil.ReadAll(os.Stdin)
	} else {
		manifest, err = ioutil.ReadFile(argFile)
	}
	if err != nil {
		return shared.Fail(err)
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	sigfile, err := signjar.DigestManifest(manifest, hash, argSectionsOnly)
	if err != nil {
		return shared.Fail(err)
	}
	detach := !argInlineSignature && argSignFileOutput != ""
	pkcs, audit, err := signAndTimestamp(sigfile, key, hash, "jar-manifest", detach)
	if err != nil {
		return shared.Fail(err)
	}
	if argSignFileOutput != "" {
		if err := atomicfile.WriteFile(argSignFileOutput, sigfile); err != nil {
			return shared.Fail(err)
		}
	}

	if err := atomicfile.WriteFile(argOutput, pkcs); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return shared.Fail(audit.Commit())
}
