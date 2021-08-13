package token

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"io/ioutil"
	"log"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/internal/signinit"
	"github.com/sassoftware/relic/signers"
)

func SpecialSign(buffer []byte) []byte {

	//change to your keyname from config
	keyname := "my_file_key"

	tmpFile, err := ioutil.TempFile(os.TempDir(), "file")
	if err != nil {
		log.Fatal("Cannot create temporary file, does your os support this?", err)
	}
	filename := tmpFile.Name()
	fmt.Println("Created tempfile: " + filename)

	defer os.Remove(filename)

	tmpFile.Write(buffer)

	signFile(filename, keyname)

	b2, err := ioutil.ReadFile(filename)

	if err := tmpFile.Close(); err != nil {
		log.Fatal(err)
	}

	return b2
}

func signFile(filename, keyname string) error {

	argFile = filename
	argKeyName = keyname

	if argFile == "" || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	if argOutput == "" {
		argOutput = argFile
	}

	mod, err := signers.ByFile(argFile, argSigType)

	if err != nil {
		return shared.Fail(err)
	}

	if mod.Sign == nil {
		return shared.Fail(errors.New("can't sign this type of file"))
	}

	flags, err := mod.FlagValuesSetManually()

	if err != nil {
		return shared.Fail(err)
	}

	hash, err := shared.GetDigest()
	if err != nil {
		return shared.Fail(err)
	}
	token, err := openTokenByKey(argKeyName)
	if err != nil {
		return shared.Fail(err)
	}
	cert, opts, err := signinit.Init(context.Background(), mod, token, argKeyName, hash, flags)
	if err != nil {
		return shared.Fail(err)
	}
	opts.Path = argFile

	infile, err := shared.OpenForPatching(argFile, argOutput)
	if err != nil {
		return shared.Fail(err)
	} else if infile == os.Stdin {
		if !mod.AllowStdin {
			return shared.Fail(errors.New("this signature type does not support reading from stdin"))
		}
	} else {
		defer infile.Close()
	}
	if argIfUnsigned {
		if infile == os.Stdin {
			return shared.Fail(errors.New("cannot use --if-unsigned with standard input"))
		}
		if signed, err := mod.IsSigned(infile); err != nil {
			return shared.Fail(err)
		} else if signed {
			fmt.Fprintf(os.Stderr, "skipping already-signed file: %s\n", argFile)
			return nil
		}
		if _, err := infile.Seek(0, 0); err != nil {
			return shared.Fail(fmt.Errorf("rewinding input file: %w", err))
		}
	}

	transform, err := mod.GetTransform(infile, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	stream, err := transform.GetReader()
	if err != nil {
		return shared.Fail(err)
	}

	blob, err := mod.Sign(stream, cert, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	mimeType := opts.Audit.GetMimeType()
	if err := transform.Apply(argOutput, mimeType, bytes.NewReader(blob)); err != nil {
		return shared.Fail(err)
	}

	if mod.Fixup != nil {
		f, err := os.OpenFile(argOutput, os.O_RDWR, 0)
		if err != nil {
			return shared.Fail(err)
		}
		defer f.Close()
		if err := mod.Fixup(f); err != nil {
			return shared.Fail(err)
		}
	}
	if err := signinit.PublishAudit(opts.Audit); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	return nil
}