package age

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/age"
	"github.com/metacubex/age/armor"
)

const FileHeader = armor.Header

var globalSecretKeys []string

// parseIdentities parse age-secret-key to age.Identity
func parseIdentities(secretKey string) ([]age.Identity, error) {
	return age.ParseIdentities(strings.NewReader(secretKey))
}

// parseRecipients parse age-public-key to age.Recipient
func parseRecipients(publicKey string) ([]age.Recipient, error) {
	return age.ParseRecipients(strings.NewReader(publicKey))
}

// convertToRecipient convert age.Identity to age.Recipient
func convertToRecipient(identity age.Identity) (age.Recipient, error) {
	switch identity := identity.(type) {
	case *age.X25519Identity:
		return identity.Recipient(), nil
	case *age.HybridIdentity:
		return identity.Recipient(), nil
	default:
		return nil, fmt.Errorf("unexpected identity type: %T", identity)
	}
}

// ToPublicKeys convert age-secret-key to age-public-key
func ToPublicKeys(secretKeys ...string) (publicKeys []string, err error) {
	for _, secretKey := range secretKeys {
		identities, err := parseIdentities(secretKey)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			recipient, err := convertToRecipient(identity)
			if err != nil {
				return nil, err
			}
			publicKeys = append(publicKeys, fmt.Sprint(recipient))
		}
	}
	return
}

// SetGlobalSecretKeys set global secret keys, which will be used when decrypting
func SetGlobalSecretKeys(secretKeys ...string) {
	globalSecretKeys = append(globalSecretKeys[:0], secretKeys...)
}

// VeritySecretKeys check if the secret key is valid
func VeritySecretKeys(secretKeys ...string) error {
	for _, secretKey := range secretKeys {
		if _, err := parseIdentities(secretKey); err != nil {
			return err
		}
	}
	return nil
}

// VerityPublicKeys check if the public key is valid
func VerityPublicKeys(publicKeys ...string) error {
	for _, publicKey := range publicKeys {
		if _, err := parseRecipients(publicKey); err != nil {
			return err
		}
	}
	return nil
}

// DecryptBytes decrypt age armor format encrypted data
// if not the age armor format, return original data
func DecryptBytes(data []byte, secretKeys ...string) ([]byte, error) {
	if !strings.HasPrefix(string(data), FileHeader) { // not age armor format
		return data, nil
	}
	var identities []age.Identity
	for _, secretKey := range secretKeys {
		identity, err := parseIdentities(secretKey)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity...)
	}
	for _, secretKey := range globalSecretKeys {
		identity, err := parseIdentities(secretKey)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity...)
	}

	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// EncryptBytes encrypt data with age armor format
func EncryptBytes(data []byte, publicKeys ...string) ([]byte, error) {
	var recipients []age.Recipient
	for _, publicKey := range publicKeys {
		recipient, err := parseRecipients(publicKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient...)
	}
	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)
	w, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	err = armorWriter.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GenX25519KeyPair generate x25519 recipient type age-secret-key and age-public-key
func GenX25519KeyPair() (secretKey string, publicKey string, err error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return identity.String(), identity.Recipient().String(), nil
}

// GenHybridKeyPair generate mlkem768-x25519 hybrid post-quantum recipient type age-secret-key and age-public-key
func GenHybridKeyPair() (secretKey string, publicKey string, err error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", "", err
	}
	return identity.String(), identity.Recipient().String(), nil
}

// writePrivateFile writes decrypted data to path readable by the owner only.
// It writes a new 0600 file next to path and renames it into place, so an
// existing target with wider permissions (or a symlink) is replaced rather
// than written through.
func writePrivateFile(path string, data []byte) (err error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp") // created with mode 0600
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// secretKeyArg reads the secret key argument of the age subcommands: "@path"
// reads it from a file and "-" from the standard input, which keeps it out of
// the process arguments; anything else is the key itself.
func secretKeyArg(arg string) (string, error) {
	var data []byte
	var err error
	switch {
	case arg == "-":
		data, err = io.ReadAll(os.Stdin)
	case strings.HasPrefix(arg, "@"):
		data, err = os.ReadFile(arg[1:])
	default:
		return arg, nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func Main(args []string) {
	if len(args) < 1 {
		panic("Using: age keygen/keygen-pq/convert/decrypt/encrypt")
	}
	switch args[0] {
	case "keygen":
		secretKey, publicKey, err := GenX25519KeyPair()
		if err != nil {
			panic(err)
		}
		fmt.Printf("# created: %s\n", time.Now().Format(time.RFC3339))
		fmt.Printf("# public key: %s\n", publicKey)
		fmt.Printf("%s\n", secretKey)
	case "keygen-pq":
		secretKey, publicKey, err := GenHybridKeyPair()
		if err != nil {
			panic(err)
		}
		fmt.Printf("# created: %s\n", time.Now().Format(time.RFC3339))
		fmt.Printf("# public key: %s\n", publicKey)
		fmt.Printf("%s\n", secretKey)
	case "convert":
		if len(args) < 2 {
			panic("Using: age convert <secret_key|@file|->")
		}
		secretKey, err := secretKeyArg(args[1])
		if err != nil {
			panic(err)
		}
		publicKeys, err := ToPublicKeys(secretKey)
		if err != nil {
			panic(err)
		}
		if len(publicKeys) == 0 {
			panic("no public keys found in the input")
		}
		for _, publicKey := range publicKeys {
			fmt.Println(publicKey)
		}
	case "decrypt":
		if len(args) < 4 {
			panic("Using: age decrypt <secret_key|@file> <source_file> <target_file>")
		}
		secretKey, err := secretKeyArg(args[1])
		if err != nil {
			panic(err)
		}
		var data []byte
		if args[2] == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(args[2])
		}
		if err != nil {
			panic(err)
		}
		result, err := DecryptBytes(data, secretKey)
		if err != nil {
			panic(err)
		}
		if args[3] == "-" {
			_, err = os.Stdout.Write(result)
		} else {
			err = writePrivateFile(args[3], result)
		}
		if err != nil {
			panic(err)
		}
	case "encrypt":
		if len(args) < 4 {
			panic("Using: age encrypt <public_key> <source_file> <target_file>")
		}
		var data []byte
		var err error
		if args[2] == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(args[2])
		}
		if err != nil {
			panic(err)
		}
		result, err := EncryptBytes(data, args[1])
		if err != nil {
			panic(err)
		}
		if args[3] == "-" {
			_, err = os.Stdout.Write(result)
		} else {
			err = os.WriteFile(args[3], result, 0644)
		}
		if err != nil {
			panic(err)
		}
	}
}
