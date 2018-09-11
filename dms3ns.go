package dms3ns

import (
	"bytes"
	"fmt"
	"time"

	pb "github.com/dms3-fs/go-dms3ns/pb"

	u "github.com/dms3-fs/go-fs-util"
	ic "github.com/dms3-p2p/go-p2p-crypto"
	peer "github.com/dms3-p2p/go-p2p-peer"
)

// Create creates a new DMS3NS entry and signs it with the given private key.
//
// This function does not embed the public key. If you want to do that, use
// `EmbedPublicKey`.
func Create(sk ic.PrivKey, val []byte, seq uint64, eol time.Time) (*pb.Dms3NsEntry, error) {
	entry := new(pb.Dms3NsEntry)

	entry.Value = val
	typ := pb.Dms3NsEntry_EOL
	entry.ValidityType = &typ
	entry.Sequence = &seq
	entry.Validity = []byte(u.FormatRFC3339(eol))

	sig, err := sk.Sign(dms3nsEntryDataForSig(entry))
	if err != nil {
		return nil, err
	}
	entry.Signature = sig

	return entry, nil
}

// Validates validates the given DMS3NS entry against the given public key.
func Validate(pk ic.PubKey, entry *pb.Dms3NsEntry) error {
	// Check the dms3ns record signature with the public key
	if ok, err := pk.Verify(dms3nsEntryDataForSig(entry), entry.GetSignature()); err != nil || !ok {
		return ErrSignature
	}

	eol, err := GetEOL(entry)
	if err != nil {
		return err
	}
	if time.Now().After(eol) {
		return ErrExpiredRecord
	}
	return nil
}

// GetEOL returns the EOL of this DMS3NS entry
//
// This function returns ErrUnrecognizedValidity if the validity type of the
// record isn't EOL. Otherwise, it returns an error if it can't parse the EOL.
func GetEOL(entry *pb.Dms3NsEntry) (time.Time, error) {
	if entry.GetValidityType() != pb.Dms3NsEntry_EOL {
		return time.Time{}, ErrUnrecognizedValidity
	}
	return u.ParseRFC3339(string(entry.GetValidity()))
}

// EmbedPublicKey embeds the given public key in the given dms3ns entry. While not
// strictly required, some nodes (e.g., DHT servers) may reject DMS3NS entries
// that don't embed their public keys as they may not be able to validate them
// efficiently.
func EmbedPublicKey(pk ic.PubKey, entry *pb.Dms3NsEntry) error {
	// Try extracting the public key from the ID. If we can, *don't* embed
	// it.
	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return err
	}
	extracted, err := id.ExtractPublicKey()
	if err != nil {
		return err
	}
	if extracted != nil {
		return nil
	}

	// We failed to extract the public key from the peer ID, embed it in the
	// record.
	pkBytes, err := pk.Bytes()
	if err != nil {
		return err
	}
	entry.PubKey = pkBytes
	return nil
}

// ExtractPublicKey extracts a public key matching `pid` from the DMS3NS record,
// if possible.
//
// This function returns (nil, nil) when no public key can be extracted and
// nothing is malformed.
func ExtractPublicKey(pid peer.ID, entry *pb.Dms3NsEntry) (ic.PubKey, error) {
	if entry.PubKey != nil {
		pk, err := ic.UnmarshalPublicKey(entry.PubKey)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling pubkey in record: %s", err)
		}

		expPid, err := peer.IDFromPublicKey(pk)
		if err != nil {
			return nil, fmt.Errorf("could not regenerate peerID from pubkey: %s", err)
		}

		if pid != expPid {
			return nil, ErrPublicKeyMismatch
		}
		return pk, nil
	}

	return pid.ExtractPublicKey()
}

// Compare compares two DMS3NS entries. It returns:
//
// * -1 if a is older than b
// * 0 if a and b cannot be ordered (this doesn't mean that they are equal)
// * +1 if a is newer than b
//
// It returns an error when either a or b are malformed.
//
// NOTE: It *does not* validate the records, the caller is responsible for calling
// `Validate` first.
//
// NOTE: If a and b cannot be ordered by this function, you can determine their
// order by comparing their serialized byte representations (using
// `bytes.Compare`). You must do this if you are implementing a dms3-p2p record
// validator (or you can just use the one provided for you by this package).
func Compare(a, b *pb.Dms3NsEntry) (int, error) {
	as := a.GetSequence()
	bs := b.GetSequence()

	if as > bs {
		return 1, nil
	} else if as < bs {
		return -1, nil
	}

	at, err := u.ParseRFC3339(string(a.GetValidity()))
	if err != nil {
		return 0, err
	}

	bt, err := u.ParseRFC3339(string(b.GetValidity()))
	if err != nil {
		return 0, err
	}

	if at.After(bt) {
		return 1, nil
	} else if bt.After(at) {
		return -1, nil
	}

	return 0, nil
}

func dms3nsEntryDataForSig(e *pb.Dms3NsEntry) []byte {
	return bytes.Join([][]byte{
		e.Value,
		e.Validity,
		[]byte(fmt.Sprint(e.GetValidityType())),
	},
		[]byte{})
}
