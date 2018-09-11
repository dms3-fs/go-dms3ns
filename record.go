package dms3ns

import (
	"bytes"
	"errors"

	pb "github.com/dms3-fs/go-dms3ns/pb"

	proto "github.com/gogo/protobuf/proto"
	logging "github.com/dms3-fs/go-log"
	ic "github.com/dms3-p2p/go-p2p-crypto"
	peer "github.com/dms3-p2p/go-p2p-peer"
	pstore "github.com/dms3-p2p/go-p2p-peerstore"
	record "github.com/dms3-p2p/go-p2p-record"
)

var log = logging.Logger("dms3ns")

var _ record.Validator = Validator{}

// RecordKey returns the dms3-p2p record key for a given peer ID.
func RecordKey(pid peer.ID) string {
	return "/dms3ns/" + string(pid)
}

// Validator is an DMS3NS record validator that satisfies the dms3-p2p record
// validator interface.
type Validator struct {
	// KeyBook, if non-nil, will be used to lookup keys for validating DMS3NS
	// records.
	KeyBook pstore.KeyBook
}

// Validate validates an DMS3NS record.
func (v Validator) Validate(key string, value []byte) error {
	ns, pidString, err := record.SplitKey(key)
	if err != nil || ns != "dms3ns" {
		return ErrInvalidPath
	}

	// Parse the value into an Dms3NsEntry
	entry := new(pb.Dms3NsEntry)
	err = proto.Unmarshal(value, entry)
	if err != nil {
		return ErrBadRecord
	}

	// Get the public key defined by the dms3ns path
	pid, err := peer.IDFromString(pidString)
	if err != nil {
		log.Debugf("failed to parse dms3ns record key %s into peer ID", pidString)
		return ErrKeyFormat
	}

	pubk, err := v.getPublicKey(pid, entry)
	if err != nil {
		return err
	}

	return Validate(pubk, entry)
}

func (v Validator) getPublicKey(pid peer.ID, entry *pb.Dms3NsEntry) (ic.PubKey, error) {
	pk, err := ExtractPublicKey(pid, entry)
	if err != nil {
		return nil, err
	}
	if pk != nil {
		return pk, nil
	}

	if v.KeyBook == nil {
		log.Debugf("public key with hash %s not found in DMS3NS record and no peer store provided", pid)
		return nil, ErrPublicKeyNotFound
	}

	pubk := v.KeyBook.PubKey(pid)
	if pubk == nil {
		log.Debugf("public key with hash %s not found in peer store", pid)
		return nil, ErrPublicKeyNotFound
	}
	return pubk, nil
}

// Select selects the best record by checking which has the highest sequence
// number and latest EOL.
//
// This function returns an error if any of the records fail to parse. Validate
// your records first!
func (v Validator) Select(k string, vals [][]byte) (int, error) {
	var recs []*pb.Dms3NsEntry
	for _, v := range vals {
		e := new(pb.Dms3NsEntry)
		if err := proto.Unmarshal(v, e); err != nil {
			return -1, err
		}
		recs = append(recs, e)
	}

	return selectRecord(recs, vals)
}

func selectRecord(recs []*pb.Dms3NsEntry, vals [][]byte) (int, error) {
	switch len(recs) {
	case 0:
		return -1, errors.New("no usable records in given set")
	case 1:
		return 0, nil
	}

	var i int
	for j := 1; j < len(recs); j++ {
		cmp, err := Compare(recs[i], recs[j])
		if err != nil {
			return -1, err
		}
		if cmp == 0 {
			cmp = bytes.Compare(vals[i], vals[j])
		}
		if cmp < 0 {
			i = j
		}
	}

	return i, nil
}
