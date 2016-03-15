package healthsrv

<<<<<<< a4e52011cd181ce189cb2b6d24a3c3a03275015b
import (
	s3 "github.com/minio/minio-go"
)

// BucketLister is a *(github.com/minio/minio-go).Client compatible interface that provides just
// the ListBuckets cross-section of functionality. It can also be implemented for unit tests.
type BucketLister interface {
	// ListBuckets lists all the buckets in the object storage system
	CheckConnectionStatus() (bool, error)
}

type emptyBucketLister struct{}

func (e emptyBucketLister) ListBuckets() (bool, error) {
	return true, nil
}

type errBucketLister struct {
	err error
}

func (e errBucketLister) ListBuckets() (bool, error) {
	return true, e.err
}

// listBuckets calls bl.ListBuckets(...) and sends the results back on the various given channels.
// This func is intended to be run in a goroutine and communicates via the channels it's passed.
//
// On success, it passes the bucket output on succCh, and on failure, it passes the error on errCh.
// At most one of {succCh, errCh} will be sent on. If stopCh is closed, no pending or future sends
// will occur.
func listBuckets(bl BucketLister, succCh chan<- bool, errCh chan<- error, stopCh <-chan struct{}) {
	lbOut, err := bl.CheckConnectionStatus()
	if err != nil {
		select {
		case errCh <- err:
		case <-stopCh:
		}
		return
	}
	select {
	case succCh <- lbOut:
	case <-stopCh:
	}
}
