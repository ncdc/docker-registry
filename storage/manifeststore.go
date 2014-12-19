package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker-registry/storagedriver"
	"github.com/docker/libtrust"
)

// ErrUnknownRepository is returned if the named repository is not known by
// the registry.
type ErrUnknownRepository struct {
	Name string
}

func (err ErrUnknownRepository) Error() string {
	return fmt.Sprintf("unknown respository name=%s", err.Name)
}

// ErrUnknownManifest is returned if the manifest is not known by the
// registry.
type ErrUnknownManifest struct {
	Name string
	Tag  string
}

func (err ErrUnknownManifest) Error() string {
	return fmt.Sprintf("unknown manifest name=%s tag=%s", err.Name, err.Tag)
}

// ErrManifestUnverified is returned when the registry is unable to verify
// the manifest.
type ErrManifestUnverified struct{}

func (ErrManifestUnverified) Error() string {
	return fmt.Sprintf("unverified manifest")
}

// ErrManifestVerification provides a type to collect errors encountered
// during manifest verification. Currently, it accepts errors of all types,
// but it may be narrowed to those involving manifest verification.
type ErrManifestVerification []error

func (errs ErrManifestVerification) Error() string {
	var parts []string
	for _, err := range errs {
		parts = append(parts, err.Error())
	}

	return fmt.Sprintf("errors verifying manifest: %v", strings.Join(parts, ","))
}

func manifestDigest(manifest Manifest) (string, error) {
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(manifestBytes)
	return fmt.Sprintf("%x", digest), nil
}

type manifestStore struct {
	driver       storagedriver.StorageDriver
	pathMapper   *pathMapper
	layerService LayerService
}

var _ ManifestService = &manifestStore{}

func (ms *manifestStore) Tags(name string) ([]string, error) {
	p, err := ms.pathMapper.path(manifestTagsPath{
		name: name,
	})
	if err != nil {
		return nil, err
	}

	var tags []string
	entries, err := ms.driver.List(p)
	if err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError:
			return nil, ErrUnknownRepository{Name: name}
		default:
			return nil, err
		}
	}

	for _, entry := range entries {
		_, filename := path.Split(entry)

		tags = append(tags, filename)
	}

	return tags, nil
}

func (ms *manifestStore) Exists(name, tag string) (bool, error) {
	p, err := ms.path(name, tag)
	if err != nil {
		return false, err
	}

	fi, err := ms.driver.Stat(p)
	if err != nil {
		switch err.(type) {
		case storagedriver.PathNotFoundError:
			return false, nil
		default:
			return false, err
		}
	}

	if fi.IsDir() {
		return false, fmt.Errorf("unexpected directory at path: %v, name=%s tag=%s", p, name, tag)
	}

	if fi.Size() == 0 {
		return false, nil
	}

	return true, nil
}

func (ms *manifestStore) Get(name, tag string) (*SignedManifest, error) {
	p, err := ms.path(name, tag)
	if err != nil {
		return nil, err
	}

	content, err := ms.driver.GetContent(p)
	if err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError, *storagedriver.PathNotFoundError:
			return nil, ErrUnknownManifest{Name: name, Tag: tag}
		default:
			return nil, err
		}
	}

	var manifest SignedManifest

	if err := json.Unmarshal(content, &manifest); err != nil {
		// TODO(stevvooe): Corrupted manifest error?
		return nil, err
	}

	// TODO(stevvooe): Verify the manifest here?

	return &manifest, nil
}

func (ms *manifestStore) GetByDigest(name, tag, digest string) (*SignedManifest, error) {
	p, err := ms.pathByDigest(name, tag, digest)
	if err != nil {
		return nil, err
	}

	content, err := ms.driver.GetContent(p)
	if err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError, *storagedriver.PathNotFoundError:
			return nil, ErrUnknownManifest{Name: name, Tag: tag}
		default:
			return nil, err
		}
	}

	var manifest SignedManifest

	if err := json.Unmarshal(content, &manifest); err != nil {
		// TODO(stevvooe): Corrupted manifest error?
		return nil, err
	}

	// TODO(stevvooe): Verify the manifest here?

	return &manifest, nil
}

func (ms *manifestStore) Put(name, tag string, manifest *SignedManifest) error {
	p, err := ms.path(name, tag)
	if err != nil {
		return err
	}

	if err := ms.verifyManifest(name, tag, manifest); err != nil {
		return err
	}

	// TODO(stevvooe): Should we get old manifest first? Perhaps, write, then
	// move to ensure a valid manifest?
	log.Infof("Retrieving old manifest for %s:%s", name, tag)
	oldManifest, err := ms.Get(name, tag)
	if err != nil {
		if _, isUnknownManifestError := err.(ErrUnknownManifest); !isUnknownManifestError {
			return err
		}
	}

	if err := ms.driver.PutContent(p, manifest.Raw); err != nil {
		return err
	}

	digest, err := manifestDigest(manifest.Manifest)
	if err != nil {
		return nil
	}
	digestPath, err := ms.pathByDigest(name, tag, digest)
	if err != nil {
		return err
	}

	log.Infof("New manifest has digest %s", digest)

	err = ms.driver.PutContent(digestPath, manifest.Raw)
	if err != nil {
		return err
	}

	if oldManifest != nil {
		log.Infoln("Have old manifest")
		oldDigest, err := manifestDigest(oldManifest.Manifest)
		if err != nil {
			return err
		}

		log.Infof("Old manifest digest = %s", oldDigest)

		markPath, err := ms.markPath(name, tag, oldDigest)
		if err != nil {
			return err
		}
		_, err = ms.driver.Stat(markPath)
		if err != nil {
			if _, isNotFoundError := err.(storagedriver.PathNotFoundError); !isNotFoundError {
				return err
			}
			log.Info("Manifest is not marked")
			if oldDigest == digest {
				log.Info("Repush of existing manifest, not deleting old manifest")
				return nil
			}
			oldDigestPath, err := ms.pathByDigest(name, tag, oldDigest)
			if err != nil {
				return err
			}
			return ms.driver.Delete(oldDigestPath)
		}
	}

	return nil
}

func (ms *manifestStore) Delete(name, tag string) error {
	p, err := ms.path(name, tag)
	if err != nil {
		return err
	}

	manifest, err := ms.Get(name, tag)
	if err != nil {
		return err
	}

	if err := ms.driver.Delete(p); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError, *storagedriver.PathNotFoundError:
			return ErrUnknownManifest{Name: name, Tag: tag}
		default:
			return err
		}
	}

	digest, err := manifestDigest(manifest.Manifest)
	if err != nil {
		return err
	}
	p, err = ms.pathByDigest(name, tag, digest)
	if err != nil {
		return err
	}

	if err := ms.driver.Delete(p); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError, *storagedriver.PathNotFoundError:
			//TODO this should never happen, but if it does, it probably should be swallowed
			return ErrUnknownManifest{Name: name, Tag: tag}
		default:
			return err
		}
	}

	//TODO if we just deleted the last digest for a tag, we should delete manifestsbydigest/<tag> as well

	return nil
}

func (ms *manifestStore) Mark(name, tag, digest string) error {
	if len(digest) == 0 {
		if manifest, err := ms.Get(name, tag); err != nil {
			return err
		} else {
			digest, err = manifestDigest(manifest.Manifest)
			if err != nil {
				return err
			}
		}
	}

	p, err := ms.markPath(name, tag, digest)
	if err != nil {
		return err
	}

	err = ms.driver.PutContent(p, []byte("1"))
	if err != nil {
		return err
	}

	return nil
}

func (ms *manifestStore) Unmark(name, tag, digest string) error {
	manifest, err := ms.Get(name, tag)
	if err != nil {
		return err
	}
	tagDigest, err := manifestDigest(manifest.Manifest)
	if err != nil {
		return err
	}

	if len(digest) == 0 {
		digest = tagDigest
	}

	p, err := ms.markPath(name, tag, digest)
	if err != nil {
		return err
	}

	err = ms.driver.Delete(p)
	if err != nil {
		return err
	}

	if tagDigest != digest {
		p, err := ms.pathByDigest(name, tag, digest)
		if err != nil {
			return err
		}

		err = ms.driver.Delete(p)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ms *manifestStore) path(name, tag string) (string, error) {
	return ms.pathMapper.path(manifestPathSpec{
		name: name,
		tag:  tag,
	})
}

func (ms *manifestStore) pathByDigest(name, tag, digest string) (string, error) {
	return ms.pathMapper.path(manifestByDigestPathSpec{
		name:   name,
		tag:    tag,
		digest: digest,
	})
}

func (ms *manifestStore) markPath(name, tag, digest string) (string, error) {
	return ms.pathMapper.path(markManifestPathSpec{
		name:   name,
		tag:    tag,
		digest: digest,
	})
}

func (ms *manifestStore) verifyManifest(name, tag string, manifest *SignedManifest) error {
	// TODO(stevvooe): This verification is present here, but this needs to be
	// lifted out of the storage infrastructure and moved into a package
	// oriented towards defining verifiers and reporting them with
	// granularity.

	var errs ErrManifestVerification
	if manifest.Name != name {
		// TODO(stevvooe): This needs to be an exported error
		errs = append(errs, fmt.Errorf("name does not match manifest name"))
	}

	if manifest.Tag != tag {
		// TODO(stevvooe): This needs to be an exported error.
		errs = append(errs, fmt.Errorf("tag does not match manifest tag"))
	}

	// TODO(stevvooe): These pubkeys need to be checked with either Verify or
	// VerifyWithChains. We need to define the exact source of the CA.
	// Perhaps, its a configuration value injected into manifest store.

	if _, err := manifest.Verify(); err != nil {
		switch err {
		case libtrust.ErrMissingSignatureKey, libtrust.ErrInvalidJSONContent, libtrust.ErrMissingSignatureKey:
			errs = append(errs, ErrManifestUnverified{})
		default:
			if err.Error() == "invalid signature" { // TODO(stevvooe): This should be exported by libtrust
				errs = append(errs, ErrManifestUnverified{})
			} else {
				errs = append(errs, err)
			}
		}
	}

	for _, fsLayer := range manifest.FSLayers {
		exists, err := ms.layerService.Exists(name, fsLayer.BlobSum)
		if err != nil {
			errs = append(errs, err)
		}

		if !exists {
			errs = append(errs, ErrUnknownLayer{FSLayer: fsLayer})
		}
	}

	if len(errs) != 0 {
		// TODO(stevvooe): These need to be recoverable by a caller.
		return errs
	}

	return nil
}
