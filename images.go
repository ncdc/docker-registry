package registry

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker-registry/api/v2"
	"github.com/docker/docker-registry/digest"
	"github.com/docker/docker-registry/storage"
	"github.com/gorilla/handlers"
)

// imageManifestDispatcher takes the request context and builds the
// appropriate handler for handling image manifest requests.
func imageManifestDispatcher(ctx *Context, r *http.Request) http.Handler {
	imageManifestHandler := &imageManifestHandler{
		Context: ctx,
		Tag:     ctx.vars["tag"],
	}

	imageManifestHandler.log = imageManifestHandler.log.WithField("tag", imageManifestHandler.Tag)

	return handlers.MethodHandler{
		"GET":    http.HandlerFunc(imageManifestHandler.GetImageManifest),
		"PUT":    http.HandlerFunc(imageManifestHandler.PutImageManifest),
		"DELETE": http.HandlerFunc(imageManifestHandler.DeleteImageManifest),
	}
}

func imageManifestByDigestDispatcher(ctx *Context, r *http.Request) http.Handler {
	imageManifestHandler := &imageManifestHandler{
		Context: ctx,
		Tag:     ctx.vars["tag"],
		Digest:  ctx.vars["digest"],
	}

	imageManifestHandler.log = imageManifestHandler.log.WithField("tag", imageManifestHandler.Tag)

	return handlers.MethodHandler{
		"GET": http.HandlerFunc(imageManifestHandler.GetImageManifestByDigest),
	}
}

// imageManifestHandler handles http operations on image manifests.
type imageManifestHandler struct {
	*Context

	Tag    string
	Digest string
}

// GetImageManifest fetches the image manifest from the storage backend, if it exists.
func (imh *imageManifestHandler) GetImageManifest(w http.ResponseWriter, r *http.Request) {
	manifests := imh.services.Manifests()
	manifest, err := manifests.Get(imh.Name, imh.Tag)

	if err != nil {
		imh.Errors.Push(v2.ErrorCodeManifestUnknown, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(manifest.Raw)))
	w.Write(manifest.Raw)
}

// GetImageManifestByDigest fetches the image manifest from the storage backend, if it exists.
func (imh *imageManifestHandler) GetImageManifestByDigest(w http.ResponseWriter, r *http.Request) {
	log.Infoln("GET IMAGE MANIFEST BY DIGEST!")
	manifests := imh.services.Manifests()
	manifest, err := manifests.GetByDigest(imh.Name, imh.Tag, imh.Digest)

	if err != nil {
		imh.Errors.Push(v2.ErrorCodeManifestUnknown, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(manifest.Raw)))
	w.Write(manifest.Raw)
}

// PutImageManifest validates and stores and image in the registry.
func (imh *imageManifestHandler) PutImageManifest(w http.ResponseWriter, r *http.Request) {
	manifests := imh.services.Manifests()
	dec := json.NewDecoder(r.Body)

	var manifest storage.SignedManifest
	if err := dec.Decode(&manifest); err != nil {
		imh.Errors.Push(v2.ErrorCodeManifestInvalid, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//previousManifest, _ := manifests.Get(imh.Name, imh.Tag)

	if err := manifests.Put(imh.Name, imh.Tag, &manifest); err != nil {
		// TODO(stevvooe): These error handling switches really need to be
		// handled by an app global mapper.
		switch err := err.(type) {
		case storage.ErrManifestVerification:
			for _, verificationError := range err {
				switch verificationError := verificationError.(type) {
				case storage.ErrUnknownLayer:
					imh.Errors.Push(v2.ErrorCodeBlobUnknown, verificationError.FSLayer)
				case storage.ErrManifestUnverified:
					imh.Errors.Push(v2.ErrorCodeManifestUnverified)
				default:
					if verificationError == digest.ErrDigestInvalidFormat {
						// TODO(stevvooe): We need to really need to move all
						// errors to types. Its much more straightforward.
						imh.Errors.Push(v2.ErrorCodeDigestInvalid)
					} else {
						imh.Errors.PushErr(verificationError)
					}
				}
			}
		default:
			imh.Errors.PushErr(err)
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//event.Broadcast("manifestAdded", previousManifest, manifest)
}

// DeleteImageManifest removes the image with the given tag from the registry.
func (imh *imageManifestHandler) DeleteImageManifest(w http.ResponseWriter, r *http.Request) {
	manifests := imh.services.Manifests()
	if err := manifests.Delete(imh.Name, imh.Tag); err != nil {
		switch err := err.(type) {
		case storage.ErrUnknownManifest:
			imh.Errors.Push(v2.ErrorCodeManifestUnknown, err)
			w.WriteHeader(http.StatusNotFound)
		default:
			imh.Errors.Push(v2.ErrorCodeUnknown, err)
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
}
