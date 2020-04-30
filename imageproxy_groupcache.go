package imageproxy

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Hapara/golibs/logging"
	"github.com/golang/groupcache"
)

type ImageFetcher interface {
	GetImageByURL(url string) (*CacheResponse, error)
}

type CacheResponse struct {
	Status     string
	StatusCode int
	Body       []byte
	Header     http.Header
}

type ImageProxyGroupcache struct {
	Group       groupcache.Getter
	CacheWindow time.Duration
}

const name = "urls"

// CacheSize = 100MB
// CacheWindow = 1 Hour
var (
	ModelGroupCacheSizeDefault   = int64(1024 * 1024 * 100)
	ModelGroupCacheWindowDefault = 1 * time.Hour
)

// NewImageProxyGroupcache initializes the image proxy group cache
func NewImageProxyGroupcache(cacheSize int64, cacheWindow time.Duration) *ImageProxyGroupcache {
	service := &ImageProxyGroupcache{
		CacheWindow: cacheWindow,
	}
	cacheGroup := groupcache.GetGroup(name)
	if cacheGroup == nil {

		cacheGroup = groupcache.NewGroup(name, cacheSize, groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {

			p := strings.SplitN(key, "~", 2)
			if len(p) < 2 {
				return fmt.Errorf("Invalid key")
			}
			urlString := p[1]
			logging.L().Debugf("caching image with url %s", urlString)

			client := new(http.Client)
			resp, err := client.Get(urlString)

			if err != nil {
				return err
			}

			defer resp.Body.Close()
			body := new(bytes.Buffer)
			io.Copy(body, resp.Body)

			cResponse := &CacheResponse{Status: resp.Status, StatusCode: resp.StatusCode, Header: resp.Header, Body: body.Bytes()}
			w := new(bytes.Buffer)
			enc := gob.NewEncoder(w)
			err = enc.Encode(cResponse)

			if err != nil {
				return err
			}

			return dest.SetBytes(w.Bytes())
		}))
	}
	service.Group = cacheGroup
	return service

}

// GetImageByURL fetches the image either from cache or from the source specified
func (service *ImageProxyGroupcache) GetImageByURL(url string) (*CacheResponse, error) {
	b := []byte{}
	t := time.Now().UTC().Add(service.CacheWindow / 2).Round(service.CacheWindow).Format(time.RFC3339)

	key := fmt.Sprintf("%s~%s", t, url)
	err := service.Group.Get(context.TODO(), key, groupcache.AllocatingByteSliceSink(&b))
	if err != nil {
		return nil, err
	}

	r := bytes.NewBuffer(b)
	dec := gob.NewDecoder(r)

	cResponse := &CacheResponse{}
	err = dec.Decode(&cResponse)
	if err != nil {
		return nil, err
	}

	return cResponse, err
}
