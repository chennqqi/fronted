package fronted

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/refraction-networking/utls"
)

var (
	DefaultContext = NewFrontingContext("default")
)

// Configure sets the masquerades to use, the trusted root CAs, and the
// cache file for caching masquerades to set up direct domain fronting
// in the default context.
//
// defaultProviderID is used when a masquerade without a provider is
// encountered (eg in a cache file)
func Configure(pool *x509.CertPool, providers map[string]*Provider, defaultProviderID string, cacheFile string) {
	if err := DefaultContext.Configure(pool, providers, defaultProviderID, cacheFile); err != nil {
		log.Errorf("Error configuring fronting %s context: %s!!", DefaultContext.name, err)
	}
}

// NewDirect creates a new http.RoundTripper that does direct domain fronting
// using the default context. If it can't obtain a working masquerade within
// the given timeout, it will return nil/false.
func NewDirect(timeout time.Duration) (http.RoundTripper, bool) {
	return DefaultContext.NewDirect(timeout)
}

// CloseCache closes any existing cache file in the default context
func CloseCache() {
	DefaultContext.CloseCache()
}

func NewFrontingContext(name string) *FrontingContext {
	fc := &FrontingContext{
		name:  name,
		ready: make(chan struct{}),
	}
	fc._instance.Store(newDirect(nil, 0, "", tls.ClientHelloID{}, fc.signalReady))
	return fc
}

type FrontingContext struct {
	name      string
	_instance atomic.Value
	ready     chan struct{}
	readyOnce sync.Once
}

// Configure sets the masquerades to use, the trusted root CAs, and the
// cache file for caching masquerades to set up direct domain fronting.
// defaultProviderID is used when a masquerade without a provider is
// encountered (eg in a cache file)
func (fctx *FrontingContext) Configure(pool *x509.CertPool, providers map[string]*Provider, defaultProviderID string, cacheFile string) error {
	return fctx.ConfigureWithHello(pool, providers, defaultProviderID, cacheFile, tls.ClientHelloID{})
}

func (fctx *FrontingContext) ConfigureWithHello(pool *x509.CertPool, providers map[string]*Provider, defaultProviderID string, cacheFile string, clientHelloID tls.ClientHelloID) error {
	log.Tracef("Configuring fronted %s context", fctx.name)
	if providers == nil || len(providers) == 0 {
		return fmt.Errorf("No fronted providers for %s context.", fctx.name)
	}
	fctx.CloseCache()

	size := 0
	for _, p := range providers {
		size += len(p.Masquerades)
	}

	if size == 0 {
		return fmt.Errorf("No masquerades for %s context.", fctx.name)
	}

	d := newDirect(pool, size, defaultProviderID, clientHelloID, fctx.signalReady)
	for k, p := range providers {
		d.providers[k] = NewProvider(p.HostAliases, p.TestURL, p.Masquerades, p.Validator, p.PassthroughPatterns)
	}

	numberToVet := numberToVetInitially
	if cacheFile != "" {
		numberToVet -= d.initCaching(cacheFile)
	}

	d.loadCandidates(d.providers)
	if numberToVet > 0 {
		d.vet(numberToVet)
	} else {
		log.Debugf("Not vetting any masquerades for %s context because we have enough cached ones", fctx.name)
		fctx.signalReady()
	}
	fctx._instance.Store(d)
	return nil
}

// NewDirect creates a new http.RoundTripper that does direct domain fronting.
// If it can't obtain a working masquerade within the given timeout, it will
// return nil/false.
func (fctx *FrontingContext) NewDirect(timeout time.Duration) (http.RoundTripper, bool) {
	select {
	case <-fctx.ready:
		return fctx.instance(), true
	case <-time.After(timeout):
		log.Errorf("No DirectHttpClient available within %v", timeout)
		return nil, false
	}
}

// Ready returns a channel which always signal as long as there's at least one
// masquerade available.
func (fctx *FrontingContext) Ready() <-chan struct{} {
	return fctx.ready
}

// CloseCache closes any existing cache file in the default contexxt.
func (fctx *FrontingContext) CloseCache() {
	log.Debugf("Closing cache from existing instance in %s context", fctx.name)
	fctx.instance().closeCache()
}

func (fctx *FrontingContext) signalReady() {
	fctx.readyOnce.Do(func() {
		close(fctx.ready)
	})
}

func (fctx *FrontingContext) instance() *direct {
	return fctx._instance.Load().(*direct)
}
