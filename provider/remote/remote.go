package remote

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var infoRegexp = regexp.MustCompile(`(upload|download|total|expire)[\s\t]*=[\s\t]*(-?\d*);?`)

var _ adapter.Provider = (*ProviderRemote)(nil)

type ProviderRemote struct {
	provider.Adapter
	ctx              context.Context
	cancel           context.CancelFunc
	logger           log.ContextLogger
	outbound         adapter.OutboundManager
	provider         adapter.ProviderManager
	cacheFile        adapter.CacheFile
	httpClient       *http.Client
	infoMu           sync.RWMutex
	lastEtag         string
	lastOutOpts      []option.Outbound
	lastEPOpts       []option.Endpoint
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	ticker           *time.Ticker
	updating         atomic.Bool

	httpClientOptions *option.HTTPClientOptions
	downloadDetour    string
	url               string
	urlHash           [32]byte
	userAgent         string
	updateInterval    time.Duration
	exclude           *regexp.Regexp
	include           *regexp.Regexp

	overrideDialer *option.OverrideDialerOptions
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Minute {
		updateInterval = time.Minute
	}
	if options.UserAgent != "" && options.HTTPClient != nil && !options.HTTPClient.IsEmpty() {
		return nil, E.New("user_agent conflicts with http_client: configure User-Agent via http_client.headers instead")
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	endpointMgr := service.FromContext[adapter.EndpointManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	return &ProviderRemote{
		Adapter:  provider.NewAdapter(ctx, router, outbound, endpointMgr, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),

		httpClientOptions: options.HTTPClient,
		url:               options.URL,
		urlHash:           sha256.Sum256([]byte(options.URL)),
		userAgent:         userAgent,
		updateInterval:    updateInterval,
		exclude:           (*regexp.Regexp)(options.Exclude),
		include:           (*regexp.Regexp)(options.Include),

		overrideDialer: options.OverrideDialer,

		//nolint:staticcheck
		downloadDetour: options.DownloadDetour,
	}, nil
}

func (s *ProviderRemote) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if s.cacheFile != nil {
		if saveSub := s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			content, _ := parser.DecodeBase64URLSafe(string(saveSub.Content))
			firstLine, others := getFirstLine(content)
			if info, ok := parseInfo(firstLine); ok {
				s.subscriptionInfo = info
				content, _ = parser.DecodeBase64URLSafe(others)
			}
			if err := s.updateProviderFromContent(content); err != nil {
				return E.Cause(err, "restore cached outbound provider")
			}
			s.UpdateGroups()
			s.lastUpdated, s.lastEtag = saveSub.LastUpdated, saveSub.LastEtag
		}
	}
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create provider http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.lastUpdated.IsZero() {
		ctx = interrupt.ContextWithIsProviderConnection(ctx)
		err = s.fetch(ctx, true)
		if err != nil {
			return E.Cause(err, "initial outbound provider: ", s.Tag())
		}
	}
	s.ticker = time.NewTicker(s.updateInterval)
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	if err := s.fetch(ctx, false); err != nil {
		return err
	}
	if s.ticker != nil {
		s.ticker.Reset(s.updateInterval)
	}
	return nil
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.lastUpdated
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.subscriptionInfo
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.httpClientOptions != nil && !s.httpClientOptions.IsEmpty() {
		if s.downloadDetour != "" {
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.httpClientOptions)
	}
	if s.downloadDetour != "" {
		deprecated.Report(s.ctx, deprecated.OptionLegacyProviderDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.downloadDetour,
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *ProviderRemote) updateOnce() {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	if err := s.fetch(ctx, false); err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
}

func (s *ProviderRemote) fetch(ctx context.Context, isStart bool) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer s.updating.Store(false)
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	resp, err := s.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.infoMu.Lock()
		if hasInfo {
			s.subscriptionInfo = info
		}
		s.lastUpdated = time.Now()
		s.infoMu.Unlock()
		if s.cacheFile != nil {
			saveSub := s.cacheFile.LoadSubscription(s.Tag())
			if saveSub != nil {
				if hasInfo {
					content := string(saveSub.Content)
					firstLine, others := getFirstLine(content)
					if _, ok := parseInfo(firstLine); ok {
						content = others
					}
					saveSub.Content = []byte(infoStr + "\n" + content)
				}
				saveSub.LastUpdated = s.lastUpdated
				err := s.cacheFile.SaveSubscription(s.Tag(), saveSub)
				if err != nil {
					s.logger.Error("save outbound provider cache file: ", err)
				}
			}
		}
		s.logger.Info("update outbound provider ", s.Tag(), ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", resp.Status)
	}
	contentRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	eTagHeader := resp.Header.Get("Etag")
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	if !hasInfo {
		firstLine, others := getFirstLine(content)
		if info, hasInfo = parseInfo(firstLine); hasInfo {
			infoStr = firstLine
			content, _ = parser.DecodeBase64URLSafe(others)
		}
	}
	if err := s.updateProviderFromContent(content); err != nil {
		return err
	}
	if eTagHeader != "" {
		s.infoMu.Lock()
		s.lastEtag = eTagHeader
		s.infoMu.Unlock()
	}
	s.UpdateGroups()
	s.infoMu.Lock()
	s.subscriptionInfo = info
	s.lastUpdated = time.Now()
	s.infoMu.Unlock()
	if s.cacheFile != nil {
		cacheContent := content
		if hasInfo {
			cacheContent = infoStr + "\n" + cacheContent
		}
		err = s.cacheFile.SaveSubscription(s.Tag(), &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     []byte(cacheContent),
			LastEtag:    s.lastEtag,
		})
		if err != nil {
			s.logger.Error("save outbound provider cache file: ", err)
		}
	}
	s.logger.Info("updated outbound provider ", s.Tag())
	return nil
}

func (s *ProviderRemote) loopUpdate() {
	s.ticker.Stop()
	select {
	case <-s.ticker.C:
	default:
	}
	if remaining := time.Until(func() time.Time {
		s.infoMu.RLock()
		defer s.infoMu.RUnlock()
		return s.lastUpdated
	}().Add(s.updateInterval)); remaining > 0 {
		s.ticker.Reset(remaining)
	} else {
		s.updateOnce()
		s.ticker.Reset(s.updateInterval)
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
			runtime.GC()
			s.ticker.Reset(s.updateInterval)
		}
	}
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	outboundOpts, endpointOpts, err := parser.ParseSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	outboundOpts, endpointOpts = s.filterOptions(outboundOpts, endpointOpts)
	outboundOpts, endpointOpts = parser.ApplyOverrideDialer(outboundOpts, endpointOpts, s.overrideDialer, s.Tag())
	s.applyOptions(outboundOpts, endpointOpts)
	return nil
}

func (s *ProviderRemote) filterOptions(outboundOpts []option.Outbound, endpointOpts []option.Endpoint) ([]option.Outbound, []option.Endpoint) {
	matchTag := func(tag string) bool {
		return (s.exclude == nil || !s.exclude.MatchString(tag)) && (s.include == nil || s.include.MatchString(tag))
	}
	outboundOpts = common.Filter(outboundOpts, func(it option.Outbound) bool { return matchTag(it.Tag) })
	endpointOpts = common.Filter(endpointOpts, func(it option.Endpoint) bool { return matchTag(it.Tag) })
	return outboundOpts, endpointOpts
}

func (s *ProviderRemote) applyOptions(outboundOpts []option.Outbound, endpointOpts []option.Endpoint) {
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	s.UpdateEndpoints(s.lastEPOpts, endpointOpts)
	s.lastEPOpts = endpointOpts
	s.TriggerHealthCheck()
}

func getFirstLine(content string) (string, string) {
	first, rest, _ := strings.Cut(content, "\n")
	return first, rest
}

func parseInfo(infoStr string) (adapter.SubscriptionInfo, bool) {
	info := adapter.SubscriptionInfo{}
	if infoStr == "" {
		return info, false
	}
	matches := infoRegexp.FindAllStringSubmatch(infoStr, 4)
	if len(matches) == 0 {
		return info, false
	}
	for _, match := range matches {
		key, value := match[1], match[2]
		switch key {
		case "upload":
			info.Upload = parser.StringToType[int64](value)
		case "download":
			info.Download = parser.StringToType[int64](value)
		case "total":
			info.Total = parser.StringToType[int64](value)
		case "expire":
			info.Expire = parser.StringToType[int64](value)
		default:
			return info, false
		}
	}
	return info, true
}
