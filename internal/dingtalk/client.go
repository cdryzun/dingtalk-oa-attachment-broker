package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	contact "github.com/alibabacloud-go/dingtalk/contact_1_0"
	oauth "github.com/alibabacloud-go/dingtalk/oauth2_1_0"
	workflow "github.com/alibabacloud-go/dingtalk/workflow_1_0"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	brokerauth "github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	appTokenRefreshBefore = 5 * time.Minute
	maxOAPIResponseBytes  = 1 << 20
)

type oauthAPI interface {
	GetAccessToken(*oauth.GetAccessTokenRequest) (*oauth.GetAccessTokenResponse, error)
	GetUserToken(*oauth.GetUserTokenRequest) (*oauth.GetUserTokenResponse, error)
}

type contactAPI interface {
	GetUserWithOptions(
		*string,
		*contact.GetUserHeaders,
		*util.RuntimeOptions,
	) (*contact.GetUserResponse, error)
}

type workflowAPI interface {
	ListProcessInstanceIdsWithOptions(
		*workflow.ListProcessInstanceIdsRequest,
		*workflow.ListProcessInstanceIdsHeaders,
		*util.RuntimeOptions,
	) (*workflow.ListProcessInstanceIdsResponse, error)
	ListUserVisibleBpmsProcessesWithOptions(
		*workflow.ListUserVisibleBpmsProcessesRequest,
		*workflow.ListUserVisibleBpmsProcessesHeaders,
		*util.RuntimeOptions,
	) (*workflow.ListUserVisibleBpmsProcessesResponse, error)
	GetProcessInstanceWithOptions(
		*workflow.GetProcessInstanceRequest,
		*workflow.GetProcessInstanceHeaders,
		*util.RuntimeOptions,
	) (*workflow.GetProcessInstanceResponse, error)
	GrantProcessInstanceForDownloadFileWithOptions(
		*workflow.GrantProcessInstanceForDownloadFileRequest,
		*workflow.GrantProcessInstanceForDownloadFileHeaders,
		*util.RuntimeOptions,
	) (*workflow.GrantProcessInstanceForDownloadFileResponse, error)
}

type Options struct {
	ClientID        string
	ClientSecret    string
	APIEndpoint     string
	OAPIBaseURL     *url.URL
	HTTPClient      *http.Client
	UpstreamTimeout time.Duration
	Now             func() time.Time
}

type Client struct {
	clientID       string
	clientSecret   string
	oauth          oauthAPI
	contact        contactAPI
	workflow       workflowAPI
	oapiBaseURL    *url.URL
	httpClient     *http.Client
	runtimeOptions *util.RuntimeOptions
	appTokens      *appTokenCache
}

func NewClient(options Options) (*Client, error) {
	if strings.TrimSpace(options.ClientID) == "" || strings.TrimSpace(options.ClientSecret) == "" {
		return nil, fmt.Errorf("%w: DingTalk client credentials are required", domain.ErrInvalidInput)
	}
	if strings.TrimSpace(options.APIEndpoint) == "" {
		return nil, fmt.Errorf("%w: DingTalk API endpoint is required", domain.ErrInvalidInput)
	}
	if options.OAPIBaseURL == nil || options.OAPIBaseURL.Scheme != "https" ||
		options.OAPIBaseURL.Hostname() == "" {
		return nil, fmt.Errorf("%w: DingTalk OAPI HTTPS base URL is required", domain.ErrInvalidInput)
	}
	if options.UpstreamTimeout < time.Millisecond {
		return nil, fmt.Errorf("%w: upstream timeout must be at least one millisecond", domain.ErrInvalidInput)
	}

	timeoutMilliseconds := int(options.UpstreamTimeout.Milliseconds())
	sdkConfig := &openapi.Config{
		Protocol:       tea.String("https"),
		Endpoint:       tea.String(options.APIEndpoint),
		ReadTimeout:    tea.Int(timeoutMilliseconds),
		ConnectTimeout: tea.Int(timeoutMilliseconds),
	}
	oauthClient, err := oauth.NewClient(sdkConfig)
	if err != nil {
		return nil, fmt.Errorf("create DingTalk OAuth client: %w", err)
	}
	contactClient, err := contact.NewClient(sdkConfig)
	if err != nil {
		return nil, fmt.Errorf("create DingTalk contact client: %w", err)
	}
	workflowClient, err := workflow.NewClient(sdkConfig)
	if err != nil {
		return nil, fmt.Errorf("create DingTalk workflow client: %w", err)
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: options.UpstreamTimeout}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	client := &Client{
		clientID:     options.ClientID,
		clientSecret: options.ClientSecret,
		oauth:        oauthClient,
		contact:      contactClient,
		workflow:     workflowClient,
		oapiBaseURL:  cloneURL(options.OAPIBaseURL),
		httpClient:   httpClient,
		runtimeOptions: &util.RuntimeOptions{
			ReadTimeout:    tea.Int(timeoutMilliseconds),
			ConnectTimeout: tea.Int(timeoutMilliseconds),
			Autoretry:      tea.Bool(false),
		},
	}
	client.appTokens = newAppTokenCache(
		client.fetchAppToken,
		now,
		appTokenRefreshBefore,
	)
	return client, nil
}

func (client *Client) ExchangeAuthorizationCode(
	ctx context.Context,
	code string,
) (brokerauth.IdentityToken, error) {
	if strings.TrimSpace(code) == "" {
		return brokerauth.IdentityToken{}, fmt.Errorf(
			"%w: authorization code is required",
			domain.ErrInvalidInput,
		)
	}
	response, err := callSDK(ctx, func() (*oauth.GetUserTokenResponse, error) {
		return client.oauth.GetUserToken(&oauth.GetUserTokenRequest{
			ClientId:     tea.String(client.clientID),
			ClientSecret: tea.String(client.clientSecret),
			Code:         tea.String(code),
			GrantType:    tea.String("authorization_code"),
		})
	})
	if err != nil {
		return brokerauth.IdentityToken{}, classifySDKError("exchange user token", err)
	}
	if response == nil || response.Body == nil ||
		value(response.Body.AccessToken) == "" || value(response.Body.CorpId) == "" {
		return brokerauth.IdentityToken{}, fmt.Errorf(
			"%w: DingTalk user token response is incomplete",
			domain.ErrUpstream,
		)
	}
	return brokerauth.IdentityToken{
		AccessToken: value(response.Body.AccessToken),
		CorpID:      value(response.Body.CorpId),
	}, nil
}

func (client *Client) CurrentUser(
	ctx context.Context,
	userAccessToken string,
) (brokerauth.IdentityProfile, error) {
	if strings.TrimSpace(userAccessToken) == "" {
		return brokerauth.IdentityProfile{}, fmt.Errorf(
			"%w: user access token is required",
			domain.ErrInvalidInput,
		)
	}
	response, err := callSDK(ctx, func() (*contact.GetUserResponse, error) {
		return client.contact.GetUserWithOptions(
			tea.String("me"),
			&contact.GetUserHeaders{
				XAcsDingtalkAccessToken: tea.String(userAccessToken),
			},
			client.runtime(),
		)
	})
	if err != nil {
		return brokerauth.IdentityProfile{}, classifySDKError("get current user", err)
	}
	if response == nil || response.Body == nil || value(response.Body.UnionId) == "" {
		return brokerauth.IdentityProfile{}, fmt.Errorf(
			"%w: DingTalk current user response is incomplete",
			domain.ErrUpstream,
		)
	}
	return brokerauth.IdentityProfile{
		UnionID:     value(response.Body.UnionId),
		DisplayName: value(response.Body.Nick),
	}, nil
}

func (client *Client) UserIDByUnionID(ctx context.Context, unionID string) (string, error) {
	if strings.TrimSpace(unionID) == "" {
		return "", fmt.Errorf("%w: union ID is required", domain.ErrInvalidInput)
	}
	appToken, err := client.appTokens.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("get app token for union ID mapping: %w", err)
	}
	endpoint := cloneURL(client.oapiBaseURL)
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/topapi/user/getbyunionid"
	query := endpoint.Query()
	query.Set("access_token", appToken)
	endpoint.RawQuery = query.Encode()

	payload, err := json.Marshal(map[string]string{"unionid": unionID})
	if err != nil {
		return "", fmt.Errorf("encode union ID mapping request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("create union ID mapping request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", classifyHTTPError("map union ID", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxOAPIResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: read union ID mapping response: %v", domain.ErrUpstream, err)
	}
	if len(body) > maxOAPIResponseBytes {
		return "", fmt.Errorf("%w: union ID mapping response is too large", domain.ErrUpstream)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", classifyHTTPStatus("map union ID", response.StatusCode)
	}
	var result struct {
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		Result       struct {
			UserID string `json:"userid"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("%w: decode union ID mapping response: %v", domain.ErrUpstream, err)
	}
	if result.ErrorCode != 0 {
		if result.ErrorCode == 60121 {
			return "", fmt.Errorf("%w: DingTalk union ID was not found", domain.ErrNotFound)
		}
		return "", fmt.Errorf(
			"%w: DingTalk union ID mapping failed with code %d",
			domain.ErrUpstream,
			result.ErrorCode,
		)
	}
	if strings.TrimSpace(result.Result.UserID) == "" {
		return "", fmt.Errorf("%w: DingTalk user ID is empty", domain.ErrUpstream)
	}
	return result.Result.UserID, nil
}

func (client *Client) Approval(
	ctx context.Context,
	processInstanceID string,
) (domain.Approval, error) {
	processInstanceID, err := domain.NormalizeProcessInstanceID(processInstanceID)
	if err != nil {
		return domain.Approval{}, err
	}
	appToken, err := client.appTokens.Token(ctx)
	if err != nil {
		return domain.Approval{}, fmt.Errorf("get app token for approval: %w", err)
	}
	response, err := callSDK(ctx, func() (*workflow.GetProcessInstanceResponse, error) {
		return client.workflow.GetProcessInstanceWithOptions(
			&workflow.GetProcessInstanceRequest{
				ProcessInstanceId: tea.String(processInstanceID),
			},
			&workflow.GetProcessInstanceHeaders{
				XAcsDingtalkAccessToken: tea.String(appToken),
			},
			client.runtime(),
		)
	})
	if err != nil {
		return domain.Approval{}, classifySDKError("get approval instance", err)
	}
	if response == nil || response.Body == nil || response.Body.Result == nil ||
		strings.EqualFold(value(response.Body.Success), "false") {
		return domain.Approval{}, fmt.Errorf(
			"%w: DingTalk approval response is incomplete",
			domain.ErrUpstream,
		)
	}
	return mapApproval(processInstanceID, response.Body.Result), nil
}

func (client *Client) ListVisibleApprovalTemplates(
	ctx context.Context,
	query domain.VisibleApprovalTemplateQuery,
) (domain.VisibleApprovalTemplatePage, error) {
	userID := strings.TrimSpace(query.UserID)
	if userID == "" || query.NextToken < 0 ||
		query.MaxResults < 1 || query.MaxResults > 100 {
		return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
			"%w: visible approval template query is invalid",
			domain.ErrInvalidInput,
		)
	}
	appToken, err := client.appTokens.Token(ctx)
	if err != nil {
		return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
			"get app token for visible approval templates: %w",
			err,
		)
	}
	response, err := callSDK(
		ctx,
		func() (*workflow.ListUserVisibleBpmsProcessesResponse, error) {
			return client.workflow.ListUserVisibleBpmsProcessesWithOptions(
				&workflow.ListUserVisibleBpmsProcessesRequest{
					UserId:     tea.String(userID),
					NextToken:  tea.Int64(query.NextToken),
					MaxResults: tea.Int64(int64(query.MaxResults)),
				},
				&workflow.ListUserVisibleBpmsProcessesHeaders{
					XAcsDingtalkAccessToken: tea.String(appToken),
				},
				client.runtime(),
			)
		},
	)
	if err != nil {
		return domain.VisibleApprovalTemplatePage{}, classifySDKError(
			"list user-visible approval templates",
			err,
		)
	}
	if response == nil || response.Body == nil || response.Body.Result == nil ||
		len(response.Body.Result.ProcessList) > query.MaxResults {
		return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
			"%w: DingTalk visible approval template response is invalid",
			domain.ErrUpstream,
		)
	}
	templates := make(
		[]domain.VisibleApprovalTemplate,
		0,
		len(response.Body.Result.ProcessList),
	)
	for _, process := range response.Body.Result.ProcessList {
		if process == nil {
			return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
				"%w: DingTalk visible approval template response is invalid",
				domain.ErrUpstream,
			)
		}
		processCode := strings.TrimSpace(value(process.ProcessCode))
		name := strings.TrimSpace(value(process.Name))
		if processCode == "" || len(processCode) > 256 ||
			name == "" || len(name) > 512 {
			return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
				"%w: DingTalk visible approval template response is invalid",
				domain.ErrUpstream,
			)
		}
		templates = append(templates, domain.VisibleApprovalTemplate{
			ProcessCode:   processCode,
			Name:          name,
			DirectoryName: strings.TrimSpace(value(process.DirName)),
		})
	}
	nextToken := response.Body.Result.NextToken
	if nextToken != nil && *nextToken <= query.NextToken {
		return domain.VisibleApprovalTemplatePage{}, fmt.Errorf(
			"%w: DingTalk visible approval template cursor did not advance",
			domain.ErrUpstream,
		)
	}
	return domain.VisibleApprovalTemplatePage{
		Templates: templates,
		NextToken: nextToken,
	}, nil
}

func (client *Client) ListApprovalInstanceIDs(
	ctx context.Context,
	query domain.ApprovalInstanceIDQuery,
) (domain.ApprovalInstanceIDPage, error) {
	if strings.TrimSpace(query.ProcessCode) == "" ||
		query.StartTime.IsZero() ||
		query.EndTime.IsZero() ||
		!query.EndTime.After(query.StartTime) ||
		query.NextToken < 0 ||
		query.MaxResults < 1 ||
		query.MaxResults > domain.MaxApprovalSearchPageSize {
		return domain.ApprovalInstanceIDPage{}, fmt.Errorf(
			"%w: approval instance list query is invalid",
			domain.ErrInvalidInput,
		)
	}
	appToken, err := client.appTokens.Token(ctx)
	if err != nil {
		return domain.ApprovalInstanceIDPage{}, fmt.Errorf(
			"get app token for approval instance list: %w",
			err,
		)
	}
	response, err := callSDK(
		ctx,
		func() (*workflow.ListProcessInstanceIdsResponse, error) {
			return client.workflow.ListProcessInstanceIdsWithOptions(
				&workflow.ListProcessInstanceIdsRequest{
					ProcessCode: tea.String(strings.TrimSpace(query.ProcessCode)),
					StartTime:   tea.Int64(query.StartTime.UnixMilli()),
					EndTime:     tea.Int64(query.EndTime.UnixMilli()),
					NextToken:   tea.Int64(query.NextToken),
					MaxResults:  tea.Int64(int64(query.MaxResults)),
				},
				&workflow.ListProcessInstanceIdsHeaders{
					XAcsDingtalkAccessToken: tea.String(appToken),
				},
				client.runtime(),
			)
		},
	)
	if err != nil {
		return domain.ApprovalInstanceIDPage{}, classifySDKError(
			"list approval instance IDs",
			err,
		)
	}
	if response == nil || response.Body == nil || response.Body.Result == nil ||
		response.Body.Success == nil || !*response.Body.Success {
		return domain.ApprovalInstanceIDPage{}, fmt.Errorf(
			"%w: DingTalk approval instance list response is incomplete",
			domain.ErrUpstream,
		)
	}

	processInstanceIDs := stringsFromPointers(response.Body.Result.List)
	rawNextToken := strings.TrimSpace(value(response.Body.Result.NextToken))
	var nextToken *int64
	if rawNextToken != "" {
		parsed, parseErr := strconv.ParseInt(rawNextToken, 10, 64)
		if parseErr != nil || parsed < 0 {
			return domain.ApprovalInstanceIDPage{}, fmt.Errorf(
				"%w: DingTalk approval instance list cursor is invalid",
				domain.ErrUpstream,
			)
		}
		if parsed <= query.NextToken {
			return domain.ApprovalInstanceIDPage{}, fmt.Errorf(
				"%w: DingTalk approval instance list cursor did not advance",
				domain.ErrUpstream,
			)
		}
		nextToken = &parsed
	}
	return domain.ApprovalInstanceIDPage{
		ProcessInstanceIDs: processInstanceIDs,
		NextToken:          nextToken,
	}, nil
}

func (client *Client) DownloadURL(
	ctx context.Context,
	processInstanceID string,
	fileID string,
) (*url.URL, error) {
	processInstanceID, err := domain.NormalizeProcessInstanceID(processInstanceID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(fileID) == "" {
		return nil, fmt.Errorf(
			"%w: file ID is required",
			domain.ErrInvalidInput,
		)
	}
	appToken, err := client.appTokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("get app token for attachment grant: %w", err)
	}
	response, err := callSDK(
		ctx,
		func() (*workflow.GrantProcessInstanceForDownloadFileResponse, error) {
			return client.workflow.GrantProcessInstanceForDownloadFileWithOptions(
				&workflow.GrantProcessInstanceForDownloadFileRequest{
					ProcessInstanceId:      tea.String(processInstanceID),
					FileId:                 tea.String(fileID),
					WithCommentAttatchment: tea.Bool(true),
				},
				&workflow.GrantProcessInstanceForDownloadFileHeaders{
					XAcsDingtalkAccessToken: tea.String(appToken),
				},
				client.runtime(),
			)
		},
	)
	if err != nil {
		return nil, classifySDKError("grant approval attachment download", err)
	}
	if response == nil || response.Body == nil || response.Body.Result == nil ||
		response.Body.Success == nil || !*response.Body.Success {
		return nil, fmt.Errorf("%w: DingTalk attachment grant failed", domain.ErrUpstream)
	}
	if value(response.Body.Result.FileId) != fileID {
		return nil, fmt.Errorf("%w: DingTalk attachment grant returned another file", domain.ErrUpstream)
	}
	downloadURL, err := url.Parse(value(response.Body.Result.DownloadUri))
	if err != nil || downloadURL.Hostname() == "" || downloadURL.User != nil {
		return nil, fmt.Errorf("%w: DingTalk attachment grant returned an unsafe URL", domain.ErrUpstream)
	}
	switch downloadURL.Scheme {
	case "https":
	case "http":
		if port := downloadURL.Port(); port != "" && port != "443" {
			return nil, fmt.Errorf(
				"%w: DingTalk attachment grant returned an unsafe URL",
				domain.ErrUpstream,
			)
		}
		// DingTalk currently returns HTTP OSS links even though the same signed
		// resource supports TLS. Upgrade before the URL reaches the downloader
		// so plaintext transport is never attempted.
		downloadURL.Scheme = "https"
	default:
		return nil, fmt.Errorf(
			"%w: DingTalk attachment grant returned an unsafe URL",
			domain.ErrUpstream,
		)
	}
	return downloadURL, nil
}

func (client *Client) fetchAppToken(ctx context.Context) (string, time.Duration, error) {
	response, err := callSDK(ctx, func() (*oauth.GetAccessTokenResponse, error) {
		return client.oauth.GetAccessToken(&oauth.GetAccessTokenRequest{
			AppKey:    tea.String(client.clientID),
			AppSecret: tea.String(client.clientSecret),
		})
	})
	if err != nil {
		return "", 0, classifySDKError("get app token", err)
	}
	if response == nil || response.Body == nil || value(response.Body.AccessToken) == "" ||
		response.Body.ExpireIn == nil || *response.Body.ExpireIn <= 0 {
		return "", 0, fmt.Errorf("%w: DingTalk app token response is incomplete", domain.ErrUpstream)
	}
	return value(response.Body.AccessToken), time.Duration(*response.Body.ExpireIn) * time.Second, nil
}

func (client *Client) runtime() *util.RuntimeOptions {
	if client.runtimeOptions == nil {
		return &util.RuntimeOptions{}
	}
	copy := *client.runtimeOptions
	return &copy
}

func mapApproval(
	processInstanceID string,
	result *workflow.GetProcessInstanceResponseBodyResult,
) domain.Approval {
	formValues := make([]domain.FormValue, 0, len(result.FormComponentValues))
	for _, item := range result.FormComponentValues {
		if item == nil {
			continue
		}
		formValues = append(formValues, domain.FormValue{
			Name:     value(item.Name),
			Value:    value(item.Value),
			ExtValue: value(item.ExtValue),
		})
	}

	operationRecords := make([]domain.OperationRecord, 0, len(result.OperationRecords))
	ccUserIDs := stringsFromPointers(result.CcUserIds)
	for _, record := range result.OperationRecords {
		if record == nil {
			continue
		}
		recordCCUserIDs := stringsFromPointers(record.CcUserIds)
		ccUserIDs = appendUnique(ccUserIDs, recordCCUserIDs...)
		attachments := make([]domain.Attachment, 0, len(record.Attachments))
		for _, attachment := range record.Attachments {
			if attachment == nil {
				continue
			}
			attachments = append(attachments, domain.Attachment{
				FileID:   value(attachment.FileId),
				FileName: value(attachment.FileName),
				FileSize: parseNonNegativeInt64(value(attachment.FileSize)),
				FileType: value(attachment.FileType),
				SpaceID:  value(attachment.SpaceId),
			})
		}
		operationRecords = append(operationRecords, domain.OperationRecord{
			UserID:      value(record.UserId),
			CCUserIDs:   recordCCUserIDs,
			Attachments: attachments,
		})
	}

	taskUserIDs := make([]string, 0, len(result.Tasks))
	for _, task := range result.Tasks {
		if task != nil {
			taskUserIDs = appendUnique(taskUserIDs, value(task.UserId))
		}
	}
	approval := domain.Approval{
		ProcessInstanceID: processInstanceID,
		BusinessID:        value(result.BusinessId),
		Title:             value(result.Title),
		Status:            value(result.Status),
		Result:            value(result.Result),
		CreateTime:        value(result.CreateTime),
		FinishTime:        value(result.FinishTime),
		OriginatorUserID:  value(result.OriginatorUserId),
		ApproverUserIDs:   stringsFromPointers(result.ApproverUserIds),
		CCUserIDs:         ccUserIDs,
		TaskUserIDs:       taskUserIDs,
		FormValues:        formValues,
		OperationRecords:  operationRecords,
	}
	approval.Attachments = domain.ParseAttachments(formValues, operationRecords)
	return approval
}

func callSDK[T any](ctx context.Context, call func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	results := make(chan result, 1)
	go func() {
		value, err := call()
		results <- result{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case completed := <-results:
		return completed.value, completed.err
	}
}

func classifySDKError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %v", domain.ErrUnavailable, operation, err)
	}
	var sdkError *tea.SDKError
	if errors.As(err, &sdkError) {
		status := 0
		if sdkError.StatusCode != nil {
			status = *sdkError.StatusCode
		}
		return classifyHTTPStatus(operation, status)
	}
	return fmt.Errorf("%w: %s", domain.ErrUpstream, operation)
}

func classifyHTTPError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %v", domain.ErrUnavailable, operation, err)
	}
	var urlError *url.Error
	if errors.As(err, &urlError) && urlError.Timeout() {
		return fmt.Errorf("%w: %s: %v", domain.ErrUnavailable, operation, err)
	}
	return fmt.Errorf("%w: %s", domain.ErrUpstream, operation)
}

func classifyHTTPStatus(operation string, status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s", domain.ErrForbidden, operation)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", domain.ErrNotFound, operation)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s", domain.ErrRateLimited, operation)
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("%w: %s", domain.ErrUnavailable, operation)
	default:
		return fmt.Errorf("%w: %s returned status %d", domain.ErrUpstream, operation, status)
	}
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	copy := *source
	return &copy
}

func stringsFromPointers(values []*string) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = appendUnique(result, value(item))
	}
	return result
}

func appendUnique(values []string, additions ...string) []string {
	existing := make(map[string]struct{}, len(values)+len(additions))
	for _, item := range values {
		if item != "" {
			existing[item] = struct{}{}
		}
	}
	for _, item := range additions {
		if item == "" {
			continue
		}
		if _, ok := existing[item]; ok {
			continue
		}
		existing[item] = struct{}{}
		values = append(values, item)
	}
	return values
}

func parseNonNegativeInt64(raw string) int64 {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}
