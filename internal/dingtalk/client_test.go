package dingtalk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contact "github.com/alibabacloud-go/dingtalk/contact_1_0"
	oauth "github.com/alibabacloud-go/dingtalk/oauth2_1_0"
	workflow "github.com/alibabacloud-go/dingtalk/workflow_1_0"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestAppTokenCacheMergesConcurrentRefreshes(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cache := newAppTokenCache(
		func(context.Context) (string, time.Duration, error) {
			calls.Add(1)
			<-release
			return "app-token", time.Hour, nil
		},
		time.Now,
		5*time.Minute,
	)

	const workers = 20
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	results := make(chan string, workers)
	errorsChannel := make(chan error, workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			token, err := cache.Token(context.Background())
			results <- token
			errorsChannel <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	waitGroup.Wait()
	close(results)
	close(errorsChannel)

	if calls.Load() != 1 {
		t.Fatalf("app token fetches = %d; want 1", calls.Load())
	}
	for err := range errorsChannel {
		if err != nil {
			t.Errorf("Token() error = %v", err)
		}
	}
	for token := range results {
		if token != "app-token" {
			t.Errorf("Token() = %q; want app-token", token)
		}
	}
	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("cached Token() error = %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("cached app token fetches = %d; want 1", calls.Load())
	}
}

func TestAppTokenCacheOwnerCancellationDoesNotFailOtherCallers(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	cache := newAppTokenCache(
		func(ctx context.Context) (string, time.Duration, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			deadline, bounded := ctx.Deadline()
			if !bounded || time.Until(deadline) > appTokenFetchTimeout {
				return "", 0, errors.New("app token fetch context is not bounded")
			}
			select {
			case <-ctx.Done():
				return "", 0, ctx.Err()
			case <-release:
				return "app-token", time.Hour, nil
			}
		},
		time.Now,
		5*time.Minute,
	)
	ownerContext, cancelOwner := context.WithCancel(context.Background())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := cache.Token(ownerContext)
		ownerResult <- err
	}()
	<-started
	cancelOwner()
	if err := <-ownerResult; !errors.Is(err, context.Canceled) || !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("owner Token() error = %v; want unavailable and canceled", err)
	}

	liveResult := make(chan error, 1)
	go func() {
		token, err := cache.Token(context.Background())
		if err == nil && token != "app-token" {
			err = fmt.Errorf("Token() = %q; want app-token", token)
		}
		liveResult <- err
	}()
	close(release)
	if err := <-liveResult; err != nil {
		t.Fatalf("live Token() error = %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("app token fetches = %d; want 1", calls.Load())
	}
}

func TestAppTokenCacheRefreshesBeforeExpirationAndSharesFailure(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	expected := errors.New("token endpoint unavailable")
	cache := newAppTokenCache(
		func(context.Context) (string, time.Duration, error) {
			switch calls.Add(1) {
			case 1:
				return "first-token", 10 * time.Minute, nil
			default:
				return "", 0, expected
			}
		},
		func() time.Time { return now },
		5*time.Minute,
	)
	if token, err := cache.Token(context.Background()); err != nil || token != "first-token" {
		t.Fatalf("first Token() = %q, %v; want first-token", token, err)
	}

	now = now.Add(6 * time.Minute)
	if token, err := cache.Token(context.Background()); err != nil || token != "first-token" {
		t.Fatalf("refresh fallback Token() = %q, %v; want first-token", token, err)
	}
	if token, err := cache.Token(context.Background()); err != nil || token != "first-token" {
		t.Fatalf("backoff Token() = %q, %v; want first-token", token, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("app token fetches during backoff = %d; want 2", calls.Load())
	}
	now = now.Add(5 * time.Minute)
	if _, err := cache.Token(context.Background()); !errors.Is(err, expected) {
		t.Fatalf("expired refresh Token() error = %v; want expected failure", err)
	}
}

func TestIdentityProviderUsesUserTokenOnlyForCurrentUser(t *testing.T) {
	oauthAPI := &fakeOAuthAPI{
		userTokenResponse: &oauth.GetUserTokenResponse{
			Body: &oauth.GetUserTokenResponseBody{
				AccessToken: stringPointer("user-token"),
				CorpId:      stringPointer("corp-id"),
			},
		},
	}
	contactAPI := &fakeContactAPI{
		response: &contact.GetUserResponse{
			Body: &contact.GetUserResponseBody{
				UnionId: stringPointer("union-id"),
				Nick:    stringPointer("Verified User"),
			},
		},
	}
	client := &Client{
		clientID:     "client-id",
		clientSecret: "client-secret",
		oauth:        oauthAPI,
		contact:      contactAPI,
	}

	token, err := client.ExchangeAuthorizationCode(context.Background(), "authorization-code")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}
	if token.AccessToken != "user-token" || token.CorpID != "corp-id" {
		t.Errorf("identity token = %#v", token)
	}
	profile, err := client.CurrentUser(context.Background(), token.AccessToken)
	if err != nil {
		t.Fatalf("CurrentUser() error = %v", err)
	}
	if profile.UnionID != "union-id" || profile.DisplayName != "Verified User" {
		t.Errorf("identity profile = %#v", profile)
	}
	if contactAPI.requestedUser != "me" {
		t.Errorf("current user request = %q; want me", contactAPI.requestedUser)
	}
	if contactAPI.accessToken != "user-token" {
		t.Errorf("current user access token = %q; want user-token", contactAPI.accessToken)
	}
}

func TestUserIDByUnionIDUsesAppTokenAndRejectsDingTalkErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/topapi/user/getbyunionid" {
			http.NotFound(response, request)
			return
		}
		if request.URL.Query().Get("access_token") != "app-token" {
			t.Errorf("access_token = %q; want app-token", request.URL.Query().Get("access_token"))
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"errcode":0,"errmsg":"ok","result":{"userid":"mapped-user"}}`))
	}))
	defer server.Close()

	client := &Client{
		oapiBaseURL: mustParseURL(t, server.URL),
		httpClient:  server.Client(),
		appTokens: newAppTokenCache(
			func(context.Context) (string, time.Duration, error) {
				return "app-token", time.Hour, nil
			},
			time.Now,
			5*time.Minute,
		),
	}
	userID, err := client.UserIDByUnionID(context.Background(), "union-id")
	if err != nil {
		t.Fatalf("UserIDByUnionID() error = %v", err)
	}
	if userID != "mapped-user" {
		t.Errorf("UserIDByUnionID() = %q; want mapped-user", userID)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d; want 1", requests.Load())
	}

	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"errcode":60121,"errmsg":"unionId not found"}`))
	})
	if _, err := client.UserIDByUnionID(context.Background(), "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing union ID error = %v; want not found", err)
	}
}

func TestApprovalMapsParticipantsAndAttachments(t *testing.T) {
	workflowAPI := &fakeWorkflowAPI{
		processResponse: &workflow.GetProcessInstanceResponse{
			Body: &workflow.GetProcessInstanceResponseBody{
				Success: stringPointer("true"),
				Result: &workflow.GetProcessInstanceResponseBodyResult{
					BusinessId:       stringPointer("business-id"),
					Title:            stringPointer("Approval title"),
					Status:           stringPointer("RUNNING"),
					Result:           stringPointer("NONE"),
					CreateTime:       stringPointer("2026-07-18T08:00:00Z"),
					OriginatorUserId: stringPointer("originator"),
					ApproverUserIds:  stringPointers("approver"),
					CcUserIds:        stringPointers("cc"),
					Tasks: []*workflow.GetProcessInstanceResponseBodyResultTasks{
						{UserId: stringPointer("task-user")},
					},
					FormComponentValues: []*workflow.GetProcessInstanceResponseBodyResultFormComponentValues{
						{
							Name:  stringPointer("Attachment"),
							Value: stringPointer(`[{"fileId":"form-file","fileName":"form.pdf","fileSize":"11"}]`),
						},
					},
					OperationRecords: []*workflow.GetProcessInstanceResponseBodyResultOperationRecords{
						{
							UserId:    stringPointer("operator"),
							CcUserIds: stringPointers("operation-cc"),
							Attachments: []*workflow.GetProcessInstanceResponseBodyResultOperationRecordsAttachments{
								{
									FileId:   stringPointer("comment-file"),
									FileName: stringPointer("comment.txt"),
									FileSize: stringPointer("12"),
									FileType: stringPointer("txt"),
									SpaceId:  stringPointer("space-id"),
								},
							},
						},
					},
				},
			},
		},
	}
	client := &Client{
		workflow:  workflowAPI,
		appTokens: staticAppTokenCache("app-token"),
	}

	approval, err := client.Approval(context.Background(), "instance-id")
	if err != nil {
		t.Fatalf("Approval() error = %v", err)
	}
	if approval.ProcessInstanceID != "instance-id" ||
		approval.BusinessID != "business-id" ||
		approval.Status != "RUNNING" ||
		approval.CreateTime != "2026-07-18T08:00:00Z" ||
		approval.OriginatorUserID != "originator" {
		t.Errorf("approval identity = %#v", approval)
	}
	if !approval.CanAccess("approver", nil) ||
		!approval.CanAccess("cc", nil) ||
		!approval.CanAccess("operation-cc", nil) ||
		!approval.CanAccess("task-user", nil) {
		t.Errorf("approval participant mapping = %#v", approval)
	}
	if len(approval.Attachments) != 2 {
		t.Fatalf("attachments = %#v; want 2", approval.Attachments)
	}
	if len(approval.FormValues) != 1 {
		t.Fatalf("form values = %#v; want 1", approval.FormValues)
	}
	if workflowAPI.processAccessToken != "app-token" {
		t.Errorf("process access token = %q; want app-token", workflowAPI.processAccessToken)
	}

	workflowAPI.processResponse.Body.Result.CreateTime = stringPointer("not-a-time")
	if _, err := client.Approval(context.Background(), "instance-id"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("invalid create time error = %v; want upstream", err)
	}
	workflowAPI.processResponse.Body.Result.CreateTime = stringPointer("2026-07-18T08:00:00Z")
	workflowAPI.processResponse.Body.Result.FinishTime = stringPointer("not-a-time")
	if _, err := client.Approval(context.Background(), "instance-id"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("invalid finish time error = %v; want upstream", err)
	}
}

func TestNormalizeApprovalTimestampAcceptsMinutePrecision(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "UTC", input: "2026-07-18T08:00Z", want: "2026-07-18T08:00:00Z"},
		{name: "offset", input: "2026-07-18T16:00+08:00", want: "2026-07-18T08:00:00Z"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := normalizeApprovalTimestamp("createTime", testCase.input)
			if err != nil {
				t.Fatalf("normalizeApprovalTimestamp() error = %v", err)
			}
			if got != testCase.want {
				t.Errorf("normalizeApprovalTimestamp() = %q; want %q", got, testCase.want)
			}
		})
	}
}

func TestListVisibleApprovalTemplatesMapsDirectoryMetadata(t *testing.T) {
	workflowAPI := &fakeWorkflowAPI{
		visibleTemplatesResponse: &workflow.ListUserVisibleBpmsProcessesResponse{
			Body: &workflow.ListUserVisibleBpmsProcessesResponseBody{
				Result: &workflow.ListUserVisibleBpmsProcessesResponseBodyResult{
					NextToken: int64Pointer(100),
					ProcessList: []*workflow.ListUserVisibleBpmsProcessesResponseBodyResultProcessList{
						{
							ProcessCode: stringPointer("PROC-FINANCE"),
							Name:        stringPointer("Expense reimbursement"),
							DirId:       stringPointer("directory-finance"),
							DirName:     stringPointer("Finance"),
						},
					},
				},
			},
		},
	}
	client := &Client{
		workflow:  workflowAPI,
		appTokens: staticAppTokenCache("app-token"),
	}

	page, err := client.ListVisibleApprovalTemplates(
		context.Background(),
		domain.VisibleApprovalTemplateQuery{
			UserID:     "user-id",
			NextToken:  20,
			MaxResults: 100,
		},
	)
	if err != nil {
		t.Fatalf("ListVisibleApprovalTemplates() error = %v", err)
	}
	if len(page.Templates) != 1 ||
		page.Templates[0].ProcessCode != "PROC-FINANCE" ||
		page.Templates[0].Name != "Expense reimbursement" ||
		page.Templates[0].DirectoryName != "Finance" ||
		page.NextToken == nil || *page.NextToken != 100 {
		t.Errorf("visible template page = %#v", page)
	}
	if workflowAPI.visibleTemplatesRequest == nil ||
		value(workflowAPI.visibleTemplatesRequest.UserId) != "user-id" ||
		int64Value(workflowAPI.visibleTemplatesRequest.NextToken) != 20 ||
		int64Value(workflowAPI.visibleTemplatesRequest.MaxResults) != 100 ||
		workflowAPI.visibleTemplatesAccessToken != "app-token" {
		t.Errorf(
			"visible template request = %#v, token = %q",
			workflowAPI.visibleTemplatesRequest,
			workflowAPI.visibleTemplatesAccessToken,
		)
	}
}

func TestListVisibleApprovalTemplatesFailsClosedOnInvalidResponses(t *testing.T) {
	client := &Client{}
	invalidQueries := []domain.VisibleApprovalTemplateQuery{
		{},
		{UserID: "user", NextToken: -1, MaxResults: 100},
		{UserID: "user", MaxResults: 101},
	}
	for _, query := range invalidQueries {
		if _, err := client.ListVisibleApprovalTemplates(
			context.Background(),
			query,
		); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("query %#v error = %v; want invalid input", query, err)
		}
	}

	workflowAPI := &fakeWorkflowAPI{
		visibleTemplatesResponse: &workflow.ListUserVisibleBpmsProcessesResponse{
			Body: &workflow.ListUserVisibleBpmsProcessesResponseBody{
				Result: &workflow.ListUserVisibleBpmsProcessesResponseBodyResult{
					ProcessList: []*workflow.ListUserVisibleBpmsProcessesResponseBodyResultProcessList{
						{Name: stringPointer("Missing process code")},
					},
				},
			},
		},
	}
	client = &Client{workflow: workflowAPI, appTokens: staticAppTokenCache("token")}
	if _, err := client.ListVisibleApprovalTemplates(
		context.Background(),
		domain.VisibleApprovalTemplateQuery{UserID: "user", MaxResults: 100},
	); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("invalid template response error = %v; want upstream", err)
	}

	workflowAPI.visibleTemplatesResponse = &workflow.ListUserVisibleBpmsProcessesResponse{
		Body: &workflow.ListUserVisibleBpmsProcessesResponseBody{
			Result: &workflow.ListUserVisibleBpmsProcessesResponseBodyResult{
				NextToken: int64Pointer(0),
			},
		},
	}
	if _, err := client.ListVisibleApprovalTemplates(
		context.Background(),
		domain.VisibleApprovalTemplateQuery{UserID: "user", MaxResults: 100},
	); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("non-advancing template cursor error = %v; want upstream", err)
	}
}

func TestListApprovalInstanceIDsUsesBoundedOfficialWorkflowQuery(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	workflowAPI := &fakeWorkflowAPI{
		listResponse: &workflow.ListProcessInstanceIdsResponse{
			Body: &workflow.ListProcessInstanceIdsResponseBody{
				Success: boolPointer(true),
				Result: &workflow.ListProcessInstanceIdsResponseBodyResult{
					List:      stringPointers("instance-one", "instance-two"),
					NextToken: stringPointer("12"),
				},
			},
		},
	}
	client := &Client{
		workflow:  workflowAPI,
		appTokens: staticAppTokenCache("app-token"),
	}

	page, err := client.ListApprovalInstanceIDs(
		context.Background(),
		domain.ApprovalInstanceIDQuery{
			ProcessCode: "PROC-FIRMWARE",
			StartTime:   start,
			EndTime:     end,
			NextToken:   2,
			MaxResults:  10,
		},
	)
	if err != nil {
		t.Fatalf("ListApprovalInstanceIDs() error = %v", err)
	}
	if len(page.ProcessInstanceIDs) != 2 || page.NextToken == nil || *page.NextToken != 12 {
		t.Errorf("page = %#v", page)
	}
	if workflowAPI.listRequest == nil ||
		value(workflowAPI.listRequest.ProcessCode) != "PROC-FIRMWARE" ||
		int64Value(workflowAPI.listRequest.StartTime) != start.UnixMilli() ||
		int64Value(workflowAPI.listRequest.EndTime) != end.UnixMilli() ||
		int64Value(workflowAPI.listRequest.NextToken) != int64(2) ||
		int64Value(workflowAPI.listRequest.MaxResults) != int64(10) {
		t.Errorf("list request = %#v", workflowAPI.listRequest)
	}
	if workflowAPI.listAccessToken != "app-token" {
		t.Errorf("list access token = %q; want app-token", workflowAPI.listAccessToken)
	}
}

func TestListApprovalInstanceIDsFailsClosedForInvalidQueriesAndResponses(t *testing.T) {
	client := &Client{}
	if _, err := client.ListApprovalInstanceIDs(
		context.Background(),
		domain.ApprovalInstanceIDQuery{},
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("invalid query error = %v; want invalid input", err)
	}

	testCases := []struct {
		name      string
		response  *workflow.ListProcessInstanceIdsResponse
		err       error
		nextToken int64
	}{
		{name: "SDK error", err: errors.New("failed")},
		{name: "incomplete response", response: &workflow.ListProcessInstanceIdsResponse{}},
		{
			name: "invalid cursor",
			response: &workflow.ListProcessInstanceIdsResponse{
				Body: &workflow.ListProcessInstanceIdsResponseBody{
					Success: boolPointer(true),
					Result: &workflow.ListProcessInstanceIdsResponseBodyResult{
						NextToken: stringPointer("not-a-number"),
					},
				},
			},
		},
		{
			name: "non-advancing full cursor",
			response: &workflow.ListProcessInstanceIdsResponse{
				Body: &workflow.ListProcessInstanceIdsResponseBody{
					Success: boolPointer(true),
					Result: &workflow.ListProcessInstanceIdsResponseBodyResult{
						List:      stringPointers("instance"),
						NextToken: stringPointer("0"),
					},
				},
			},
		},
		{
			name:      "regressing cursor",
			nextToken: 5,
			response: &workflow.ListProcessInstanceIdsResponse{
				Body: &workflow.ListProcessInstanceIdsResponseBody{
					Success: boolPointer(true),
					Result: &workflow.ListProcessInstanceIdsResponseBodyResult{
						NextToken: stringPointer("4"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			workflowAPI := &fakeWorkflowAPI{
				listResponse: testCase.response,
				listError:    testCase.err,
			}
			client := &Client{
				workflow:  workflowAPI,
				appTokens: staticAppTokenCache("app-token"),
			}
			_, err := client.ListApprovalInstanceIDs(
				context.Background(),
				domain.ApprovalInstanceIDQuery{
					ProcessCode: "PROC-ONE",
					StartTime:   time.Now().Add(-time.Hour),
					EndTime:     time.Now(),
					NextToken:   testCase.nextToken,
					MaxResults:  1,
				},
			)
			if !errors.Is(err, domain.ErrUpstream) {
				t.Errorf("ListApprovalInstanceIDs() error = %v; want upstream", err)
			}
		})
	}
}

func TestDownloadURLRequiresMatchingFileAndSecureURL(t *testing.T) {
	workflowAPI := &fakeWorkflowAPI{
		grantResponse: &workflow.GrantProcessInstanceForDownloadFileResponse{
			Body: &workflow.GrantProcessInstanceForDownloadFileResponseBody{
				Success: boolPointer(true),
				Result: &workflow.GrantProcessInstanceForDownloadFileResponseBodyResult{
					FileId:      stringPointer("file-id"),
					DownloadUri: stringPointer("https://download.example.test/signed"),
				},
			},
		},
	}
	client := &Client{
		workflow:  workflowAPI,
		appTokens: staticAppTokenCache("app-token"),
	}
	downloadURL, err := client.DownloadURL(context.Background(), "instance-id", "file-id")
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL.String() != "https://download.example.test/signed" {
		t.Errorf("DownloadURL() = %q", downloadURL)
	}
	if !workflowAPI.withCommentAttachment {
		t.Error("DownloadURL() did not request comment attachments")
	}

	workflowAPI.grantResponse.Body.Result.FileId = stringPointer("different-file")
	if _, err := client.DownloadURL(context.Background(), "instance-id", "file-id"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("mismatched file error = %v; want upstream failure", err)
	}
	workflowAPI.grantResponse.Body.Result.FileId = stringPointer("file-id")
	workflowAPI.grantResponse.Body.Result.DownloadUri = stringPointer(
		"http://download.example.test/signed?token=value",
	)
	upgradedURL, err := client.DownloadURL(context.Background(), "instance-id", "file-id")
	if err != nil {
		t.Fatalf("HTTP DownloadURL() error = %v", err)
	}
	if upgradedURL.String() != "https://download.example.test/signed?token=value" {
		t.Errorf("upgraded DownloadURL() = %q", upgradedURL)
	}

	workflowAPI.grantResponse.Body.Result.DownloadUri = stringPointer(
		"http://download.example.test:443/signed?token=value",
	)
	upgradedURL, err = client.DownloadURL(context.Background(), "instance-id", "file-id")
	if err != nil {
		t.Fatalf("HTTP port 443 DownloadURL() error = %v", err)
	}
	if upgradedURL.String() != "https://download.example.test:443/signed?token=value" {
		t.Errorf("upgraded port 443 DownloadURL() = %q", upgradedURL)
	}

	unsafeURLs := []string{
		"ftp://download.example.test/signed",
		"http://user@download.example.test/signed",
		"http://download.example.test:8080/signed",
	}
	for _, rawURL := range unsafeURLs {
		workflowAPI.grantResponse.Body.Result.DownloadUri = stringPointer(rawURL)
		if _, err := client.DownloadURL(
			context.Background(),
			"instance-id",
			"file-id",
		); !errors.Is(err, domain.ErrUpstream) {
			t.Errorf("unsafe URL %q error = %v; want upstream failure", rawURL, err)
		}
	}
}

func TestNewClientValidatesOptionsAndBuildsOfficialSDKClients(t *testing.T) {
	baseURL := mustParseURL(t, "https://oapi.dingtalk.com")
	valid := Options{
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		APIEndpoint:     "api.dingtalk.com",
		OAPIBaseURL:     baseURL,
		UpstreamTimeout: time.Second,
	}
	testCases := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "client ID", mutate: func(options *Options) { options.ClientID = "" }},
		{name: "client secret", mutate: func(options *Options) { options.ClientSecret = "" }},
		{name: "endpoint", mutate: func(options *Options) { options.APIEndpoint = "" }},
		{name: "OAPI URL", mutate: func(options *Options) { options.OAPIBaseURL = nil }},
		{
			name: "insecure OAPI URL",
			mutate: func(options *Options) {
				options.OAPIBaseURL = mustParseURL(t, "http://oapi.dingtalk.com")
			},
		},
		{name: "timeout", mutate: func(options *Options) { options.UpstreamTimeout = 0 }},
		{name: "sub-millisecond timeout", mutate: func(options *Options) { options.UpstreamTimeout = 500 * time.Microsecond }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := valid
			testCase.mutate(&options)
			if _, err := NewClient(options); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("NewClient() error = %v; want invalid input", err)
			}
		})
	}

	client, err := NewClient(valid)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.oauth == nil || client.contact == nil || client.workflow == nil ||
		client.appTokens == nil || client.runtime().ReadTimeout == nil {
		t.Errorf("NewClient() = %#v", client)
	}
	if client.oapiBaseURL == baseURL {
		t.Error("NewClient() retained mutable OAPI URL pointer")
	}
}

func TestIdentityProviderFailsClosedForInvalidAndIncompleteResponses(t *testing.T) {
	testCases := []struct {
		name     string
		code     string
		response *oauth.GetUserTokenResponse
		err      error
		want     error
	}{
		{name: "empty code", want: domain.ErrInvalidInput},
		{name: "SDK error", code: "code", err: errors.New("failed"), want: domain.ErrUpstream},
		{name: "nil response", code: "code", want: domain.ErrUpstream},
		{
			name: "empty access token",
			code: "code",
			response: &oauth.GetUserTokenResponse{
				Body: &oauth.GetUserTokenResponseBody{CorpId: stringPointer("corp")},
			},
			want: domain.ErrUpstream,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &Client{
				clientID:     "client",
				clientSecret: "secret",
				oauth: &fakeOAuthAPI{
					userTokenResponse: testCase.response,
					userTokenError:    testCase.err,
				},
			}
			_, err := client.ExchangeAuthorizationCode(context.Background(), testCase.code)
			if !errors.Is(err, testCase.want) {
				t.Errorf("ExchangeAuthorizationCode() error = %v; want %v", err, testCase.want)
			}
		})
	}

	client := &Client{contact: &fakeContactAPI{err: errors.New("failed")}}
	if _, err := client.CurrentUser(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty CurrentUser() error = %v", err)
	}
	if _, err := client.CurrentUser(context.Background(), "token"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("failed CurrentUser() error = %v", err)
	}
	client.contact = &fakeContactAPI{response: &contact.GetUserResponse{Body: &contact.GetUserResponseBody{}}}
	if _, err := client.CurrentUser(context.Background(), "token"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("incomplete CurrentUser() error = %v", err)
	}
}

func TestUserIDByUnionIDFailsClosedForProtocolErrors(t *testing.T) {
	if _, err := (&Client{}).UserIDByUnionID(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty union ID error = %v", err)
	}

	client := &Client{
		appTokens: newAppTokenCache(
			func(context.Context) (string, time.Duration, error) {
				return "", 0, domain.ErrUnavailable
			},
			time.Now,
			time.Minute,
		),
	}
	if _, err := client.UserIDByUnionID(context.Background(), "union"); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("app token error = %v", err)
	}

	testCases := []struct {
		name       string
		status     int
		body       string
		bodyReader io.ReadCloser
		want       error
	}{
		{name: "HTTP status", status: http.StatusTooManyRequests, body: `{}`, want: domain.ErrRateLimited},
		{name: "invalid JSON", status: http.StatusOK, body: `{`, want: domain.ErrUpstream},
		{
			name:   "DingTalk error",
			status: http.StatusOK,
			body:   `{"errcode":500,"errmsg":"failed"}`,
			want:   domain.ErrUpstream,
		},
		{
			name:   "empty user ID",
			status: http.StatusOK,
			body:   `{"errcode":0,"errmsg":"ok","result":{}}`,
			want:   domain.ErrUpstream,
		},
		{
			name:       "read error",
			status:     http.StatusOK,
			bodyReader: &failingReadCloser{},
			want:       domain.ErrUpstream,
		},
		{
			name:   "oversized response",
			status: http.StatusOK,
			body:   strings.Repeat("x", maxOAPIResponseBytes+1),
			want:   domain.ErrUpstream,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := oapiTestClient(func(*http.Request) (*http.Response, error) {
				body := testCase.bodyReader
				if body == nil {
					body = io.NopCloser(strings.NewReader(testCase.body))
				}
				return &http.Response{
					StatusCode: testCase.status,
					Body:       body,
					Header:     make(http.Header),
				}, nil
			})
			_, err := client.UserIDByUnionID(context.Background(), "union")
			if !errors.Is(err, testCase.want) {
				t.Errorf("UserIDByUnionID() error = %v; want %v", err, testCase.want)
			}
		})
	}

	client = oapiTestClient(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	if _, err := client.UserIDByUnionID(context.Background(), "union"); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("transport timeout error = %v", err)
	}
}

func TestApprovalAndDownloadURLFailClosed(t *testing.T) {
	client := &Client{}
	if _, err := client.Approval(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty Approval() error = %v", err)
	}
	if _, err := client.DownloadURL(context.Background(), "", "file"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty DownloadURL() error = %v", err)
	}
	if _, err := client.Approval(
		context.Background(),
		"PROC-DF836022-D293-44C2-976F-F80EC6340BC8",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("template-code Approval() error = %v", err)
	}
	if _, err := client.DownloadURL(
		context.Background(),
		"PROC-0421CFCB-58BA-4937-AF5E-3472773274C2",
		"file",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("template-code DownloadURL() error = %v", err)
	}

	client = &Client{
		appTokens: newAppTokenCache(
			func(context.Context) (string, time.Duration, error) {
				return "", 0, domain.ErrUnavailable
			},
			time.Now,
			time.Minute,
		),
	}
	if _, err := client.Approval(context.Background(), "instance"); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("Approval() token error = %v", err)
	}
	if _, err := client.DownloadURL(context.Background(), "instance", "file"); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("DownloadURL() token error = %v", err)
	}

	workflowAPI := &fakeWorkflowAPI{processError: errors.New("failed"), grantError: errors.New("failed")}
	client = &Client{workflow: workflowAPI, appTokens: staticAppTokenCache("token")}
	if _, err := client.Approval(context.Background(), "instance"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("Approval() SDK error = %v", err)
	}
	if _, err := client.DownloadURL(context.Background(), "instance", "file"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("DownloadURL() SDK error = %v", err)
	}

	workflowAPI.processError = nil
	workflowAPI.processResponse = &workflow.GetProcessInstanceResponse{
		Body: &workflow.GetProcessInstanceResponseBody{Success: stringPointer("false")},
	}
	if _, err := client.Approval(context.Background(), "instance"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("Approval() incomplete error = %v", err)
	}
	workflowAPI.grantError = nil
	workflowAPI.grantResponse = &workflow.GrantProcessInstanceForDownloadFileResponse{
		Body: &workflow.GrantProcessInstanceForDownloadFileResponseBody{
			Success: boolPointer(false),
		},
	}
	if _, err := client.DownloadURL(context.Background(), "instance", "file"); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("DownloadURL() unsuccessful error = %v", err)
	}
}

func TestAppTokenFetchAndErrorClassification(t *testing.T) {
	oauthAPI := &fakeOAuthAPI{
		appTokenResponse: &oauth.GetAccessTokenResponse{
			Body: &oauth.GetAccessTokenResponseBody{
				AccessToken: stringPointer("app-token"),
				ExpireIn:    int64Pointer(3600),
			},
		},
	}
	client := &Client{clientID: "client", clientSecret: "secret", oauth: oauthAPI}
	token, ttl, err := client.fetchAppToken(context.Background())
	if err != nil || token != "app-token" || ttl != time.Hour {
		t.Errorf("fetchAppToken() = %q, %s, %v", token, ttl, err)
	}
	oauthAPI.appTokenResponse = &oauth.GetAccessTokenResponse{Body: &oauth.GetAccessTokenResponseBody{}}
	if _, _, err := client.fetchAppToken(context.Background()); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("incomplete app token error = %v", err)
	}
	oauthAPI.appTokenError = errors.New("failed")
	if _, _, err := client.fetchAppToken(context.Background()); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("app token SDK error = %v", err)
	}

	statuses := map[int]error{
		http.StatusUnauthorized:       domain.ErrForbidden,
		http.StatusForbidden:          domain.ErrForbidden,
		http.StatusNotFound:           domain.ErrNotFound,
		http.StatusTooManyRequests:    domain.ErrRateLimited,
		http.StatusBadGateway:         domain.ErrUnavailable,
		http.StatusServiceUnavailable: domain.ErrUnavailable,
		http.StatusGatewayTimeout:     domain.ErrUnavailable,
		http.StatusBadRequest:         domain.ErrUpstream,
	}
	for status, expected := range statuses {
		if err := classifyHTTPStatus("operation", status); !errors.Is(err, expected) {
			t.Errorf("classifyHTTPStatus(%d) = %v; want %v", status, err, expected)
		}
	}
	sdkStatus := http.StatusForbidden
	if err := classifySDKError("operation", &tea.SDKError{StatusCode: &sdkStatus}); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("classifySDKError() = %v", err)
	}
	if err := classifySDKError("operation", context.Canceled); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("cancelled SDK error = %v", err)
	}
	if err := classifyHTTPError("operation", errors.New("failed")); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("HTTP error = %v", err)
	}
	timeout := &url.Error{Op: "GET", URL: "https://api.example.test", Err: timeoutError{}}
	if err := classifyHTTPError("operation", timeout); !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("timeout HTTP error = %v", err)
	}
}

func TestSDKCallHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	_, err := callSDK(ctx, func() (string, error) {
		calls.Add(1)
		return "late", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("callSDK() error = %v; want canceled", err)
	}
	if calls.Load() != 0 {
		t.Errorf("callSDK() calls = %d; want 0", calls.Load())
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type fakeOAuthAPI struct {
	appTokenResponse  *oauth.GetAccessTokenResponse
	appTokenError     error
	userTokenResponse *oauth.GetUserTokenResponse
	userTokenError    error
}

func (fake *fakeOAuthAPI) GetAccessToken(
	*oauth.GetAccessTokenRequest,
) (*oauth.GetAccessTokenResponse, error) {
	return fake.appTokenResponse, fake.appTokenError
}

func (fake *fakeOAuthAPI) GetUserToken(
	request *oauth.GetUserTokenRequest,
) (*oauth.GetUserTokenResponse, error) {
	if value(request.ClientId) == "" || value(request.ClientSecret) == "" ||
		value(request.Code) == "" || value(request.GrantType) != "authorization_code" {
		return nil, errors.New("invalid user token request")
	}
	return fake.userTokenResponse, fake.userTokenError
}

type fakeContactAPI struct {
	response      *contact.GetUserResponse
	err           error
	requestedUser string
	accessToken   string
}

func (fake *fakeContactAPI) GetUserWithOptions(
	user *string,
	headers *contact.GetUserHeaders,
	_ *util.RuntimeOptions,
) (*contact.GetUserResponse, error) {
	fake.requestedUser = value(user)
	fake.accessToken = value(headers.XAcsDingtalkAccessToken)
	return fake.response, fake.err
}

type fakeWorkflowAPI struct {
	listResponse                *workflow.ListProcessInstanceIdsResponse
	listError                   error
	listRequest                 *workflow.ListProcessInstanceIdsRequest
	listAccessToken             string
	visibleTemplatesResponse    *workflow.ListUserVisibleBpmsProcessesResponse
	visibleTemplatesError       error
	visibleTemplatesRequest     *workflow.ListUserVisibleBpmsProcessesRequest
	visibleTemplatesAccessToken string
	processResponse             *workflow.GetProcessInstanceResponse
	processError                error
	processAccessToken          string
	grantResponse               *workflow.GrantProcessInstanceForDownloadFileResponse
	grantError                  error
	withCommentAttachment       bool
}

func (fake *fakeWorkflowAPI) ListProcessInstanceIdsWithOptions(
	request *workflow.ListProcessInstanceIdsRequest,
	headers *workflow.ListProcessInstanceIdsHeaders,
	_ *util.RuntimeOptions,
) (*workflow.ListProcessInstanceIdsResponse, error) {
	fake.listRequest = request
	fake.listAccessToken = value(headers.XAcsDingtalkAccessToken)
	return fake.listResponse, fake.listError
}

func (fake *fakeWorkflowAPI) ListUserVisibleBpmsProcessesWithOptions(
	request *workflow.ListUserVisibleBpmsProcessesRequest,
	headers *workflow.ListUserVisibleBpmsProcessesHeaders,
	_ *util.RuntimeOptions,
) (*workflow.ListUserVisibleBpmsProcessesResponse, error) {
	fake.visibleTemplatesRequest = request
	fake.visibleTemplatesAccessToken = value(headers.XAcsDingtalkAccessToken)
	return fake.visibleTemplatesResponse, fake.visibleTemplatesError
}

func (fake *fakeWorkflowAPI) GetProcessInstanceWithOptions(
	_ *workflow.GetProcessInstanceRequest,
	headers *workflow.GetProcessInstanceHeaders,
	_ *util.RuntimeOptions,
) (*workflow.GetProcessInstanceResponse, error) {
	fake.processAccessToken = value(headers.XAcsDingtalkAccessToken)
	return fake.processResponse, fake.processError
}

func (fake *fakeWorkflowAPI) GrantProcessInstanceForDownloadFileWithOptions(
	request *workflow.GrantProcessInstanceForDownloadFileRequest,
	_ *workflow.GrantProcessInstanceForDownloadFileHeaders,
	_ *util.RuntimeOptions,
) (*workflow.GrantProcessInstanceForDownloadFileResponse, error) {
	fake.withCommentAttachment = request.WithCommentAttatchment != nil &&
		*request.WithCommentAttatchment
	return fake.grantResponse, fake.grantError
}

func staticAppTokenCache(token string) *appTokenCache {
	return newAppTokenCache(
		func(context.Context) (string, time.Duration, error) {
			return token, time.Hour, nil
		},
		time.Now,
		5*time.Minute,
	)
}

func stringPointer(value string) *string {
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}

func int64Value(pointer *int64) int64 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func stringPointers(values ...string) []*string {
	result := make([]*string, 0, len(values))
	for _, item := range values {
		result = append(result, stringPointer(item))
	}
	return result
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return parsed
}

func oapiTestClient(
	roundTrip func(*http.Request) (*http.Response, error),
) *Client {
	return &Client{
		oapiBaseURL: mustURLWithoutTest("https://oapi.dingtalk.com"),
		httpClient:  &http.Client{Transport: roundTripFunc(roundTrip)},
		appTokens:   staticAppTokenCache("app-token"),
	}
}

func mustURLWithoutTest(rawURL string) *url.URL {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsed
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct{}

func (*failingReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (*failingReadCloser) Close() error {
	return nil
}
