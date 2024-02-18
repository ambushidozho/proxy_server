package repo

import (
	"github.com/jackc/pgx"
	"proxy/internal/models"
	"proxy/internal/pkg/vunerabilities_scaner"
	"proxy/internal/pkg/lib"
)

const (
	SelectAllFromRequest = "SELECT id, method, scheme, host, path, cookies, header, body FROM request;"
	SelectOneFromRequest = "SELECT id, method, scheme, host, path, cookies, header, body FROM request WHERE id = $1;"
)
type repoPostgres struct {
	Conn *pgx.ConnPool
}

func NewRepoPostgres(Conn *pgx.ConnPool) vunerabilities_scaner.Repository {
	return &repoPostgres{Conn: Conn}
}

func (r *repoPostgres) GetAllRequests() ([]models.Request, models.StatusCode) {
	requests := make([]models.Request, 0)
	rows, err := r.Conn.Query(SelectAllFromRequest)
	if err != nil {
		return requests, models.NotFound
	}
	defer rows.Close()

	for rows.Next() {
		req := models.Request{}
		header := ""
		err = rows.Scan(&req.Id, &req.Method, &req.Scheme, &req.Host, &req.Path, &req.Cookies, &header, &req.Body)
		if err != nil {
			return requests, models.InternalError
		}
		req.Header = lib.StringToHeader(header)
		requests = append(requests, req)
	}
	return requests, models.Okey
}

func (r *repoPostgres) GetRequest(id int) (models.Request, models.StatusCode) {
	request := models.Request{}
	header := ""

	row := r.Conn.QueryRow(SelectOneFromRequest, id)
	err := row.Scan(&request.Id, &request.Method, &request.Scheme, &request.Host, &request.Path, &request.Cookies, &header, &request.Body)
	if err != nil {
		return models.Request{}, models.NotFound
	}

	request.Header = lib.StringToHeader(header)
	return request, models.Okey
}
