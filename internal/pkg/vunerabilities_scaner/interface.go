package vunerabilities_scaner

import "proxy/internal/models"

type UseCase interface {
	GetAllRequests() ([]models.Request, models.StatusCode)
	GetRequest(id int) (models.Request, models.StatusCode)
	RepeatRequest(id int) (models.Response, models.StatusCode)
	Scan(id int) models.StatusCode
}

type Repository interface {
	GetAllRequests() ([]models.Request, models.StatusCode)
	GetRequest(id int) (models.Request, models.StatusCode)
}