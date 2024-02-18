package delivery

import (
	"net/http"
	"proxy/internal/models"
	"proxy/internal/pkg/vunerabilities_scaner"
	"proxy/internal/pkg/vunerabilities_scaner/middleware"
	"strconv"

	"github.com/gorilla/mux"
)

type Handler struct {
	usecase vunerabilities_scaner.UseCase
}

func NewRepeaterHandler(RepeaterUseCase vunerabilities_scaner.UseCase) *Handler {
	return &Handler{usecase: RepeaterUseCase}
}

func (h *Handler) AllRequests(w http.ResponseWriter, r *http.Request) {
	requests, status := h.usecase.GetAllRequests()
	middleware.Response(w, status, requests)
}
func (h *Handler) GetRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ids, found := vars["id"]
	if !found {
		middleware.Response(w, models.NotFound, nil)
		return
	}
	id, err := strconv.Atoi(ids)
	if err != nil {
		middleware.Response(w, models.InternalError, nil)
		return
	}

	requests, status := h.usecase.GetRequest(id)
	middleware.Response(w, status, requests)
}

func (h *Handler) RepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ids, found := vars["id"]
	if !found {
		middleware.Response(w, models.NotFound, nil)
		return
	}
	id, err := strconv.Atoi(ids)
	if err != nil {
		middleware.Response(w, models.InternalError, nil)
		return
	}

	response, status := h.usecase.RepeatRequest(id)
	middleware.Response(w, status, response)
}

func (h *Handler) Scan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ids, found := vars["id"]
	if !found {
		middleware.Response(w, models.NotFound, nil)
		return
	}
	id, err := strconv.Atoi(ids)
	if err != nil {
		middleware.Response(w, models.InternalError, nil)
		return
	}
	status := h.usecase.Scan(id)
	if status == models.VunerabilityFound {
		middleware.Response(w, models.VunerabilityFound, "Vunerability found")
		return
	}
	middleware.Response(w, status, "Vunerability not found")
}
