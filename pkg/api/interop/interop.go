package interop

import "fmt"

type APIResponse[E any] struct {
	Success bool `json:"success"`
	Data E `json:"data,omitempty"`
	Error *string `json:"error,omitempty"`
}

func NewResponse[E any](data E) *APIResponse[E] {
	return &APIResponse[E]{Success: true, Data: data}
}

func NewErrorResponse(err any) *APIResponse[any] {
	message := fmt.Sprintf("%s", err)
	return &APIResponse[any]{Success: false, Error: &message}
}