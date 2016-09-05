package helpers

// APIError defines a standard format for API errors.
type APIError struct {
	// The status code.
	Status int `json:"status"`
	// The description of the API error.
	Description string `json:"description"`
	// The token uniquely identifying the API error.
	ErrorCode string `json:"errorCode"`
	// Additional infos.
	Params map[string]interface{} `json:"params,omitempty"`
}

var (
	APIInternal = APIError{
		Status:      500,
		Description: "An internal error occured. Please retry later.",
		ErrorCode:   "INTERNAL_ERROR",
	}
	APIUnavailable = APIError{
		Status:      503,
		Description: "The service is currently unavailable. Please retry later.",
		ErrorCode:   "SERVICE_UNAVAILABLE",
	}
	APIBodyDecoding = APIError{
		Status:      400,
		Description: "Could not decode the JSON request.",
		ErrorCode:   "BODY_DECODING_ERROR",
	}
	APIUnauthorized = APIError{
		Status:      401,
		Description: "Authorization Required.",
		ErrorCode:   "AUTHORIZATION_REQUIRED",
	}
	APIForbidden = APIError{
		Status:      403,
		Description: "The specified resource was not found or you don't have sufficient permissions.",
		ErrorCode:   "FORBIDDEN",
	}
	APIValidation = APIError{
		Status:      422,
		Description: "The parameter validation failed.",
		ErrorCode:   "VALIDATION_ERROR",
	}
)
