package middleware

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$`)

var validate = func() *validator.Validate {
	v := validator.New()
	// "slug" allows lowercase alphanumerics and hyphens, must start/end with alphanumeric
	_ = v.RegisterValidation("slug", func(fl validator.FieldLevel) bool {
		return slugRe.MatchString(fl.Field().String())
	})
	return v
}()

// DecodeAndValidate decodes JSON body into dst and validates struct tags.
// Returns false and writes error response if decode/validation fails.
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, `{"error":{"code":"BAD_REQUEST","message":"invalid JSON"}}`, http.StatusBadRequest)
		return false
	}
	if err := validate.Struct(dst); err != nil {
		errs := err.(validator.ValidationErrors)
		tagMessages := map[string]string{
			"required": "is required",
			"min":      "is too short",
			"max":      "is too long",
			"email":    "must be a valid email",
			"slug":     "must be lowercase letters, numbers, and hyphens only",
			"alphanum": "must contain only letters and numbers",
		}
		field := errs[0].Field()
		tag := errs[0].Tag()
		friendly, ok := tagMessages[tag]
		if !ok {
			friendly = "is invalid"
		}
		msg := field + " " + friendly
		http.Error(w, `{"error":{"code":"VALIDATION_ERROR","message":"`+msg+`"}}`, http.StatusUnprocessableEntity)
		return false
	}
	return true
}
