package modelRbac

import (
	"github.com/gorilla/mux"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gobuffalo/buffalo"
	"github.com/pkg/errors"
)

// RoleGetter must return the role of the user who made the request
type RoleGetter func(buffalo.Context) (string, error)

// New enables cashbin rbac
func Authorize(e *casbin.Enforcer, r RoleGetter) buffalo.MiddlewareFunc {
	return func(next buffalo.Handler) buffalo.Handler {
		return func(c buffalo.Context) error {
			role, err := r(c)
			if err != nil {
				return errors.WithStack(err)
			}

			muxHandler := mux.CurrentRoute(c.Request()).GetHandler().(*buffalo.RouteInfo)

			resourceName := ""
			if muxHandler.ResourceName != "" {
				resourceName = strings.Split(muxHandler.ResourceName, "Resource")[0]
			}

			actionName := ""
			if muxHandler.HandlerName != "" {
				actionName = strings.Split(muxHandler.HandlerName, "/actions.")[1]
			}

			res, err := e.Enforce(role, resourceName, actionName)
			if err != nil {
				return errors.WithStack(err)
			}
			if res {
				return next(c)
			}

			return c.Error(http.StatusUnauthorized, errors.New("You are unauthorized to perform the requested action"))
		}
	}
}
