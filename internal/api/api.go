// Package api implements the Connect services. NewHandler is the only way to
// mount them (forbidigo), so the authz interceptor cannot be left out.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"google.golang.org/protobuf/types/known/timestamppb"

	"example.com/starter/gen/access/v1/accessv1connect"
	appv1 "example.com/starter/gen/app/v1"
	"example.com/starter/gen/app/v1/appv1connect"
	"example.com/starter/internal/authz"
	"example.com/starter/internal/store"
	"example.com/starter/internal/store/db"
	"example.com/starter/internal/telemetry"
)

type server struct{ st *store.Store }

// NewHandler serves every Connect service, each with the authz and the validation
// interceptor. Mount it at the API root; it answers 404 for paths of no service.
func NewHandler(st *store.Store) http.Handler {
	opts := []connect.HandlerOption{
		// Tracing and logging outermost, so they see authz denials and validation failures.
		connect.WithInterceptors(telemetry.Interceptors()...),
		// Outermost first: authz before validation, so a caller who may not call the method
		// gets Unauthenticated or PermissionDenied, never a violation that shows the rules
		// (TestValidationAfterAuthorization).
		connect.WithInterceptors(authz.NewInterceptor(st.HasPrivilege), validate.NewInterceptor()),
		connect.WithReadMaxBytes(1 << 20),
	}
	services := map[string]http.Handler{}
	for _, mount := range []func() (string, http.Handler){
		func() (string, http.Handler) { return appv1connect.NewAppServiceHandler(server{st}, opts...) },
		func() (string, http.Handler) {
			return accessv1connect.NewAccessServiceHandler(accessServer{st}, opts...)
		},
		// scaffold: services above this line
	} {
		path, h := mount()
		services[path] = h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Connect paths are /<package>.<Service>/<Method>.
		if svc, _, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/"); ok {
			if h, found := services["/"+svc+"/"]; found {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
}

func (s server) WhoAmI(ctx context.Context, _ *connect.Request[appv1.WhoAmIRequest]) (*connect.Response[appv1.WhoAmIResponse], error) {
	res := &appv1.WhoAmIResponse{}
	err := s.withUser(ctx, func(q *db.Queries) error {
		u, err := q.CurrentUser(ctx)
		if err != nil {
			return err
		}
		res.UserId, res.Subject, res.DisplayName, res.Email = u.ID, u.Subject, deref(u.DisplayName), u.Email

		roles, err := q.MyRoles(ctx)
		if err != nil {
			return err
		}
		for _, r := range roles {
			res.Roles = append(res.Roles, &appv1.Role{OrgId: r.OrgID, OrgName: r.OrgName, Role: r.RoleCode, Source: r.Source})
		}

		privs, err := q.MyPrivileges(ctx)
		if err != nil {
			return err
		}
		for _, p := range privs {
			res.Privileges = append(res.Privileges, &appv1.OrgPrivilege{OrgId: p.OrgID, Privilege: p.PrivilegeCode})
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		err = errUnauthenticated // disabled since sign-in: app.current_user_id() is null
	}
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(res), nil
}

func (s server) ListProjects(ctx context.Context, req *connect.Request[appv1.ListProjectsRequest]) (*connect.Response[appv1.ListProjectsResponse], error) {
	size := pageSize(req.Msg.GetPageSize())
	after, err := decodePageToken(req.Msg.GetPageToken())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page_token"))
	}

	res := &appv1.ListProjectsResponse{}
	err = s.withUser(ctx, func(q *db.Queries) error {
		// One extra row tells whether another page exists.
		rows, err := q.ListProjects(ctx, db.ListProjectsParams{
			AfterCreatedAt: after.createdAt, AfterID: after.id, Query: strings.TrimSpace(req.Msg.GetQuery()), PageLimit: size + 1,
		})
		if err != nil {
			return err
		}
		if len(rows) > int(size) {
			rows = rows[:size]
			last := rows[len(rows)-1]
			res.NextPageToken = encodePageToken(last.CreatedAt, last.ID)
		}
		for _, p := range rows {
			res.Projects = append(res.Projects, &appv1.Project{
				Id: p.ID, Name: p.Name, OrgId: p.OrgID, OrgName: p.OrgName, CreatedAt: timestamppb.New(p.CreatedAt), Version: p.Version,
			})
		}
		return nil
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(res), nil
}

func (s server) CreateProject(ctx context.Context, req *connect.Request[appv1.CreateProjectRequest]) (*connect.Response[appv1.CreateProjectResponse], error) {
	var id int64
	err := s.withUser(ctx, func(q *db.Queries) (err error) {
		// Length and org scope are checked by the database (CHECK constraint, RLS WITH CHECK).
		id, err = q.CreateProject(ctx, db.CreateProjectParams{OrgID: req.Msg.GetOrgId(), Name: strings.TrimSpace(req.Msg.GetName())})
		return err
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&appv1.CreateProjectResponse{Id: id}), nil
}

// UpdateProject renames a project if it is still at the version the caller read.
func (s server) UpdateProject(ctx context.Context, req *connect.Request[appv1.UpdateProjectRequest]) (*connect.Response[appv1.UpdateProjectResponse], error) {
	m := req.Msg
	var version int64
	err := s.withUser(ctx, func(q *db.Queries) error {
		// Locked only if the caller may update it (RLS); the lock keeps the check and the
		// update together. lock_timeout bounds the wait.
		current, err := q.LockProject(ctx, m.GetId())
		if err != nil {
			return err
		}
		if current != m.GetVersion() {
			return errStale
		}
		version, err = q.RenameProject(ctx, db.RenameProjectParams{ID: m.GetId(), Name: strings.TrimSpace(m.GetName())})
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		err = store.ErrForbidden // missing, not visible or not writable: the caller cannot tell which
	}
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&appv1.UpdateProjectResponse{Version: version}), nil
}

func (s server) withUser(ctx context.Context, fn func(*db.Queries) error) error {
	uid, ok := authz.UserID(ctx)
	if !ok {
		return errUnauthenticated
	}
	return s.st.WithUser(ctx, uid, fn)
}

var (
	errUnauthenticated = errors.New("no user in context")
	errNotFound        = errors.New("not found")
	errAlreadyExists   = errors.New("already exists")
	errStale           = errors.New("changed since the caller read it")
)

// toConnect keeps database details out of responses.
func toConnect(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	case errors.Is(err, store.ErrForbidden):
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	case errors.Is(err, store.ErrInvalid):
		return invalidInput(err) // a mapped constraint arrives at its field (constraints.go)
	case errors.Is(err, errStale):
		return connect.NewError(connect.CodeAborted, errors.New("changed by someone else; reload and try again"))
	case errors.Is(err, errNotFound), errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("not found"))
	case errors.Is(err, errAlreadyExists):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("already exists"))
	default:
		slog.ErrorContext(ctx, "request failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
