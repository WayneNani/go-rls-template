package api

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"

	accessv1 "example.com/starter/gen/access/v1"
	"example.com/starter/internal/store"
	"example.com/starter/internal/store/db"
)

// accessServer implements AccessService. The authz interceptor checks access.manage in
// any org; requireManager narrows that to the requested org, and the RLS policies of
// migration 00004 enforce the guards (no self-changes, no escalation, IdP roles read-only).
type accessServer struct{ st *store.Store }

func (s accessServer) withUser(ctx context.Context, fn func(*db.Queries) error) error {
	return server(s).withUser(ctx, fn)
}

// requireManager fails unless the caller holds access.manage in this org.
func requireManager(ctx context.Context, q *db.Queries, orgID int64) error {
	ok, err := q.HasPrivilegeIn(ctx, db.HasPrivilegeInParams{Privilege: "access.manage", OrgID: orgID})
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrForbidden
	}
	return nil
}

func (s accessServer) ListRoles(ctx context.Context, _ *connect.Request[accessv1.ListRolesRequest]) (*connect.Response[accessv1.ListRolesResponse], error) {
	res := &accessv1.ListRolesResponse{}
	err := s.withUser(ctx, func(q *db.Queries) error {
		rows, err := q.ListRoleCatalog(ctx)
		for _, r := range rows {
			res.Roles = append(res.Roles, &accessv1.RoleDefinition{Code: r.Code, Privileges: r.Privileges})
		}
		return err
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(res), nil
}

func (s accessServer) ListMembers(ctx context.Context, req *connect.Request[accessv1.ListMembersRequest]) (*connect.Response[accessv1.ListMembersResponse], error) {
	size := pageSize(req.Msg.GetPageSize())
	after, err := decodeIDToken(req.Msg.GetPageToken())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page_token"))
	}
	res := &accessv1.ListMembersResponse{}
	err = s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, req.Msg.GetOrgId()); err != nil {
			return err
		}
		rows, err := q.ListMembers(ctx, db.ListMembersParams{
			OrgID: req.Msg.GetOrgId(), AfterID: after, Query: strings.TrimSpace(req.Msg.GetQuery()), PageLimit: size + 1,
		})
		if err != nil {
			return err
		}
		if len(rows) > int(size) {
			rows = rows[:size]
			res.NextPageToken = encodeIDToken(rows[len(rows)-1].ID)
		}
		// Emails only for the rows returned: each call is one READ row in the audit log.
		ids := make([]int64, len(rows))
		for i, m := range rows {
			ids[i] = m.ID
		}
		found, err := q.UserEmails(ctx, ids)
		if err != nil {
			return err
		}
		emails := make(map[int64]string, len(found))
		for _, e := range found {
			emails[e.UserID] = e.Email
		}
		for _, m := range rows {
			member := &accessv1.Member{UserId: m.ID, Subject: m.Subject, Email: emails[m.ID], DisplayName: deref(m.DisplayName)}
			for i, role := range m.Roles {
				member.Roles = append(member.Roles, &accessv1.MemberRole{Role: role, Source: m.Sources[i]})
			}
			res.Members = append(res.Members, member)
		}
		return nil
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(res), nil
}

func (s accessServer) GrantRole(ctx context.Context, req *connect.Request[accessv1.GrantRoleRequest]) (*connect.Response[accessv1.GrantRoleResponse], error) {
	m := req.Msg
	err := s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, m.GetOrgId()); err != nil {
			return err
		}
		userID, err := q.FindUserByEmail(ctx, strings.TrimSpace(m.GetEmail()))
		if err != nil {
			return err
		}
		if userID == 0 {
			return errNotFound // no such user, or the user has never signed in
		}
		// Self-grants, other IdPs and escalation fail the RLS WITH CHECK -> permission denied.
		n, err := q.GrantRole(ctx, db.GrantRoleParams{UserID: userID, RoleCode: m.GetRole(), OrgID: m.GetOrgId()})
		if err == nil && n == 0 {
			return errAlreadyExists // held already, locally or through an IdP group
		}
		return err
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&accessv1.GrantRoleResponse{}), nil
}

func (s accessServer) RevokeRole(ctx context.Context, req *connect.Request[accessv1.RevokeRoleRequest]) (*connect.Response[accessv1.RevokeRoleResponse], error) {
	m := req.Msg
	err := s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, m.GetOrgId()); err != nil {
			return err
		}
		n, err := q.RevokeRole(ctx, db.RevokeRoleParams{OrgID: m.GetOrgId(), UserID: m.GetUserId(), RoleCode: m.GetRole()})
		if err == nil && n == 0 {
			return store.ErrForbidden // missing, IdP-sourced, your own, or beyond your privileges
		}
		return err
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&accessv1.RevokeRoleResponse{}), nil
}

func (s accessServer) ListGroupMappings(ctx context.Context, req *connect.Request[accessv1.ListGroupMappingsRequest]) (*connect.Response[accessv1.ListGroupMappingsResponse], error) {
	size := pageSize(req.Msg.GetPageSize())
	afterGroup, afterRole, err := decodeKeyToken(req.Msg.GetPageToken())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page_token"))
	}
	res := &accessv1.ListGroupMappingsResponse{}
	err = s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, req.Msg.GetOrgId()); err != nil {
			return err
		}
		rows, err := q.ListGroupMappings(ctx, db.ListGroupMappingsParams{
			OrgID: req.Msg.GetOrgId(), AfterGroupID: afterGroup, AfterRoleCode: afterRole, PageLimit: size + 1,
		})
		if err != nil {
			return err
		}
		if len(rows) > int(size) {
			rows = rows[:size]
			last := rows[len(rows)-1]
			res.NextPageToken = encodeKeyToken(last.GroupID, last.RoleCode)
		}
		for _, r := range rows {
			res.Mappings = append(res.Mappings, &accessv1.GroupMapping{GroupId: r.GroupID, Role: r.RoleCode})
		}
		return nil
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(res), nil
}

func (s accessServer) AddGroupMapping(ctx context.Context, req *connect.Request[accessv1.AddGroupMappingRequest]) (*connect.Response[accessv1.AddGroupMappingResponse], error) {
	m := req.Msg
	group := strings.TrimSpace(m.GetGroupId()) // not blank: the request rules check it
	err := s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, m.GetOrgId()); err != nil {
			return err
		}
		return q.AddGroupMapping(ctx, db.AddGroupMappingParams{GroupID: group, RoleCode: m.GetRole(), OrgID: m.GetOrgId()})
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&accessv1.AddGroupMappingResponse{}), nil
}

func (s accessServer) RemoveGroupMapping(ctx context.Context, req *connect.Request[accessv1.RemoveGroupMappingRequest]) (*connect.Response[accessv1.RemoveGroupMappingResponse], error) {
	m := req.Msg
	err := s.withUser(ctx, func(q *db.Queries) error {
		if err := requireManager(ctx, q, m.GetOrgId()); err != nil {
			return err
		}
		n, err := q.RemoveGroupMapping(ctx, db.RemoveGroupMappingParams{OrgID: m.GetOrgId(), GroupID: m.GetGroupId(), RoleCode: m.GetRole()})
		if err == nil && n == 0 {
			return store.ErrForbidden // missing or beyond your privileges
		}
		return err
	})
	if err != nil {
		return nil, toConnect(ctx, err)
	}
	return connect.NewResponse(&accessv1.RemoveGroupMappingResponse{}), nil
}
