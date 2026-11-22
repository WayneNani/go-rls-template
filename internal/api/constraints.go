package api

import (
	"errors"

	validatepb "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"example.com/starter/internal/store"
)

// fieldViolation is what the caller sees when a named database constraint fails: the request
// field (as in the proto) and a message in protovalidate's style (lower case, no full stop).
type fieldViolation struct{ field, message string }

// constraintFields maps constraints in schema app to the request field they belong to. The
// violation arrives like a protovalidate one, so the UI shows it at the field (fieldErrors).
// TestEveryConstraintIsMapped: every constraint the app can trigger is here or in
// constraintsNotUserFacing, and every name here exists.
var constraintFields = map[string]fieldViolation{
	"projects_org_id_name_key": {"name", "a project with this name already exists"},
	"projects_name_check":      {"name", "must be 1 to 100 characters"}, // also a proto rule
	// Roles are data: the proto checks only the shape of the code (GrantRole, AddGroupMapping).
	"role_assignments_role_code_fkey":        {"role", "no such role"},
	"idp_group_role_mappings_role_code_fkey": {"role", "no such role"},
	// scaffold: constraint fields above this line
}

// constraintsNotUserFacing can fail only through a bug, never through a caller's input: the
// reason says what stops it first. Such a violation stays a generic "invalid input".
var constraintsNotUserFacing = map[string]string{
	"projects_pkey":                       "identity column",
	"projects_org_id_fkey":                "RLS WITH CHECK (project.write in that org) fails first for an unknown org",
	"role_assignments_pkey":               "GrantRole inserts with on conflict do nothing (AlreadyExists)",
	"role_assignments_org_id_fkey":        "requireManager fails first for an unknown org",
	"role_assignments_user_id_fkey":       "the user id comes from FindUserByEmail",
	"role_assignments_source_check":       "the queries set source",
	"idp_group_role_mappings_pkey":        "AddGroupMapping inserts with on conflict do nothing",
	"idp_group_role_mappings_org_id_fkey": "requireManager fails first for an unknown org",
	"sessions_pkey":                       "scs upserts by token",
	// scaffold: constraints not user-facing above this line
}

// invalidInput answers store.ErrInvalid. Only the mapped field and message leave the server,
// never the database's message or the constraint name.
func invalidInput(err error) *connect.Error {
	v, ok := constraintFields[store.ConstraintName(err)]
	if !ok {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid input"))
	}
	return fieldError(v.field, v.message)
}

// fieldError is an InvalidArgument the UI shows at the request field, in protovalidate's format.
// Also for checks a proto rule cannot express (a date that does not exist, e.g. 2026-02-30).
func fieldError(field, message string) *connect.Error {
	cerr := connect.NewError(connect.CodeInvalidArgument, errors.New("invalid input"))
	detail, derr := connect.NewErrorDetail(&validatepb.Violations{Violations: []*validatepb.Violation{{
		Field:   &validatepb.FieldPath{Elements: []*validatepb.FieldPathElement{{FieldName: proto.String(field)}}},
		Message: proto.String(message),
	}}})
	if derr == nil {
		cerr.AddDetail(detail)
	}
	return cerr
}
