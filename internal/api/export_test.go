package api

// MappedConstraints exposes the constraint tables of constraints.go to the api_test package:
// constraint name -> request field, and constraint name -> reason it is not user-facing.
func MappedConstraints() (fields, notUserFacing map[string]string) {
	fields = map[string]string{}
	for name, v := range constraintFields {
		fields[name] = v.field
	}
	return fields, constraintsNotUserFacing
}
