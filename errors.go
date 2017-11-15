package vars

import (
	"errors"
	"fmt"
	"strings"
)

type errType int

const (
	noRowsInserted errType = iota
	noRowsUpdated
	nameNotAvailable
	unknownType
	genericVars
)

var (
	//ErrNoRowsInserted is used when there were not any rows inserted into the table
	ErrNoRowsInserted = errors.New("No rows were inserted")
	//ErrNoRowsUpdated is used when there were not any rows updated in the table
	ErrNoRowsUpdated = errors.New("No rows were updated")
	//ErrNameNotAvailable is used when the provided vulnnerability name is not available
	ErrNameNotAvailable = errors.New("The provided vulnerability name is not available")
	//ErrUknownType is used for the default case of the type switch
	ErrUnknownType = errors.New("The interface type is not supported")
	//ErrGenericVars is used when the error is too generic
	ErrGenericVars = errors.New("Something went wrong")
)

// Err is an error that occured inside the vars package
type Err struct {
	parents []string
	err     error
}

// Creates a new VARS error based on the type
func newErr(errT errType, parents ...string) Err {
	err := new(Err)
	err.parents = parents
	switch errT {
	case noRowsInserted:
		err.err = ErrNoRowsInserted
	case noRowsUpdated:
		err.err = ErrNoRowsUpdated
	case nameNotAvailable:
		err.err = ErrNameNotAvailable
	case unknownType:
		err.err = ErrUnknownType
	default:
		err.err = ErrGenericVars
	}
	return *err
}

// Creates a new VARS error using the error given
// If the error given was already a VARS error Prepend the parents and don't change the error
func newErrFromErr(err error, parents ...string) Err {
	if varsErr, ok := err.(Err); ok {
		return Err{
			parents: append(parents, varsErr.parents...),
			err:     varsErr.err,
		}
	}
	return Err{
		parents: parents,
		err:     err,
	}
}

// Error impliments the error interface
func (e Err) Error() string {
	return fmt.Sprintf("VARS: %s: %s", strings.Join(e.parents, ": "), e.err.Error())
}

// IsNoRowsError returns true if the error is caused by no rows being effected
func (e Err) IsNoRowsError() bool {
	if e.err.Error() == ErrNoRowsInserted.Error() || e.err.Error() == ErrNoRowsUpdated.Error() {
		return true
	}
	return false
}

// IsNoRowsError returns true if the error is caused by no rows being effected
func IsNoRowsError(err error) bool {
	if varsErr, ok := err.(Err); ok {
		return varsErr.IsNoRowsError()
	}
	return false
}

// IsNilErr type asserts the provided error (error, Err, Errs) and returns true if the error is nil,
// false otherwise.
func IsNilErr(e interface{}) bool {
	if e == nil {
		return true
	} else if ve, ok := e.(Err); ok {
		return ve.err == nil
	} else if ves, ok := e.(Errs); ok {
		if len(ves) == 0 {
			return true
		}
		for v := range ves {
			if !IsNilErr(v) {
				return false
			}
		}
		return true
	} else if er, ok := e.(error); ok {
		return er == nil
	}
	return false
}

// Errs is a list of our errors making it easier to pass as a single paramenter and easier consumption
type Errs []Err

func (es Errs) Error() string {
	var errStrings []string
	for _, e := range es {
		errStrings = append(errStrings, e.Error())
	}
	return strings.Join(errStrings, "\n")
}

func (es Errs) append(errT errType, parents ...string) {
	es = append(es, newErr(errT, parents...))
}

func (es Errs) appendFromError(err error, parents ...string) {
	es = append(es, newErrFromErr(err, parents...))
}

func (es Errs) appendFromErrs(errs Errs) {
	for _, er := range errs {
		es.appendFromError(er.err, er.parents...)
	}
}
