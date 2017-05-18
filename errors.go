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
)

var (
	//ErrNoRowsInserted is used when there were not any rows inserted into the table
	ErrNoRowsInserted = errors.New("No rows were inserted")
	//ErrNoRowsUpdated is used when there were not any rows updated in the table
	ErrNoRowsUpdated = errors.New("No rows were updated")
	//ErrGenericVars is used when the error is too generic
	ErrGenericVars = errors.New("Something went wrong")
)

//Errs is a list of our errors making it easier to pass as a single paramenter and easier consumption
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

//Err is an error that occured inside the vars package
type Err struct {
	parents []string
	err     error
}

//Creates a new VARS error based on the type
func newErr(errT errType, parents ...string) Err {
	err := new(Err)
	err.parents = parents
	switch errT {
	case noRowsInserted:
		err.err = ErrNoRowsInserted
	case noRowsUpdated:
		err.err = ErrNoRowsUpdated
	default:
		err.err = ErrGenericVars
	}
	return *err
}

//Creates a new VARS error using the error given
//If the error given was already a VARS error Prepend the parents and don't change the error
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

//Error impliments the error interface
func (e Err) Error() string {
	return fmt.Sprintf("VARS: %s: %s", strings.Join(e.parents, ": "), e.err.Error())
}

//IsNoRowsError returns true if the error is caused by no rows being effected
func (e Err) IsNoRowsError() bool {
	if e.err.Error() == ErrNoRowsInserted.Error() || e.err.Error() == ErrNoRowsUpdated.Error() {
		return true
	}
	return false
}

//IsNoRowsError returns true if the error is caused by no rows being effected
func IsNoRowsError(err error) bool {
	if varsErr, ok := err.(Err); ok {
		return varsErr.IsNoRowsError()
	}
	return false
}
