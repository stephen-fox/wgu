package ini

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Schema specifies how to parse an INI blob.
//
// Refer to the INI type for an example implementation.
type Schema interface {
	// Rules returns the ParserRules that the parser
	// should abide by.
	Rules() ParserRules

	// OnGlobalParam is called when the parser encounters
	// a global parameter. If the global parameter is known,
	// a non-nil function pointer should be returned which
	// parses the Param and stores it as desired by the caller.
	//
	// The returned SchemaRule dictates how to handle the
	// global parameter prior to calling the function pointer.
	//
	// A nil function pointer indicates that the parameter
	// is unknown, which is then handled by the rules
	// specified by ParserRules.
	OnGlobalParam(paramName string) (func(*Param) error, SchemaRule)

	// OnSection is called when the parser encounters a section.
	// If the section is known, a non-nil function pointer
	// should be returned which constructs a new SectionSchema.
	//
	// The returned SchemaRule dictates how to handle the
	// section prior to calling the function pointer.
	//
	// A nil function pointer indicates that the section
	// is unknown, which is then handled by the rules
	// specified by ParserRules.
	OnSection(sectionName string) (func(name string) (SectionSchema, error), SchemaRule)

	// Validate is called by the parser when the
	// parser finishes parsing the INI blob.
	Validate() error
}

// ParserRules tells the parser how to handle several possible
// scenarios while parsing an INI blob.
type ParserRules struct {
	// AllowGlobalParams tells the parser to allow global
	// parameters if set to true.
	AllowGlobalParams bool

	// AllowUnknownGlobalParams tells the parser to allow
	// unknown global parameters if set to true.
	AllowUnknownGlobalParams bool

	// AllowUnknownSections tells the parser to allow
	// unknown sections if set to true.
	AllowUnknownSections bool

	// AllowUnknownParams tells the parser to allow
	// unknown parameters if set to true.
	AllowUnknownParams bool

	// LowercaseNames tells the parser to provide
	// section and parameters in lowercase when
	// calling *Schema functions if set to true.
	//
	// The original string is passed to each
	// respective constructor function returned
	// by the *Schema function.
	LowercaseNames bool

	// RequiredGlobalParams contains the required
	// global parameters (if any).
	//
	// A nil map means no global parameters
	// are required.
	RequiredGlobalParams map[string]struct{}

	// RequiredSections contains the required
	// sections (if any).
	//
	// A nil map means no sections are required.
	RequiredSections map[string]struct{}
}

// SchemaRule configures individual schema requirements.
type SchemaRule struct {
	// Limit is the maximum number of instances permitted for this
	// entity. A value of zero means no limit.
	//
	// For example, a value of one means only one instance of this
	// entity is allowed.
	Limit int
}

// SectionSchema specifies how to parse a section in an INI blob.
//
// Refer to Section for an example implementation.
type SectionSchema interface {
	// RequiredParams are the parameters required for this section
	// (if any).
	//
	// nil can be returned if no parameters are required.
	RequiredParams() map[string]struct{}

	// OnParam returns a constructor function pointer
	// and SchemaRule for the named parameter.
	//
	// Returning a nil function pointer tells the parser
	// that the parameter is unknown.
	//
	// Refer to ParserRules for configuring handling of
	// unknown parameters.
	OnParam(paramName string) (func(*Param) error, SchemaRule)

	// Validate is called when the parser finishes parsing
	// the current section.
	Validate() error
}

// ParseSchema parses an INI blob from an io.Reader according to the
// provided Schema.
//
// The Parse function serves as an alternative for cases where minimal
// data processing is required.
func ParseSchema(r io.Reader, schema Schema) error {
	p := newParser(schema)

	return p.parse(r)
}

func newParser(schema Schema) *parser {
	rules := schema.Rules()

	mangleNameFn := func(name string) string {
		return name
	}

	if rules.LowercaseNames {
		mangleNameFn = strings.ToLower
	}

	return &parser{
		schema:       schema,
		rules:        rules,
		mangleNameFn: mangleNameFn,
		seenGlobals:  make(map[string]int),
		seenSections: make(map[string]int),
	}
}

type parser struct {
	schema       Schema
	rules        ParserRules
	mangleNameFn func(name string) string

	line            int
	currSectionLine int
	currSectionName string
	currSectionObj  SectionSchema

	seenGlobals           map[string]int
	seenSections          map[string]int
	seenCurrSectionParams map[string]int
}

func (o *parser) parse(r io.Reader) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		o.line++

		withoutSpaces := bytes.TrimSpace(scanner.Bytes())

		if len(withoutSpaces) == 0 || withoutSpaces[0] == '#' {
			continue
		}

		if withoutSpaces[0] == '[' {
			if len(o.seenSections) == 0 {
				// Global params finished.
				for required := range o.rules.RequiredGlobalParams {
					_, hasIt := o.seenGlobals[required]
					if !hasIt {
						return fmt.Errorf("missing required global param: %q",
							required)
					}
				}
			}

			err := o.startSection(withoutSpaces)
			if err != nil {
				return err
			}

			continue
		}

		if len(o.seenSections) > 0 && o.currSectionObj == nil {
			// Unknown section which was permitted by user.
			continue
		}

		paramName, paramValue, err := parseParamLine(withoutSpaces)
		if err != nil {
			return fmt.Errorf("line %d - failed to parse line - %w", o.line, err)
		}

		mangledName := o.mangleNameFn(paramName)

		if o.currSectionObj == nil {
			err := o.globalParam(mangledName, paramName, paramValue)
			if err != nil {
				return err
			}
		} else {
			err := o.param(mangledName, paramName, paramValue)
			if err != nil {
				return err
			}
		}
	}

	err := scanner.Err()
	if err != nil {
		return err
	}

	// This is needed because the final section will not
	// fall down the code path leading to the validation
	// function.
	err = o.validateCurrentSection()
	if err != nil {
		return err
	}

	for required := range o.rules.RequiredSections {
		_, hasIt := o.seenSections[required]
		if !hasIt {
			return fmt.Errorf("missing required section: %q", required)
		}
	}

	err = o.schema.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate config - %w", err)
	}

	return nil
}

func (o *parser) startSection(withoutSpaces []byte) error {
	name, err := parseSectionLine(withoutSpaces)
	if err != nil {
		return fmt.Errorf("line %d - failed to parse section header - %w",
			o.line, err)
	}

	mangledName := o.mangleNameFn(name)

	o.seenSections[mangledName]++

	// Validate last section before starting this one.
	err = o.validateCurrentSection()
	if err != nil {
		return err
	}

	newSectionFn, rule := o.schema.OnSection(mangledName)
	if newSectionFn == nil {
		if o.rules.AllowUnknownSections {
			o.currSectionObj = nil
			return nil
		} else {
			return fmt.Errorf("line %d - unknown section: %q",
				o.line, name)
		}
	}

	numInstances := o.seenSections[mangledName]
	if rule.Limit > 0 && numInstances > rule.Limit {
		if rule.Limit == 1 {
			return fmt.Errorf("line %d - %q section can only be specified once",
				o.line, name)
		}

		return fmt.Errorf("line %d - only %d %q sections may be specified (current is %d)",
			o.line, rule.Limit, name, numInstances)
	}

	o.currSectionObj, err = newSectionFn(name)
	if err != nil {
		return fmt.Errorf("line %d - failed to initialize section object: %q - %w",
			o.line, name, err)
	}

	o.currSectionLine = o.line
	o.currSectionName = name
	o.seenCurrSectionParams = make(map[string]int)

	return nil
}

func (o *parser) globalParam(mangledName string, paramName string, paramValue string) error {
	if !o.rules.AllowGlobalParams {
		return fmt.Errorf("line %d - global parameters are not supported", o.line)
	}

	paramSchemaFn, rule := o.schema.OnGlobalParam(mangledName)
	if paramSchemaFn == nil && !o.rules.AllowUnknownGlobalParams {
		return fmt.Errorf("line %d - unknown global parameter: %q",
			o.line, paramName)
	}

	o.seenGlobals[mangledName]++

	numInst := o.seenGlobals[mangledName]
	if rule.Limit > 0 && numInst > rule.Limit {
		if rule.Limit == 1 {
			return fmt.Errorf("line %d - %q global param can only be specified once",
				o.line, paramName)
		}

		return fmt.Errorf("line %d - only %d %q global params may be specified (current is %d)",
			o.line, rule.Limit, paramName, numInst)
	}

	err := paramSchemaFn(&Param{
		Name:  paramName,
		Value: paramValue,
	})
	if err != nil {
		return fmt.Errorf("line %d - failed to set global param %q - %w",
			o.line, paramName, err)
	}

	return nil
}

func (o *parser) param(mangledName string, paramName string, paramValue string) error {
	paramSchemaFn, rule := o.currSectionObj.OnParam(mangledName)

	if paramSchemaFn == nil && !o.rules.AllowUnknownParams {
		return fmt.Errorf("line %d - unknown parameter: %q",
			o.line, paramName)
	}

	o.seenCurrSectionParams[mangledName]++

	numInst := o.seenCurrSectionParams[mangledName]
	if rule.Limit > 0 && numInst > rule.Limit {
		if rule.Limit == 1 {
			return fmt.Errorf("line %d - %q param can only be specified once",
				o.line, paramName)
		}

		return fmt.Errorf("line %d - only %d %q params may be specified (current is %d)",
			o.line, rule.Limit, paramName, numInst)
	}

	err := paramSchemaFn(&Param{
		Name:  paramName,
		Value: paramValue,
	})
	if err != nil {
		return fmt.Errorf("line %d - failed to set param %q - %w",
			o.line, paramName, err)
	}

	return nil
}

func (o *parser) validateCurrentSection() error {
	if o.currSectionObj == nil {
		return nil
	}

	for required := range o.currSectionObj.RequiredParams() {
		_, hasIt := o.seenCurrSectionParams[required]
		if !hasIt {
			return fmt.Errorf("line %d - section %q is missing required param: %q",
				o.currSectionLine, o.currSectionName, required)
		}
	}

	err := o.currSectionObj.Validate()
	if err != nil {
		return fmt.Errorf("line %d - failed to validate section: %q - %w",
			o.currSectionLine, o.currSectionName, err)
	}

	return nil
}

func parseSectionLine(line []byte) (string, error) {
	if len(line) < 2 {
		return "", errors.New("invalid section header length")
	}

	if line[0] != '[' {
		return "", errors.New("section header does not start with '['")
	}

	if line[len(line)-1] != ']' {
		return "", errors.New("section header does not end with ']'")
	}

	line = bytes.TrimSpace(line[1 : len(line)-1])

	if len(line) == 0 {
		return "", errors.New("section name is empty")
	}

	return string(line), nil
}

func parseParamLine(line []byte) (string, string, error) {
	if !bytes.Contains(line, []byte{'='}) {
		return string(line), "", nil
	}

	parts := bytes.SplitN(line, []byte("="), 2)

	switch len(parts) {
	case 0:
		return "", "", errors.New("line is empty")
	case 1:
		return "", "", errors.New("line is missing value")
	}

	param := bytes.TrimSpace(parts[0])
	value := bytes.TrimSpace(parts[1])

	switch {
	case len(param) == 0:
		return "", "", errors.New("parameter name is empty")
	case len(value) == 0:
		return "", "", errors.New("parameter value is empty")
	}

	return string(param), string(value), nil
}
