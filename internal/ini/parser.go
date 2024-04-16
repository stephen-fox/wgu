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
	// ParserRules returns the ParserRules that the parser
	// should abide by.
	ParserRules() ParserRules

	// GlobalParamSchema is called when the parser encounters
	// a global parameter. If the global parameter is known,
	// a non-nil function pointer should be returned which will
	// parse the Param and add it.
	//
	// The returned SchemaRule dictates how to handle the
	// global parameter prior to calling the function pointer.
	//
	// A nil function pointer indicates that the parameter
	// is unknown, which is then handled by the rules
	// specified by ParserRules.
	GlobalParamSchema(paramName string) (func(*Param) error, SchemaRule)

	// SectionSchema is called when the parser encounters
	// a section. If the section is known, a non-nil function
	// pointer should be returned which will construct a new
	// SectionSchema.
	//
	// The returned SchemaRule dictates how to handle the
	// section prior to calling the function pointer.
	//
	// A nil function pointer indicates that the section
	// is unknown, which is then handled by the rules
	// specified by ParserRules.
	SectionSchema(sectionName string) (func(name string) (SectionSchema, error), SchemaRule)

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
	// unknown sections.
	AllowUnknownSections bool

	// AllowUnknownParam tells the parser to allow
	// unknown parameters.
	AllowUnknownParams bool

	// LowercaseNames tells the parser to provide
	// section and parameters in lowercase when
	// calling *Schema functions.
	//
	// The original string is passed to each
	// respective constructor function returned
	// by the *Schema function.
	LowercaseNames bool

	// RequiredGlobalParms contains the required
	// global parameters (if any).
	//
	// The map can be set to nil if no global parameters
	// are required.
	RequiredGlobalParms map[string]struct{}

	// RequiredSections contains the required
	// sections (if any).
	//
	// The map can be set to nil if no sections
	// are required.
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

	// ParamSchema returns a constructor function pointer
	// and SchemaRule for the named parameter.
	//
	// Returning a nil function pointer tells the parser that
	// the parameter is unknown.
	//
	// Refer to ParserRules for configuring handling of
	// unknown parameters.
	ParamSchema(paramName string) (func(*Param) error, SchemaRule)

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
	line := 0

	rules := schema.ParserRules()

	mangleNameFn := func(name string) string {
		return name
	}

	if rules.LowercaseNames {
		mangleNameFn = strings.ToLower
	}

	var currSectionLine int
	var currSectionName string
	var currSectionObj SectionSchema

	seenGlobals := make(map[string]int)
	seenSections := make(map[string]int)
	var seenCurrSectionParams map[string]int

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line++

		withoutSpaces := bytes.TrimSpace(scanner.Bytes())

		if len(withoutSpaces) == 0 || withoutSpaces[0] == '#' {
			continue
		}

		if withoutSpaces[0] == '[' {
			if len(seenSections) == 0 {
				// Global params finished.
				for required := range rules.RequiredGlobalParms {
					_, hasIt := seenGlobals[required]
					if !hasIt {
						return fmt.Errorf("missing required global param: %q",
							required)
					}
				}
			}

			name, err := parseSectionLine(withoutSpaces)
			if err != nil {
				return fmt.Errorf("line %d - failed to parse section header - %w",
					line, err)
			}

			mangledName := mangleNameFn(name)

			seenSections[mangledName]++

			if currSectionObj != nil {
				for required := range currSectionObj.RequiredParams() {
					_, hasIt := seenCurrSectionParams[required]
					if !hasIt {
						return fmt.Errorf("line %d - section %q is missing required param: %q",
							currSectionLine, currSectionName, required)
					}
				}

				err := currSectionObj.Validate()
				if err != nil {
					return fmt.Errorf("line %d - failed to validate section: %q - %w",
						currSectionLine, currSectionName, err)
				}
			}

			newSectionFn, rule := schema.SectionSchema(mangledName)
			if newSectionFn == nil {
				if rules.AllowUnknownSections {
					currSectionObj = nil
					continue
				} else {
					return fmt.Errorf("line %d - unknown section: %q",
						line, name)
				}
			}

			numInstances := seenSections[mangledName]
			if rule.Limit > 0 && numInstances > rule.Limit {
				if rule.Limit == 1 {
					return fmt.Errorf("line %d - %q section can only be specified once",
						line, name)
				}

				return fmt.Errorf("line %d - only %d %q sections may be specified (current is %d)",
					line, rule.Limit, name, numInstances)
			}

			currSectionObj, err = newSectionFn(name)
			if err != nil {
				return fmt.Errorf("line %d - failed to initialize section object: %q - %w",
					line, name, err)
			}

			currSectionLine = line
			currSectionName = name
			seenCurrSectionParams = make(map[string]int)

			continue
		}

		if len(seenSections) > 0 && currSectionObj == nil {
			continue
		}

		paramName, paramValue, err := parseParamLine(withoutSpaces)
		if err != nil {
			return fmt.Errorf("line %d - failed to parse line - %w", line, err)
		}

		mangledName := mangleNameFn(paramName)

		if currSectionObj == nil {
			if !rules.AllowGlobalParams {
				return fmt.Errorf("line %d - global parameters are not supported", line)
			}

			paramSchemaFn, rule := schema.GlobalParamSchema(mangledName)
			if paramSchemaFn == nil && !rules.AllowUnknownGlobalParams {
				return fmt.Errorf("line %d - unknown global parameter: %q",
					line, paramName)
			}

			seenGlobals[mangledName]++

			numInst := seenGlobals[mangledName]
			if rule.Limit > 0 && numInst > rule.Limit {
				if rule.Limit == 1 {
					return fmt.Errorf("line %d - %q global param can only be specified once",
						line, paramName)
				}

				return fmt.Errorf("line %d - only %d %q global params may be specified (current is %d)",
					line, rule.Limit, paramName, numInst)
			}

			err = paramSchemaFn(&Param{
				Name:  paramName,
				Value: paramValue,
			})
			if err != nil {
				return fmt.Errorf("line %d - failed to set global param %q - %w",
					line, paramName, err)
			}

			continue
		}

		paramSchemaFn, rule := currSectionObj.ParamSchema(mangledName)
		if paramSchemaFn == nil && !rules.AllowUnknownParams {
			return fmt.Errorf("line %d - unknown parameter: %q",
				line, paramName)
		}

		seenCurrSectionParams[mangledName]++

		numInst := seenCurrSectionParams[mangledName]
		if rule.Limit > 0 && numInst > rule.Limit {
			if rule.Limit == 1 {
				return fmt.Errorf("line %d - %q param can only be specified once",
					line, paramName)
			}

			return fmt.Errorf("line %d - only %d %q params may be specified (current is %d)",
				line, rule.Limit, paramName, numInst)
		}

		err = paramSchemaFn(&Param{
			Name:  paramName,
			Value: paramValue,
		})
		if err != nil {
			return fmt.Errorf("line %d - failed to set param %q - %w",
				line, paramName, err)
		}
	}

	err := scanner.Err()
	if err != nil {
		return err
	}

	if currSectionObj != nil {
		for required := range currSectionObj.RequiredParams() {
			_, hasIt := seenCurrSectionParams[required]
			if !hasIt {
				return fmt.Errorf("line %d - section %q is missing required param: %q",
					currSectionLine, currSectionName, required)
			}
		}

		err := currSectionObj.Validate()
		if err != nil {
			return fmt.Errorf("line %d - failed to validate section: %q - %w",
				currSectionLine, currSectionName, err)
		}
	}

	for required := range rules.RequiredSections {
		_, hasIt := seenSections[required]
		if !hasIt {
			return fmt.Errorf("missing required section: %q", required)
		}
	}

	err = schema.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate config - %w", err)
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
