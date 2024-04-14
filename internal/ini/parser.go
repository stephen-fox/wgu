package ini

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Schema specifies how to parse an INI blob.
//
// Refer to the INI type for an example implementation.
type Schema interface {
	// GlobalParam is called when the parser encounters
	// a global parameter (i.e., one defined before
	// any sections are defined).
	GlobalParam(*Param) error

	// StartSection is called when the parser encounters
	// a new section header.
	//
	// The implementer must return an object that
	// represents the new section.
	//
	// Refer to Section for an example implementation.
	StartSection(name string) (SectionSchema, error)

	// Validate is called by the parser when the
	// parser finishes parsing the INI blob.
	Validate() error
}

// SectionSchema specifies how to parse a section in an INI blob.
//
// Refer to Section for an example implementation.
type SectionSchema interface {
	// AddParam is called by the parser when it encounters
	// a new parameter.
	AddParam(*Param) error

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

	var currSectionLine int
	var currSectionName string
	var currSectionObj SectionSchema

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line++

		withoutSpaces := bytes.TrimSpace(scanner.Bytes())

		if len(withoutSpaces) == 0 || withoutSpaces[0] == '#' {
			continue
		}

		if withoutSpaces[0] == '[' {
			name, err := parseSectionLine(withoutSpaces)
			if err != nil {
				return fmt.Errorf("line %d - failed to parse section header - %w",
					line, err)
			}

			if currSectionObj != nil {
				err := currSectionObj.Validate()
				if err != nil {
					return fmt.Errorf("line %d - failed to validate section: %q - %w",
						currSectionLine, currSectionName, err)
				}
			}

			currSectionObj, err = schema.StartSection(name)
			if err != nil {
				return fmt.Errorf("line %d - failed to start parsing section: %q - %w",
					line, name, err)
			}

			currSectionLine = line
			currSectionName = name

			continue
		}

		paramName, paramValue, err := parseParamLine(withoutSpaces)
		if err != nil {
			return fmt.Errorf("line %d - failed to parse line - %w", line, err)
		}

		if currSectionObj == nil {
			err := schema.GlobalParam(&Param{
				Name:  paramName,
				Value: paramValue,
			})
			if err != nil {
				return fmt.Errorf("line %d - failed to parse global param %q - %w",
					line, paramName, err)
			}
		} else {
			err := currSectionObj.AddParam(&Param{
				Name:  paramName,
				Value: paramValue,
			})
			if err != nil {
				return fmt.Errorf("line %d - failed to parse param %q in section: %q - %w",
					line, paramName, currSectionName, err)
			}
		}
	}

	err := scanner.Err()
	if err != nil {
		return err
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
