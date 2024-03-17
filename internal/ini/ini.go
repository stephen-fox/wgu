package ini

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

var ErrStopIterating = errors.New("stop iterating over sections")

func Parse(r io.Reader) (*INI, error) {
	scanner := bufio.NewScanner(r)

	line := 0

	var sections []*Section

	for scanner.Scan() {
		line++

		withoutSpaces := bytes.TrimSpace(scanner.Bytes())

		if len(withoutSpaces) == 0 || withoutSpaces[0] == '#' {
			continue
		}

		if withoutSpaces[0] == '[' {
			name, err := parseSectionLine(withoutSpaces)
			if err != nil {
				return nil, fmt.Errorf("line %d - failed to parse section header - %w", line, err)
			}

			sections = append(sections, &Section{Name: name})

			continue
		}

		if len(sections) == 0 {
			return nil, fmt.Errorf("line %d - parameter appears outside of a section", line)
		}

		paramName, paramValue, err := parseParamLine(withoutSpaces)
		if err != nil {
			return nil, fmt.Errorf("line %d - failed to parse line - %w", line, err)
		}

		currentSection := sections[len(sections)-1]
		currentSection.Params = append(*&currentSection.Params, &Param{
			Name:  paramName,
			Value: paramValue,
		})
	}

	err := scanner.Err()
	if err != nil {
		return nil, err
	}

	return &INI{
		Sections: sections,
	}, nil
}

type INI struct {
	Sections []*Section
}

func (o *INI) String() string {
	buf := bytes.NewBuffer(nil)

	for i, section := range o.Sections {
		section.string(buf)

		if len(o.Sections) > 1 && i < len(o.Sections)-1 {
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

func (o *INI) IterateSections(sectionName string, fn func(*Section) error) error {
	var foundOneSection bool

	for _, section := range o.Sections {
		if section.Name == sectionName {
			foundOneSection = true

			err := fn(section)
			if err != nil {
				if errors.Is(err, ErrStopIterating) {
					return nil
				}

				return err
			}
		}
	}

	if !foundOneSection {
		return fmt.Errorf("failed to find section: %q", sectionName)
	}

	return nil
}

func (o *INI) ParamInSection(paramName string, sectionName string) (string, error) {
	var foundOneSection bool

	for _, section := range o.Sections {
		if section.Name == sectionName {
			foundOneSection = true

			for _, param := range section.Params {
				if param.Name == paramName {
					return param.Value, nil
				}
			}
		}
	}

	if !foundOneSection {
		return "", fmt.Errorf("failed to find section: %q", sectionName)
	}

	return "", fmt.Errorf("failed to find %q in section %q", paramName, sectionName)
}

type Section struct {
	Name   string
	Params []*Param
}

func (o *Section) string(b *bytes.Buffer) {
	b.WriteString("[" + o.Name + "]\n")
	for _, param := range o.Params {
		b.WriteString(param.Name)
		b.WriteString(" = ")
		b.WriteString(param.Value)
		b.WriteString("\n")
	}
}

func (o *Section) IterateParams(paramName string, fn func(*Param) error) error {
	var foundOne bool

	for _, param := range o.Params {
		if param.Name == paramName {
			foundOne = true

			err := fn(param)
			if err != nil {
				if errors.Is(err, ErrStopIterating) {
					return nil
				}

				return err
			}
		}
	}

	if !foundOne {
		return fmt.Errorf("failed to find param: %q", paramName)
	}

	return nil
}

func (o *Section) FirstParamValue(paramName string) (string, error) {
	for _, param := range o.Params {
		if param.Name == paramName {
			return param.Value, nil
		}
	}

	return "", fmt.Errorf("failed to find param: %q", paramName)
}

func (o *Section) AddOrSetFirstParam(paramName string, value string) error {
	for i := range o.Params {
		if o.Params[i].Name == paramName {
			o.Params[i].Value = value
			return nil
		}
	}

	o.Params = append(o.Params, &Param{
		Name:  paramName,
		Value: value,
	})

	return nil
}

type Param struct {
	Name  string
	Value string
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
