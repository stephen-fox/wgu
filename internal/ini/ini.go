package ini

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrStopIterating should be returned by an iterator function
	// when no further iterations are required.
	ErrStopIterating = errors.New("stop iterating over sections")

	// ErrNoSuchSection is returned when the specified section
	// does not exist.
	ErrNoSuchSection = errors.New("failed to find specified section")

	// ErrNoSuchParam  is returned when the specified parameter
	// does not exist.
	ErrNoSuchParam = errors.New("failed to find specified parameter")
)

// Parse parses the contents of an io.Reader to an INI.
//
// This function is useful for parsing an INI blob without
// doing deeper inspection of its contents.
func Parse(r io.Reader) (*INI, error) {
	config := &INI{}

	err := ParseSchema(r, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// INI represents an INI blob.
type INI struct {
	// Globals are global parameters.
	Globals []*Param

	// Sections are sections contained within the INI blob.
	Sections []*Section
}

// GlobalParam partly implements the Schema interface.
func (o *INI) GlobalParam(p *Param) error {
	o.Globals = append(o.Globals, p)

	return nil
}

// StartSection partly implements the Schema interface.
func (o *INI) StartSection(name string) (SectionSchema, error) {
	section := &Section{Name: name}

	o.Sections = append(o.Sections, section)

	return section, nil
}

// Validate partly implements the Schema interface.
func (o *INI) Validate() error {
	return nil
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

// FirstParamInFirstSection returns the first instance of the parameter
// named by paramName in the section named by sectionName.
//
// If the specified section does not exist, ErrNoSuchSection is returned.
// If the specified parameter does not exist, ErrNoSuchParam is returned.
func (o *INI) FirstParamInFirstSection(paramName string, sectionName string) (*Param, error) {
	var param *Param

	err := o.IterateSections(sectionName, func(section *Section) error {
		p, err := section.FirstParam(paramName)
		if err != nil {
			return err
		}

		param = p

		return ErrStopIterating
	})
	if err != nil {
		return nil, err
	}

	return param, nil
}

// IterateSections iterates over each section named by sectionName.
// It executes fn for each section.
//
// Iteration can be stopped by returning ErrStopIterating.
//
// If the specified section does not exist, ErrNoSuchSection is returned.
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
		return fmt.Errorf("%q - %w", sectionName, ErrNoSuchSection)
	}

	return nil
}

// Section represents a section in an INI blob.
type Section struct {
	Name   string
	Params []*Param
}

// AddParam adds the provided parameter to the Section.
//
// It partly implements the SectionSchema interface.
func (o *Section) AddParam(p *Param) error {
	o.Params = append(o.Params, p)

	return nil
}

// Validate partly implements the SectionSchema interface.
func (o *Section) Validate() error {
	if o.Name == "" {
		return errors.New("section is missing name")
	}

	return nil
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

// FirstParam returns the first instance of the parameter named
// by paramName.
//
// If the specified parameter does not exist, ErrNoSuchParam is returned.
func (o *Section) FirstParam(paramName string) (*Param, error) {
	var param *Param

	err := o.IterateParams(paramName, func(p *Param) error {
		param = p

		return ErrStopIterating
	})
	if err != nil {
		return nil, err
	}

	return param, nil
}

// IterateParams iterates over each parameter named by paramName.
// It executes fn for each parameter.
//
// Iteration can be stopped by returning ErrStopIterating.
//
// If the specified parameter does not exist, ErrNoSuchParam is returned.
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
		return fmt.Errorf("%q - %w", paramName, ErrNoSuchParam)
	}

	return nil
}

// SetOrAddFirstParam sets the parameter named by paramName to the specified
// value. If the parameter does not exist, a new parameter is added with the
// specified name and value.
func (o *Section) SetOrAddFirstParam(paramName string, value string) error {
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

// Param represents a parameter in an INI blob.
type Param struct {
	Name  string
	Value string
}
