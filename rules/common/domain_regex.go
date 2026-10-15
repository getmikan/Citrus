package common

import (
	"github.com/metacubex/mihomo/common/regexp2x"
	C "github.com/metacubex/mihomo/constant"

	"github.com/dlclark/regexp2"
)

type DomainRegex struct {
	Base
	regex   *regexp2.Regexp
	adapter string
}

func (dr *DomainRegex) RuleType() C.RuleType {
	return C.DomainRegex
}

func (dr *DomainRegex) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	domain := metadata.RuleHost()
	match := regexp2x.MatchString(dr.regex, domain)
	return match, dr.adapter
}

func (dr *DomainRegex) Adapter() string {
	return dr.adapter
}

func (dr *DomainRegex) Payload() string {
	return dr.regex.String()
}

func NewDomainRegex(regex string, adapter string) (*DomainRegex, error) {
	r, err := regexp2x.Compile(regex, regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}
	return &DomainRegex{
		Base:    Base{},
		regex:   r,
		adapter: adapter,
	}, nil
}

var _ C.Rule = (*DomainRegex)(nil)
