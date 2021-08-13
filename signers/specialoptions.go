package signers

func (s *Signer) FlagValuesSetManually() (*FlagValues, error) {
	if s.flags == nil {
		return nil, nil
	}
	values := &FlagValues{
		Defs:   s.flags,
		Values: make(map[string]string),
	}
	/*
		s.flags.VisitAll(func(flag *pflag.Flag) {
			if fs.Changed(flag.Name) {
				values.Values[flag.Name] = fs.Lookup(flag.Name).Value.String()
			}
		})
	*/
	return values, nil
}