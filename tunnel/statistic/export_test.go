package statistic

// Closer returns the function set by SetCloser, for the tests that wrap it.
func (um *UserManager) Closer() func(key UserKey, still func() bool) { return um.closer }
