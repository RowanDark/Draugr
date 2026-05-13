package output

type Writer struct{}

// Write emits a single finding. Implemented in Issue #5.
func (w *Writer) Write(finding map[string]any) error {
	// TODO: implemented in Issue #5
	return nil
}
