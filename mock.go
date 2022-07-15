package glutton

type DummyLogger struct{}

func (DummyLogger) Debug(args ...interface{})
func (DummyLogger) Debugf(format string, args ...interface{})
func (DummyLogger) Error(args ...interface{})
func (DummyLogger) Errorf(format string, args ...interface{})
func (DummyLogger) Fatal(args ...interface{})
func (DummyLogger) Fatalf(format string, args ...interface{})
func (DummyLogger) Info(args ...interface{})
func (DummyLogger) Infof(format string, args ...interface{})
func (DummyLogger) Panic(args ...interface{})
func (DummyLogger) Panicf(format string, args ...interface{})
func (DummyLogger) Warn(args ...interface{})
func (DummyLogger) Warnf(format string, args ...interface{})
