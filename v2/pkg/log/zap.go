// This is a wrapper for the zap framework
// no SugerLogger, Only Logger
// @author: 胖胖的ALEX
// example:
//
//	Log().Debug("debug log test")
//	Log().Info("info log test")
//	Log().Warn("warn log test")
//	Log().Error("error log test")
//	Log().Panic("panic log test")
//	Log().Fatal("fatal log test")
package log

import (
	"os"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	defaultLogFileName = "./logs"

	defaultLevel = zapcore.FatalLevel

	log *zap.Logger

	logOnce sync.Once
)

// singleton pattern
func Log() *zap.Logger {
	logOnce.Do(func() {
		core := zapcore.NewCore(getEncoder(), getLogWriter(), defaultLevel)
		log = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0))
		defer log.Sync()
	})
	return log
}

func Debug(msg string, fields ...zap.Field) {
	log.Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	log.Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	log.Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	log.Fatal(msg, fields...)
}

func Panic(msg string, fields ...zap.Field) {
	log.Panic(msg, fields...)
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.LineEnding = zapcore.DefaultLineEnding
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.EncodeTime = timeEncoder
	encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	encoderConfig.EncodeName = zapcore.FullNameEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func timeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05"))
}

func getLogWriter() zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   defaultLogFileName,
		MaxSize:    60,
		MaxBackups: 6,
		MaxAge:     60,
		Compress:   false,
	}
	return zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(lumberJackLogger))
	// return zapcore.AddSync(lumberJackLogger)
}
