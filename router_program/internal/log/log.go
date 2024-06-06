package log

import (
	"log/slog"

	"gopkg.in/natefinch/lumberjack.v2"
)

var Slog *slog.Logger

func InitLog() {
	r := &lumberjack.Logger{
		Filename:   "./run.log", //
		MaxSize:    1,           // 文件最大大小 1M
		MaxAge:     1,           // 最大保留时间 1天
		MaxBackups: 3,           // 最大保留文件数 3个
		LocalTime:  true,        // 是否用本机时间
		Compress:   false,       // 是否压缩归档日志
	}

	opts := &slog.HandlerOptions{
		//AddSource: true,
		Level: slog.LevelInfo,
	}
	//Slog = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	Slog = slog.New(slog.NewJSONHandler(r, opts))
}
