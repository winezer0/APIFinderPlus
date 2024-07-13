package utils;

import burp.BurpExtender;

import java.io.PrintWriter;

import static burp.BurpExtender.SHOW_MSG_LEVEL;

public class BurpPrintUtils {
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    // 定义日志级别
    public static int LOG_ERROR = 2;  //重要
    public static int LOG_INFO = 1;   //一般
    public static int LOG_DEBUG = 0;   //调试

    public BurpPrintUtils(){
        this.stdout = BurpExtender.getStdout();
        this.stderr = BurpExtender.getStderr();
    }

    public BurpPrintUtils(PrintWriter stdout, PrintWriter stderr){
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void stdout_println(Integer msgLevel, Object msg){
        if(msgLevel <=  SHOW_MSG_LEVEL){
            stdout.println(msg);
            System.out.println(msg);
        }
    }


    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void stderr_println(Integer msgLevel, Object msg){
        if(msgLevel <= SHOW_MSG_LEVEL){
            stderr.println(msg);
            System.out.println(msg);
        }
    }


    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void system_println(Integer msgLevel, Object msg){
        if(msgLevel <=  SHOW_MSG_LEVEL)
            System.out.println(msg);
    }

    public static void stdout_println(Object msg){
        stdout_println(LOG_INFO,msg);
    }

    public static void stderr_println(Object msg){
        stderr_println(LOG_ERROR,msg);
    }

    public static void system_println(Object msg){
        system_println(LOG_INFO,msg);
    }
}
