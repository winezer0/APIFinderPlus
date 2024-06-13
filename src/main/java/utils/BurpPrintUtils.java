package utils;

import burp.BurpExtender;

import java.io.PrintWriter;

import static burp.BurpExtender.SHOW_MSG_LEVEL;

public class BurpPrintUtils {
    private static final PrintWriter stdout = BurpExtender.getStdout();
    private static final PrintWriter stderr = BurpExtender.getStderr();

    // 定义日志级别
    public static int LOG_ERROR = 0;  //重要
    public static int LOG_INFO = 1;   //一般
    public static int LOG_DEBUG = 2;   //调试

    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void stdout_println(Integer msgLevel, String msg){
        if(msgLevel <=  SHOW_MSG_LEVEL){
            stdout.println(msg);
        }
    }


    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void stderr_println(Integer msgLevel, String msg){
        if(msgLevel <=  SHOW_MSG_LEVEL){
            stderr.println(msg);
        }
    }


    /**
     * 根据输出日志级别输出错误消息 SHOW_MSG_LEVEL 越小,输出内容越少
     * @param msgLevel
     * @param msg
     */
    public static void system_println(Integer msgLevel, String msg){
        if(msgLevel <=  SHOW_MSG_LEVEL){
            System.out.println(msg);
        }
    }

    public static void stdout_println(String msg){
        stdout_println(LOG_INFO,msg);
    }

    public static void stderr_println(String msg){
        stderr_println(LOG_INFO,msg);
    }

    public static void system_println(String msg){
        system_println(LOG_INFO,msg);
    }
}
