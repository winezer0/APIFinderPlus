package utilbox;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeUtils {

    public static final String COMMON_DISPLAY_FORMATE = "yyyy-MM-dd HH:mm:ss"; //通常的显示格式
    public static final String COMMON_FILENAME_FORMATE = "yyyy_MM_dd_HH_mm_ss"; //常用于文件名中

    /**
     * 返回毫秒级的时间戳
     *
     * @param date
     * @return
     */
    public static Long getTimestampMillisecond(Date date) {
        if (null == date) {
            return (long) 0;
        }
        return date.getTime();
    }

    /**
     * 返回秒级的时间戳
     *
     * @param date
     * @return
     */
    public static Long getTimestampSecond(Date date) {
        if (null == date) {
            return (long) 0;
        }
        return date.getTime() / 1000;
    }

    /**
     * 输入的格式要求（标准的时间） 2020-12-11 12:00:00
     * 效果如同 https://tool.lu/timestamp/，比如
     * 2024-04-30 12:15:45 --->1714450545
     */
    public static Long getTimestampMillisecondFromStr(String date) throws Exception {
        if (null == date) {
            return (long) 0;
        }
        DateFormat dateFormat = new SimpleDateFormat(COMMON_DISPLAY_FORMATE);
        return dateFormat.parse(date).getTime();
    }


    public static Long getTimestampSecondFromStr(String date) throws Exception {
        if (null == date) {
            return (long) 0;
        }
        DateFormat dateFormat = new SimpleDateFormat(COMMON_DISPLAY_FORMATE);
        return dateFormat.parse(date).getTime() / 1000;
    }


    public static String getTimeStr(Date date, SimpleDateFormat formate) {
        String time = formate.format(date);
        return time;
    }


    public static String getNowTimeStr(String formate) {
        SimpleDateFormat df = new SimpleDateFormat(formate);//设置日期格式
        String time = df.format(new Date());// new Date()为获取当前系统时间
        return time;
    }

    /**
     * 获取当前时间字符串，通常显示格式
     *
     * @return
     */
    public static String getNowTimeStrToDisplay() {
        SimpleDateFormat df = new SimpleDateFormat(COMMON_DISPLAY_FORMATE);
        String time = df.format(new Date());
        return time;
    }

    /**
     * 获取当前时间字符串，用于文件名
     *
     * @return
     */
    public static String getNowTimeStrAsFilename() {
        SimpleDateFormat df = new SimpleDateFormat(COMMON_FILENAME_FORMATE);
        String time = df.format(new Date());
        return time;
    }

    /**
     * 时间加减
     *
     * @param sec
     * @return
     */
    public static String timePlusOrSub(long sec) {
        SimpleDateFormat df = new SimpleDateFormat(COMMON_DISPLAY_FORMATE);//设置日期格式
        String time = df.format(new Date(new Date().getTime() + sec * 1000));// new Date()为获取当前系统时间
        return time;
    }


    public static void main(String[] args) {
        System.out.println(getTimestampSecond(null));
    }
}
