package database;

public class Constants {
    public static final String ANALYSE_WAIT = "Waiting";     //等待处理
    public static final String ANALYSE_ING = "Analysing";    //处理中
    public static final String ANALYSE_END = "Analysed";    //处理完毕

    public static final String HANDLE_WAIT = "Waiting";  //手动处理中
    public static final String HANDLE_ING = "Handling";  //手动处理中
    public static final String HANDLE_END = "Handled";   //手动处理完毕

    public static final String SPLIT_SYMBOL = "<->";
    public static final String RULE_CONF_PREFIX = "CONF_"; //配置文件中 配置规则的开头
}
