package database;

public class Constants {
    public static final String ANALYSE_WAIT = "Waiting";     //等待自动处理
    public static final String ANALYSE_ING = "Analysing";    //自动处理中
    public static final String ANALYSE_END = "Analysed";    //自动处理完毕

    public static final String HANDLE_WAIT = "Pending";  //等待手动处理
    public static final String HANDLE_ING = "Handling";  //手动处理中
    public static final String HANDLE_END = "Handled";   //手动处理完毕

    public static final String SPLIT_SYMBOL = "<->";
    public static final String RULE_CONF_PREFIX = "CONF_"; //配置文件中 配置规则的开头
}
