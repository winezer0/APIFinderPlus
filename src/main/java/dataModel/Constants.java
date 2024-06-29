package dataModel;

public class Constants {
    //所有表状态都使用
    public static final String ANALYSE_WAIT = "等待解析";
    public static final String ANALYSE_ING = "解析中";
    public static final String ANALYSE_END = "解析完成";
    public static final String ANALYSE_SKIP = "无需解析";


    //AnalyseDataTable 使用
    public static String DATA_ID = "DATA_ID";
    public static String REQ_URL = "REQ_URL";
    public static String FIND_PATH = "FIND_PATH";

    //RecordUrlsTable使用
    public static String SPLIT_SYMBOL = "<->";
    public static String REQ_HOST_PORT = "REQ_HOST_PORT";
    public static String REQ_PATH_DIRS = "REQ_PATH_DIRS";
    public static String PATH_TREE = "PATH_TREE";
    public static String PATH_NUM = "PATH_NUM";


    static public String TREE_STATUS_EXPAND = "▼";
    static public String TREE_STATUS_COLLAPSE = "▶";

    static public String TAB_COLOR_SELECTED = "0xffc599";
    static public String TAB_COLOR_MAIN_DATA = "0xf2f2f2";
    static public String TAB_COLOR_SUB_DATA = "0xffffff";

    static public String GRAPHQL_SPACE = " ";
    static public String GRAPHQL_NEW_LINE = "\n";
    static public String GRAPHQL_TAB = "    ";
}
