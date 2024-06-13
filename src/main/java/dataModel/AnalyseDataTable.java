package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;

import java.io.PrintWriter;

public class AnalyseDataTable {
    private static final PrintWriter stdout = BurpExtender.getStdout();
    private static final PrintWriter stderr = BurpExtender.getStderr();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();;

    //数据表名称
    static String tableName = "analyse_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n".replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"

            + " req_url TEXT NOT NULL,\n"
            + " req_path TEXT NOT NULL,\n"
            + " req_method TEXT,\n"

            + " path_data TEXT,\n"
            + " resp_status TEXT,\n"

            + " result TEXT,\n"
            + " describe TEXT,\n"
            + " having_important INTEGER,\n"
            + " isJsFindUrl TEXT,\n"
            + " jsFindUrl TEXT, \n"
            + " mayNewParentPath TEXT DEFAULT '', \n"
            + " isTryNewParentPath INTEGER DEFAULT 0"
            + ");";

}
