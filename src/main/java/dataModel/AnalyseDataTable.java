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
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"  //请求Hash信息
            + " req_url TEXT NOT NULL,\n"  //请求URL
            + " req_path TEXT NOT NULL,\n" //请求Path 便于补充根目录
            
            + " analysed_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + " find_url INTEGER DEFAULT -1,\n"     //发现URL的数量

            + " analysed_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + " find_path INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + " analysed_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + " find_info INTEGER DEFAULT -1,\n"    //发现INFO的数量

            + " analysed_api DEFAULT '',\n"        //基于分析的不完整URI信息计算出来的URL (Json格式)
            + " find_api INTEGER DEFAULT -1\n"     //发现API的数量
            + ");";

}
