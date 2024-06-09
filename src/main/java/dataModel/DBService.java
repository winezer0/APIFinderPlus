package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import utils.BurpFileUtils;

import java.io.PrintWriter;
import java.sql.*;

public class DBService {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //指定sqlite数据库配置文件路径
    private static final String CONNECTION_STRING = "jdbc:sqlite:" + BurpFileUtils.getPluginDirFilePath(BurpExtender.getCallbacks(), "APIFinder.db");
    private static DBService instance;
    private Connection connection;

    private DBService() {
        initDBConnection();
        initCreateTables();
    }

    public static synchronized DBService getInstance() {
        // 单例模式配置
        if (instance == null) {
            instance = new DBService();
        }
        return instance;
    }

    //创建数据库链接
    private void initDBConnection() {
        try {
            // 自动注册 SQLite 驱动程序
            Class.forName("org.sqlite.JDBC");

            // 建立数据库连接
            connection = DriverManager.getConnection(CONNECTION_STRING);

            // 启用外键支持
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA foreign_keys = ON");
            } catch (SQLException e) {
                e.printStackTrace();
            }

            stdout.println("[+] SQLite database connection initialized successfully. ");
        } catch (ClassNotFoundException e) {
            stderr.println(String.format("[!] JDBC driver not found. -> %s", e.getMessage()));
            e.printStackTrace(BurpExtender.getStderr());
        } catch (SQLException e) {
            stderr.println(String.format("[!] Failed to connect db. -> %s", e.getMessage()));
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    //创建数据表结构
    private synchronized void initCreateTables() {
        // RecordUrlsTable URL PATH记录表 用于后续路径猜测记录
        execCreatTableSql(RecordUrlsTable.creatTableSQL, RecordUrlsTable.tableName);

        // MsgDataTable 用于存储 实际的请求体和响应体
        execCreatTableSql(MsgDataTable.creatTableSQL, MsgDataTable.tableName);

        // reqDataTable 存储需要敏感信息提取的url
        execCreatTableSql(ReqDataTable.creatTableSQL, ReqDataTable.tableName);

        // 用来创建数据库 analyse_path 存储分析后的数据
        execCreatTableSql(AnalyseDataTable.creatTableSQL, AnalyseDataTable.tableName);
    }

    //创建数据表的语句
    private void execCreatTableSql(String creatTableSql, String tableName) {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(creatTableSql);
            stdout.println(String.format("[+] create db %s success ...", tableName));
        } catch (Exception e) {
            stderr.println(String.format("[!] create db %s failed -> %s", tableName, e.getMessage()));
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    //获取一个数据库语句
    public Connection getNewConnection() throws SQLException {
        return DriverManager.getConnection(CONNECTION_STRING);
    }

    // 关闭数据库连接的方法
    public void closeConnection() {
        try {
            if (this.connection != null && !this.connection.isClosed()) {
                this.connection.close();
            }
        } catch (SQLException e) {
            stderr.println(String.format("关闭数据库连接时发生错误: %s", e.getMessage()));
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

}
