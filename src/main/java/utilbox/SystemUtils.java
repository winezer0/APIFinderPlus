package utilbox;

import org.apache.commons.lang3.StringUtils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

/**
 * 常用操作系统操作：打开浏览器、打开文件夹、操作剪切板等
 */
public class SystemUtils {

    public static String getNowTimeString() {
        SimpleDateFormat simpleDateFormat =
                new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
        return simpleDateFormat.format(new Date());
    }

    public static String getNowTimeStr() {
        SimpleDateFormat simpleDateFormat =
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return simpleDateFormat.format(new Date());
    }


    public static void browserOpen(Object url, String browser){
        String urlString = null;
        URI uri = null;
        try {
			if (url instanceof String) {
			    urlString = (String) url;
			    uri = new URI((String) url);
			} else if (url instanceof URL) {
			    uri = ((URL) url).toURI();
			    urlString = url.toString();
			}
			if (StringUtils.isEmpty(browser)|| browser.equalsIgnoreCase("default")) {
			    Desktop desktop = Desktop.getDesktop();
			    if (Desktop.isDesktopSupported() && desktop.isSupported(Desktop.Action.BROWSE)) {
			        desktop.browse(uri);
			    }
			} else {
			    String[] cmdArray = new String[]{browser, urlString};

			    //runtime.exec(browser+" "+urlString);//当命令中有空格时会有问题
			    Runtime.getRuntime().exec(cmdArray);
			}
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    

    public static boolean isWindows() {
        String OS_NAME = System.getProperty("os.name").toLowerCase();
        return OS_NAME.contains("windows");
    }

    public static boolean isWindows10() {
        String OS_NAME = System.getProperty("os.name").toLowerCase();
        return OS_NAME.equalsIgnoreCase("windows 10");
    }

    public static boolean isMac() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("mac");
    }

    /**
     * //linux or unix
     *
     * @return
     */
    public static boolean isUnix() {
        String os = System.getProperty("os.name").toLowerCase();
        return (os.contains("nix") || os.contains("nux"));
    }

    /**
     * 获取系统默认编码
     * //https://javarevisited.blogspot.com/2012/01/get-set-default-character-encoding.html
     *
     * @return
     */
    private static String getSystemCharSet() {
        return Charset.defaultCharset().toString();
    }

    /**
     * 将文本写入系统剪切板
     *
     * @param text
     */
    public static void writeToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection selection = new StringSelection(text);
        clipboard.setContents(selection, null);
    }


    /**
     * 拼接命令行中的命令
     * <p>
     * parserPath --- python.exe java.exe ....
     * executerPath --- sqlmap.py nmap.exe ....
     * parameters ---- -v -A -r xxx.file .....
     */
    public static String genCmd(String parserPath, String executerPath, String parameter) {
        StringBuilder command = new StringBuilder();

        if (parserPath != null) {
            if (parserPath.contains(" ")) {
                parserPath = "\"" + parserPath + "\"";//如果路径中包含空格，需要引号
            }
            command.append(parserPath);
            command.append(" ");
        }

        if (executerPath != null) {

            if (executerPath.contains(" ")) {
                executerPath = "\"" + executerPath + "\"";//如果路径中包含空格，需要引号
            }

            command.append(executerPath);
            command.append(" ");
        }

        if (parameter != null && !parameter.equals("")) {
            command.append(parameter);
        }
        command.append(System.lineSeparator());
        return command.toString();
    }


    /**
     * 通知执行bat文件来执行命令
     */
    public static Process runBatchFile(String batfilepath) {
        String command = "";
        if (isWindows()) {
            command = "cmd /c start " + batfilepath;
        } else {
            if (new File("/bin/sh").exists()) {
                command = "/bin/sh " + batfilepath;
            } else if (new File("/bin/bash").exists()) {
                command = "/bin/bash " + batfilepath;
            }
        }
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();//等待执行完成
            return process;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String genBatchFile(String cmdContent, String batchFileName) {
        try {
            if (batchFileName == null || batchFileName.trim().equals("")) {
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("MMdd-HHmmss");
                String timeString = simpleDateFormat.format(new Date());
                batchFileName = timeString + ".bat";
            } else if (!batchFileName.endsWith(".bat") && !batchFileName.endsWith(".cmd")) {
                batchFileName = batchFileName + ".bat";
            }
            String workdir = System.getProperty("user.home");
            File batFile = new File(workdir, batchFileName);
            if (!batFile.exists()) {
                batFile.createNewFile();
            }
            if (isMac()) {
                cmdContent = String.format("osascript -e 'tell app \"Terminal\" to do script \"%s\"'", cmdContent);
            }
            byte2File(cmdContent.getBytes(), batFile);
            return batFile.getAbsolutePath();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void startCmdConsole() {
        try {
            Process process = null;
            if (isWindows()) {
                process = Runtime.getRuntime().exec("cmd /c start cmd.exe");
            } else if (isMac()) {
                ///System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal
                process = Runtime.getRuntime().exec("open -n -F -a /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal");
            } else if (isUnix()) {
                process = Runtime.getRuntime().exec("/usr/bin/gnome-terminal");//kali和Ubuntu测试通过
                //				if(new File("/usr/bin/gnome-terminal").exists()) {
                //					process = Runtime.getRuntime().exec("/usr/bin/gnome-terminal");
                //				}else {
                //					process = Runtime.getRuntime().exec("/usr/bin/xterm");//只能使用shift+insert 进行粘贴操作，但是修改剪切板并不能修改它粘贴的内容。
                //貌似和使用了openjdk有关，故暂时只支持gnome-terminal.
                //				}
            }
            process.waitFor();//等待执行完成
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * 切换工作目录
     */
    public static String changeDirCommand(String dir) {
        //运行命令的工作目录，work path
        String command = "cd " + dir + System.lineSeparator();

        if (isWindows()) {//如果是windows，还要注意不同磁盘的切换
            String diskString = dir.split(":")[0];
            command = command + diskString + ":" + System.lineSeparator();
        }
        return command;
    }

    /**
     * 判断某个文件是否在环境变量中
     */
    @Deprecated
    public static boolean isInEnvironmentPath(String filename) {
        if (filename == null) {
            return false;
        }
        Map<String, String> values = System.getenv();
        String pathvalue = values.get("PATH");
        if (pathvalue == null) {
            pathvalue = values.get("path");
        }
        if (pathvalue == null) {
            pathvalue = values.get("Path");
        }
        //		System.out.println(pathvalue);
        String[] items = pathvalue.split(";");
        for (String item : items) {
            File tmpPath = new File(item);
            if (tmpPath.isDirectory()) {
                //				System.out.println(Arrays.asList(tmpPath.listFiles()));
                File fullpath = new File(item, filename);
                if (Arrays.asList(tmpPath.listFiles()).contains(fullpath)) {
                    return true;
                } else {
                    continue;
                }
            }
        }
        return false;
    }

    /**
     * 检测某个命令是否存在，根据which where命令来的，如果不在环境变量中应该读取不到！
     */
    public static String isCommandExists(String cmd) {
        if (isWindows()) {
            cmd = "where " + cmd;
        } else {
            cmd = "which " + cmd;
        }
        try {
            //启动进程
            Process process = Runtime.getRuntime().exec(cmd);
            //获取输入流
            InputStream inputStream = process.getInputStream();
            //转成字符输入流
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, getSystemCharSet());
            int len = -1;
            char[] c = new char[1024];
            StringBuffer outputString = new StringBuffer();
            //读取进程输入流中的内容
            while ((len = inputStreamReader.read(c)) != -1) {
                String s = new String(c, 0, len);
                outputString.append(s);
                //System.out.print(s);
            }
            inputStream.close();
            return outputString.toString().trim();//去除换行符
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }


    public static void OpenFolder(String path) throws IOException {
        Desktop.getDesktop().open(new File(path));
    }

    public static void byte2File(byte[] buf, File file) {
        BufferedOutputStream bos = null;
        FileOutputStream fos = null;
        try {
            file.createNewFile();
            fos = new FileOutputStream(file);
            bos = new BufferedOutputStream(fos);
            bos.write(buf);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static byte[] File2byte(String filePath) {
        byte[] buffer = null;
        try {
            File file = new File(filePath);
            FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[1024];
            int n;
            while ((n = fis.read(b)) != -1) {
                bos.write(b, 0, n);
            }
            fis.close();
            bos.close();
            buffer = bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return buffer;
    }

    public static void editWithVSCode(String filepath) {
        // /Applications/Visual Studio Code.app/Contents/MacOS/Electron
        if (filepath.contains(" ")) {
            filepath = "\"" + filepath + "\"";
        }
        if (isMac()) {
            try {
                String[] cmdArray = new String[]{"/Applications/Visual Studio Code.app/Contents/MacOS/Electron", filepath};
                Runtime.getRuntime().exec(cmdArray);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (isWindows()) {
            try {
                String[] cmdArray = new String[]{"code.cmd", filepath};
                Runtime.getRuntime().exec(cmdArray);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    public static void main(String args[]) {
        System.out.println(isCommandExists("python"));
    }
}

