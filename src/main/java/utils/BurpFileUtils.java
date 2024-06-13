package utils;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static utils.BurpPrintUtils.stderr_println;
import static utils.BurpPrintUtils.stdout_println;

public class BurpFileUtils {
    /**
     * 检查指定路径的文件是否存在
     * @param filePath 文件的路径
     * @return 如果文件存在返回true，否则返回false
     */
    public static boolean isFileExists(String filePath) {
        Path path = Paths.get(filePath);
        return Files.exists(path);
    }

    /**
     * 拼接目录和文件名
     * @param directory 目录路径
     * @param fileName 文件名
     * @return 拼接后的完整路径
     */
    public static String concatPath(String directory, String fileName) {
        Path path = Paths.get(directory, fileName);
        return path.toString();
    }

    /**
     * 读取文本文件内容并返回一个字符串
     * @param filePath 文本文件的路径
     * @return 文件内容字符串，如果发生错误则返回null
     */
    public static String readFileToString(String filePath) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            stderr_println(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return content.toString();
    }

    /**
     * 从jar包中读取资源文件内容到字符串
     * @param resourceName 资源的路径（例如："com/example/myfile.txt"）
     * @return 文件内容字符串，如果发生错误则返回null
     */
    public static String readResourceToString(String resourceName) {
        StringBuilder content = new StringBuilder();
        try (InputStream inputStream = BurpFileUtils.class.getClassLoader().getResourceAsStream(resourceName);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            if (inputStream == null) {
                stderr_println("无法找到资源: " + resourceName);
                return null;
            }

            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            stderr_println(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return content.toString();
    }

    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public static String getPluginPath(IBurpExtenderCallbacks callbacks) {
        String path = "";
        Integer lastIndex = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

    /**
     * 从 jar文件所在路径或jar文件内部读取配置文件
     * @param callbacks
     * @param configName
     * @return
     */
    public static String ReadPluginConfFile(IBurpExtenderCallbacks callbacks, String configName) {
        String configJson;

        String extensionPath = getPluginPath(callbacks);
        String configPath = concatPath(extensionPath, configName);

        if(isFileExists(configPath)){
            stdout_println(String.format("[+] Custom Config File Path: %s", configPath));
            configJson = readFileToString(configPath);
        }else {
            configName = String.format("conf/%s", configName);
            stdout_println(String.format("[+] User Jar File Inner Config: %s -> %s", extensionPath, configName));
            configJson = readResourceToString(configName);
        }
        return configJson;
    }

    /**
     * 获取插件同级目录下的指定文件
     * @param callbacks
     * @param fileName
     * @return
     */
    public static Path getPluginDirFilePath(IBurpExtenderCallbacks callbacks, String fileName) {
        Path path = Paths.get(getPluginPath(callbacks), fileName);
        return path.toAbsolutePath();
    }
}
