package utils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static utils.BurpPrintUtils.*;

public class RegularUtils {
    /**
     * 编译提取URI的正则表达式列表
     */
    public static List<Pattern> compileUriMatchRegular(List<String> regularList) {
        List<Pattern> patternList = new ArrayList<>();

        if (CastUtils.isNotEmptyObj(regularList)){
            for (String regular : regularList) {
                try {
                    Pattern pattern = Pattern.compile(regular);
                    patternList.add(pattern);
                    stdout_println(LOG_DEBUG, String.format("[+] compile regular success: [%s]", regular));
                } catch (PatternSyntaxException e) {
                    // 处理正则表达式语法错误
                    stderr_println(LOG_ERROR, String.format("[!] Invalid regular expression: [%s]", regular));
                    e.printStackTrace();
                } catch (Exception e) {
                    // 处理其他可能的异常
                    stderr_println(LOG_ERROR, String.format("Unexpected error occurred while compiling regex: [%s]", regular) );
                    e.printStackTrace();
                }
            }
        }

        if (patternList.isEmpty()){
            Pattern FIND_PATH_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
            patternList.add(FIND_PATH_PATTERN);
        }

        return patternList;
    }
}
