package burp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static utils.AnalyseInfoUtils.extractUriMode1;
import static utils.AnalyseInfoUtils.formatUri;

public class test {

    public static String readFileAsString(String filePath) throws IOException {
        return String.join(System.lineSeparator(), Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8));
    }


    public static Set<String> extractUriFromJs(String jsText,Pattern pattern, int chunkSize){
        int jsLength = jsText.length();
        Set<String> findUris = new LinkedHashSet<>();

        // 处理每个 chunkSize 大小的片段
        for (int start = 0; start < jsLength; start += chunkSize) {
            int end = Math.min(start + chunkSize, jsLength);
            String jsChunk = jsText.substring(start, end);

            Matcher matcher_result = pattern.matcher(jsChunk);
            while (matcher_result.find()){
                // 检查第一个捕获组
                String group1 = matcher_result.group(1);
                if (group1 != null) {
                    findUris.add(formatUri(group1));
                }
                // 检查第二个捕获组
                String group2 = matcher_result.group(2);
                if (group2 != null) {
                    findUris.add(formatUri(group2));
                }
            }
        }

        return findUris;
    }

    public static void main(String[] args) {
//        String FIND_URL = "(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?";
//        String URLSchemes = "((?![http]|[https])(([-A-Za-z0-9]{1,20})://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]))";
//        String ALLUrl = "(https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;\\u4E00-\\u9FFF]+[-A-Za-z0-9+&@#/%=~_|])";

        String FIND_PATH_FROM_JS_PATTERN1 = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')";
        //String FIND_PATH_FROM_JS_PATTERN2 = "\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'";
        String LinkFinder = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:\\w)(?:[\\?|#][^\"|']{0,}|)))(?:\"|')";
        Pattern FIND_PATH_PATTERN_2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");

        try {
            String filePath = "C:\\Users\\WINDOWS\\Desktop\\index-d0-kis-F.js";
            //String filePath = "C:\\Users\\WINDOWS\\Desktop\\vulnweb.html";
            String content = readFileAsString(filePath);
            // System.out.println(content);
            content = content.replace("\\","");

//            List<String> list1 = extractUriFromJs(content, FIND_URL, 20000);
//            System.out.println("HAE FIND_URL:" + list1.size());
//            System.out.println(list1);

//            List<String> list3 = extractUriFromJs(content, FIND_PATH_FROM_JS_PATTERN2, 20000);
//            System.out.println("HAE FIND_PATH_FROM_JS_PATTERN2:" + list3.size());
//            System.out.println(list3);

//            List<String> list4 = extractUriFromJs(content, URLSchemes, 20000);
//            System.out.println("HAE URLSchemes:" + list4.size());
//            System.out.println(list4);

//            List<String> list5 = extractUriFromJs(content, ALLUrl, 20000);
//            System.out.println("HAE ALLUrl:" + list5.size());
//            System.out.println(list5);

            Set<String> list2 = extractUriMode1(content, FIND_PATH_FROM_JS_PATTERN1, 20000);
            System.out.println("FIND_PATH_FROM_JS_PATTERN1:" + list2.size());
            System.out.println(list2);

//            Set<String> list6 = extractUriMode1(content, LinkFinder, 20000);
//            System.out.println("HAE LinkFinder:" + list6.size());
//            System.out.println(list6);
//
//            Set<String> list11 = extractUriFromJs(content, FIND_PATH_PATTERN_2,20000);
//            System.out.println("FIND_PATH_FROM_JS_PATTERN2:" + list6.size());
//            System.out.println(list6);

            //经过测试  FIND_PATH_FROM_JS_PATTERN1 比 LinkFinder 更好

            //经过测试  FIND_PATH_FROM_JS_PATTERN2 和 LinkFinder 完全相同

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

}
