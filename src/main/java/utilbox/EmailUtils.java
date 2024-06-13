package utilbox;


import java.util.List;

public class EmailUtils {
    public static final String REGEX_TO_GREP_EMAIL = "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+";

    public static final String REGEX_TO_VALIDATE_EMAIL = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$";//TODO Check

    public static List<String> grepEmail(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_EMAIL);
    }


    public static boolean isValidEmail(String text) {
        return TextUtils.isRegexMatch(text, REGEX_TO_VALIDATE_EMAIL);
    }
}
