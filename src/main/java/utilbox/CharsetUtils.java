package utilbox;

import org.apache.commons.io.input.BOMInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CharsetUtils {

	public static String getSystemCharSet() {
		return Charset.defaultCharset().toString();
	}

	public static boolean isValidCharset(String charsetName) {
		return getCharsetNameList().contains(charsetName);
	}

	public static List<String> getCharsetNameList() {
		Map<String, Charset> charsets = Charset.availableCharsets();
		return new ArrayList<String>(charsets.keySet());
	}

	/**
	 * 消除大小写差异
	 * @param charsetName
	 * @return
	 */
	public static String getCharsetName(String charsetName) {
		List<String> charsetNameList = getCharsetNameList(); // 调用一次并保存结果
		for (String name : charsetNameList) {
			if (name.equalsIgnoreCase(charsetName)) {
				return name;
			}
		}
		return null;
	}

	/**
	 * 进行响应包的编码转换。
	 * @param content
	 * @return 转换后的格式的byte[]
	 */
	public static byte[] covertCharSet(byte[] content,String originalCharset,String newCharset){
		if (originalCharset == null) {
			originalCharset = detectCharset(content);
		}
		try {
			return new String(content,originalCharset).getBytes(newCharset);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return content;
		}
	}


	public static byte[] covertCharSet(byte[] content,String newCharset) throws UnsupportedEncodingException {
		return covertCharSet(content,null,newCharset);
	}


	public static String detectCharset(byte[] bytes){
		try {
			ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
			BOMInputStream bomInputStream = BOMInputStream.builder().setInputStream(bis).get();
			String encoding = bomInputStream.getBOMCharsetName();
			bomInputStream.close();
			return getCharsetName(encoding);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	

	public static void main(String[] args) throws Exception {
//		Map<String, Charset> charsets = Charset.availableCharsets();
//
//		// 打印所有字符编码集的规范名称
//		System.out.println("Available Charsets:");
//		for (String name : charsets.keySet()) {
//			System.out.println(name);
//		}
		
		System.out.println(detectCharset("中国中文11111".getBytes("UTF-8")));
	}
}
