package utilbox;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JsonUtils {

	public JsonUtils() {
		// TODO Auto-generated constructor stub
	}


	public static boolean isInt(String input) {
		try {
			Integer b = Integer.valueOf(input);
			return true;
		} catch (NumberFormatException e) {
			try {
				long l = Long.valueOf(input);
				return true;
			}catch(Exception e1) {

			}
			return false;
		}
	}

	public static boolean isJSON(String test) {
		if (isJSONObject(test) || isJSONArray(test)) {
			return true;
		}else {
			return false;
		}
	}

	//org.json
	public static boolean isJSONObject(String test) {
		try {
			new JSONObject(test);
			return true;
		} catch (JSONException ex) {
			return false;
		}
	}


	public static boolean isJSONArray(String test) {
		try {
			new JSONArray(test);
			return true;
		} catch (JSONException ex) {
			return false;
		}
	}

	//org.json
	public static String updateJSONValue(String JSONString, String payload) throws Exception {

		if (isJSONObject(JSONString)) {
			JSONObject obj = new JSONObject(JSONString);
			Iterator<String> iterator = obj.keys();
			while (iterator.hasNext()) {
				String key = (String) iterator.next();		// We need to know keys of Jsonobject
				String value = obj.get(key).toString();


				if (isJSONObject(value)) {// if it's jsonobject
					String newValue = updateJSONValue(value, payload);
					obj.put(key,new JSONObject(newValue));
				}else if (isJSONArray(value)) {// if it's jsonarray
					String newValue = updateJSONValue(value, payload);
					obj.put(key,new JSONArray(newValue));
				}else {
					if (!isBooleanOrNumber(value)){
						obj.put(key, value+payload);
					}
				}
			}
			return obj.toString();
		}else if(isJSONArray(JSONString)) {
			JSONArray jArray = new JSONArray(JSONString);

			ArrayList<String> newjArray = new ArrayList<String>();
			for (int i=0;i<jArray.length();i++) {//无论Array中的元素是JSONObject还是String都转换成String进行处理即可
				String item = jArray.get(i).toString();
				String newitem = updateJSONValue(item,payload);
				newjArray.add(newitem);
			}
			return newjArray.toString();
		}else {
			return JSONString+payload;
		}
	}


	public static ArrayList<String> grepValueFromJson(String jsonString,String keyName) throws Exception {
		ArrayList<String> result = new ArrayList<String>();

		if(jsonString.startsWith("HTTP/") && jsonString.contains("\r\n\r\n")) {//response
			String[] parts = jsonString.split("\r\n\r\n", 2);
			if (parts.length ==2) {
				jsonString = parts[1];
			}
		}

		if (isJSONObject(jsonString)) {
			JSONObject obj = new JSONObject(jsonString);
			Iterator<String> iterator = obj.keys();
			while (iterator.hasNext()) {
				// We need to know keys of Jsonobject
				String key = (String) iterator.next();
				String value = obj.get(key).toString();

				if (key.equals(keyName)) {
					result.add(value);
				}

				result.addAll(grepValueFromJson(value,keyName));
			}
		}else if(isJSONArray(jsonString)){
			//JSONArray中每个元素都是JSON
			JSONArray obj = new JSONArray(jsonString);
			for (int i=0;i<obj.length();i++) {
				String item = obj.get(i).toString();				
				result.addAll(grepValueFromJson(item,keyName));
			}
		}else {
			//一个字段的结束位置，可能是逗号，右括号或者换行符
			String reg = String.format("\"%s\":[\\s]*[\"]{0,1}(.*?)[\"]{0,1}[,}\n\r]+", keyName);

			Pattern pattern = Pattern.compile(reg);
			Matcher matcher = pattern.matcher(jsonString);
			while (matcher.find()) {//多次查找
				String item = matcher.group(1);
				//System.out.println("111"+item+"111");
				result.add(item);
			}
			
			String reg1 = String.format("\'%s\':[\\s]*[\']{0,1}(.*?)[\']{0,1}[,}]+", keyName);
			//JSON 标准中定义了字符串必须使用双引号（"）来包裹，因此在合法的 JSON 中，字符串不能使用单引号。
			//但是实际情况存在使用单引号的情形！
			Pattern pattern1 = Pattern.compile(reg1);
			Matcher matcher1 = pattern1.matcher(jsonString);
			while (matcher1.find()) {//多次查找
				String item = matcher1.group(1);
				//System.out.println("111"+item+"111");
				result.add(item);
			}
		}
		return result;
	}

	public static boolean isBooleanOrNumber(String input) {
		if (input.equalsIgnoreCase("true") || input.equalsIgnoreCase("false")){
			return true;
		}else{
			return isNumeric(input);
		}
	}

	public static boolean isNumeric(String str){
		for(int i=str.length();--i>=0;){
			int chr=str.charAt(i);
			if(chr<48 || chr>57) {
				return false;
			}
		}
		return true;
	}


	/**
	 * JSON美化，会自动转换Unicode
	 * @param jsonString
	 * @return
	 */
	public static String pretty(String jsonString) {
		try {
			// 将 JSON 字符串解析为 JSONObject
			JSONObject jsonObject = new JSONObject(jsonString);
			// 将 JSONObject 格式化为美化后的 JSON 字符串
			String prettyJsonString = jsonObject.toString(4); // 使用 4 个空格缩进
			return prettyJsonString;
		} catch (JSONException e) {
			try {
				JSONArray jsonArray = new JSONArray(jsonString);
				// 将 JSONObject 格式化为美化后的 JSON 字符串
				String prettyJsonString = jsonArray.toString(4); // 使用 4 个空格缩进
				return prettyJsonString;
			} catch (JSONException e1) {
				//e1.printStackTrace();
			}
		}
		return jsonString;
	}



	public static void main(String[] args) {
		String aaa = "aaa";
//		System.out.println(aaa);
		try {
			System.out.println(grepValueFromJson(aaa,"password"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}