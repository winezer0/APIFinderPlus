package utilbox;

import javax.swing.*;
import java.util.List;

public class SwingUtils {

	public SwingUtils() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) {
		System.out.print(showTextAreaDialog("aaaa"));
	}


	/**
	 * 显示Text，让用户修改确认
	 * @param text
	 * @return
	 */
	public static String showTextAreaDialog(String text) {
		return showTextAreaDialog(20, 20,"Edit And Confirm Text",text);
	}


	/**
	 * 显示Text，让用户修改确认
	 * @param text
	 * @return
	 */
	public static String showTextAreaDialog(int rows, int columns,String title,String text) {
		// 创建一个 JTextArea
		JTextArea textArea = new JTextArea(rows,columns); // 设置行数和列数
		// 将 JTextArea 放入 JScrollPane 中，以便可以滚动查看
		textArea.setText(text);
		JScrollPane scrollPane = new JScrollPane(textArea);
		// 显示包含 JTextArea 的对话框
		int result = JOptionPane.showOptionDialog(
				null, // parentComponent
				scrollPane, // message
				title, // title
				JOptionPane.OK_CANCEL_OPTION, // optionType
				JOptionPane.PLAIN_MESSAGE, // messageType
				null, // icon
				null, // options
				null // initialValue
				);

		// 处理用户输入
		if (result == JOptionPane.OK_OPTION) {
			return textArea.getText();
		}
		return null;
	}


	public static List<String> getLinesFromTextArea(JTextArea textarea){
		return TextUtils.textToLines(textarea.getText());
	}


	public static List<String> getDeduplicatedLinesFromTextArea(JTextArea textarea){
		return TextUtils.deduplicate(TextUtils.textToLines(textarea.getText()));
	}

}
