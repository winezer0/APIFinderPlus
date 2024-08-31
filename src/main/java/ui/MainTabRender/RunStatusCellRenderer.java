package ui.MainTabRender;

import database.Constants;
import utils.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class RunStatusCellRenderer extends DefaultTableCellRenderer {
    // 预加载并缓存图标
    private final Icon pendingIcon = UiUtils.getImageIcon("/icon/convenientOperationIcon.png", 15, 15);
    private final Icon handlingIcon  = UiUtils.getImageIcon("/icon/searchButton.png", 15, 15);
    private final Icon handledIcon  = UiUtils.getImageIcon("/icon/findUrlFromJS.png", 15, 15);

    public RunStatusCellRenderer() {
        setHorizontalAlignment(CENTER); // 设置居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用父类以保留默认行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 根据单元格值设置相应图标
        if (value instanceof String) {
            String stringValue = (String) value;
            if (Constants.HANDLE_WAIT.equals(stringValue)|| Constants.ANALYSE_END.equals(stringValue)) {
                setIcon(pendingIcon);
                setText(""); // 设置文本为空，因为我们只显示图标
            } else if (Constants.HANDLE_ING.equals(stringValue)) {
                setIcon(handlingIcon);
                setText(""); // 设置文本为空，因为我们只显示图标
            } else if (Constants.HANDLE_END.equals(stringValue)) {
                setIcon(handledIcon);
                setText(""); // 设置文本为空，因为我们只显示图标
            } else {
                setIcon(null);
                setText(stringValue); // 显示字符串值
            }
        } else {
            // 其他类型的值保持不变
            setIcon(null);
            setText((String)value);
        }

        return this;
    }
}
