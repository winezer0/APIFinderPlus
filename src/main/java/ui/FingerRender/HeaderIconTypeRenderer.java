package ui.FingerRender;


import utils.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class HeaderIconTypeRenderer extends DefaultTableCellRenderer {

    // 预加载图标
    private static final Icon FILTER_ICON = UiUtils.getImageIcon("/icon/filterIcon.png");

    public HeaderIconTypeRenderer() {
        super();
        setHorizontalAlignment(JLabel.CENTER); //仅需设置一次 设置水平对齐方式
        setHorizontalTextPosition(JLabel.LEFT);  //设置文本相对于图标的水平位置
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); //更改鼠标光标形状 设置为手形
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用super方法来保留原始行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 根据列设置图标
        if (column == 1) {
            setIcon(FILTER_ICON);
        } else {
            setIcon(null);
            setHorizontalAlignment(JLabel.LEADING); // 文本对齐方式恢复默认
        }

        // Since we're modifying the renderer itself, return 'this'
        return this;
    }
}
