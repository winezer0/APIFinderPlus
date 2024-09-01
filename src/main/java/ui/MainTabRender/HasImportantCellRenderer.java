package ui.MainTabRender;

import utils.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class HasImportantCellRenderer extends DefaultTableCellRenderer {

    // 预加载并缓存图标
    private final Icon importantIcon = UiUtils.getImageIcon("/icon/importantButtonIcon.png", 15, 15);
    //private final Icon notImportantIcon = UiUtils.getImageIcon("/icon/normalIcon.png", 15, 15);
    public HasImportantCellRenderer() {
        setHorizontalAlignment(CENTER); // 设置居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用父类以保留默认行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);


        // 根据单元格值设置相应图标
        if (value instanceof Boolean) {
            if ((Boolean) value){
                setIcon(importantIcon);
                // 设置文本为空，因为我们只显示图标
                setText("");
            }else{
                setIcon(null);
                setText("NO");
            }
        } else {
            setIcon(null);
            setText((String)value); // 如果值不是布尔类型，则不显示图标
        }

        return this;
    }
}
