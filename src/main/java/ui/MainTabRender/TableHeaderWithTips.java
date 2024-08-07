package ui.MainTabRender;

import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.event.MouseEvent;

public class TableHeaderWithTips extends JTableHeader {

    private final String[] tooltips;

    public TableHeaderWithTips(TableColumnModel columnModel, String[] tooltips) {
        super(columnModel); // do everything a normal JTableHeader does
        this.tooltips = tooltips; // plus extra data
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        int index = columnModel.getColumnIndexAtX(e.getPoint().x);
        int realIndex = columnModel.getColumn(index).getModelIndex();

        // 检查索引是否在 tooltips 数组的有效范围内
        if (realIndex >= 0 && realIndex < tooltips.length) {
            return tooltips[realIndex];
        } else {
            return null;
        }
    }
}