"""Control Flow Graph panel - real basic block rendering via QGraphicsView."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsPolygonItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from rawview.qt_ui.themes import CfgPalette, cfg_palette

_NODE_W = 300
_HEADER_H = 22
_LINE_H = 15
_MAX_INSNS = 16
_PAD_BOTTOM = 8
_COL_GAP = 60
_ROW_GAP = 72


def _node_height(total_insns: int, expanded: bool = False) -> float:
    if expanded:
        shown = total_insns
    else:
        shown = min(total_insns, _MAX_INSNS)
    h = _HEADER_H + shown * _LINE_H + _PAD_BOTTOM
    if not expanded and total_insns > _MAX_INSNS:
        h += _LINE_H
    return float(h)


class _BlockItem(QGraphicsRectItem):
    """A single basic block; drawn via paint(); clickable for navigation."""

    def __init__(self, node: dict[str, Any], x: float, y: float, h: float,
                 palette: CfgPalette, navigate_fn) -> None:
        super().__init__(0, 0, _NODE_W, h)
        self.setPos(x, y)
        self._addr = node["id"]
        self._navigate_fn = navigate_fn
        self._node = node
        self._palette = palette
        self._expanded = False
        self._insns = node.get("instructions", [])
        self._total = node.get("total_insns", len(self._insns))
        self._pressed_pos: QPointF | None = None
        self._default_pen = QPen(QColor(palette.node_border), 1.0)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable
        )
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        r = self.rect()
        w, h = r.width(), r.height()
        p = self._palette

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pen = QPen(QColor(p.node_hover), 1.8) if self.isSelected() else self._default_pen
        painter.setPen(pen)
        painter.setBrush(QBrush(QColor(p.node_bg)))
        painter.drawRect(r)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(p.header_bg)))
        painter.drawRect(QRectF(1, 1, w - 2, _HEADER_H - 1))

        painter.setPen(QPen(QColor(p.header_sep), 0.5))
        painter.drawLine(QPointF(0, _HEADER_H), QPointF(w, _HEADER_H))

        hfont = QFont("Consolas", 8)
        hfont.setBold(True)
        painter.setFont(hfont)
        painter.setPen(QColor(p.text_header))
        painter.drawText(
            QRectF(4, 0, w - 8, _HEADER_H),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            f"{self._addr}  [{self._total} insns]",
        )

        bfont = QFont("Consolas", 8)
        painter.setFont(bfont)
        shown = self._insns if self._expanded else self._insns[:_MAX_INSNS]
        for i, insn in enumerate(shown):
            iy = float(_HEADER_H + i * _LINE_H)
            addr_text = insn.get("addr", "")
            instr_text = insn.get("text", "")

            painter.setPen(QColor(p.text_addr))
            painter.drawText(
                QRectF(4, iy, 84, _LINE_H),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                addr_text,
            )
            painter.setPen(QColor(p.text_body))
            painter.drawText(
                QRectF(92, iy, w - 96, _LINE_H),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                instr_text,
            )

        if not self._expanded and self._total > _MAX_INSNS:
            iy = float(_HEADER_H + _MAX_INSNS * _LINE_H)
            painter.setFont(bfont)
            painter.setPen(QColor(p.text_more))
            painter.drawText(
                QRectF(4, iy, w - 8, _LINE_H),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                f"… {self._total - _MAX_INSNS} more  [click to expand]",
            )

    def mousePressEvent(self, event) -> None:
        self._pressed_pos = event.pos()
        super().mousePressEvent(event)
        event.ignore()

    def mouseReleaseEvent(self, event) -> None:
        super().mouseReleaseEvent(event)
        if event.button() != Qt.MouseButton.LeftButton:
            return
        # Ignore drags (panning) - only handle clicks
        if self._pressed_pos and (event.pos() - self._pressed_pos).manhattanLength() > 8:
            self._pressed_pos = None
            return
        self._pressed_pos = None
        # Check if click landed on the "... N more" area
        if not self._expanded and self._total > _MAX_INSNS:
            iy = float(_HEADER_H + _MAX_INSNS * _LINE_H)
            if iy - 4 <= event.pos().y() <= iy + _LINE_H + 4:
                self._expanded = True
                new_h = _node_height(self._total, expanded=True)
                self.setRect(0, 0, _NODE_W, new_h)
                self.update()
                self.scene().update()
                return
        if self._navigate_fn:
            self._navigate_fn(self._addr)

    def hoverEnterEvent(self, event) -> None:
        self.setPen(QPen(QColor(self._palette.node_hover), 1.5))
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self.setPen(self._default_pen)
        self.update()
        super().hoverLeaveEvent(event)


class _PanZoomView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene, palette: CfgPalette) -> None:
        super().__init__(scene)
        self._palette = palette
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setBackgroundBrush(QBrush(QColor(palette.bg)))
        self._zoom = 1.0

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y()
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        new_zoom = self._zoom * factor
        if 0.08 <= new_zoom <= 10.0:
            self.scale(factor, factor)
            self._zoom = new_zoom


class CfgPanel(QWidget):
    navigate_requested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._theme_id = "tokyo_night"
        self._palette = cfg_palette(self._theme_id)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._scene = QGraphicsScene(self)
        self._view = _PanZoomView(self._scene, self._palette)
        layout.addWidget(self._view, stretch=1)
        self._status = QLabel()
        self._status.setStyleSheet(f"color: {self._palette.text_more}; font-size: 10px; padding: 1px 6px;")
        layout.addWidget(self._status)
        self._show_placeholder()

    def set_theme(self, theme_id: str) -> None:
        self._theme_id = theme_id
        self._palette = cfg_palette(theme_id)
        self._view.setBackgroundBrush(QBrush(QColor(self._palette.bg)))
        self._status.setStyleSheet(f"color: {self._palette.text_more}; font-size: 10px; padding: 1px 6px;")
        # Reload the current graph with new colors
        if hasattr(self, '_last_data') and self._last_data:
            self.load_cfg_json(self._last_data)

    def _show_placeholder(self, msg: str = "Select a function; the CFG renders automatically.") -> None:
        self._scene.clear()
        from PySide6.QtWidgets import QGraphicsTextItem
        t = QGraphicsTextItem(msg)
        t.setDefaultTextColor(QColor(self._palette.text_more))
        f = QFont("Consolas", 9)
        t.setFont(f)
        self._scene.addItem(t)
        self._status.clear()

    def load_cfg_json(self, data: dict[str, Any]) -> None:
        self._last_data = data
        self._scene.clear()

        if data.get("error") == "no_function":
            self._show_placeholder("No function at the selected address.")
            return

        nodes: list[dict[str, Any]] = data.get("nodes", [])
        edges: list[dict[str, Any]] = data.get("edges", [])
        entry: str = data.get("entry", "")
        fn_name: str = data.get("function", "")
        truncated: bool = bool(data.get("truncated", False))

        if not nodes:
            self._show_placeholder(f"No basic blocks found for {fn_name!r}.")
            return

        node_ids = {n["id"] for n in nodes}
        layers = self._assign_layers(nodes, edges, entry, node_ids)
        positions, node_h = self._compute_positions(nodes, layers)
        pal = self._palette

        for edge in edges:
            src, dst = edge.get("from", ""), edge.get("to", "")
            if src in positions and dst in positions:
                self._draw_edge(src, dst, edge.get("type", ""), positions, node_h, pal)

        for node in nodes:
            nid = node["id"]
            if nid not in positions:
                continue
            x, y = positions[nid]
            h = node_h[nid]
            item = _BlockItem(node, x, y, h, pal, self._navigate)
            self._scene.addItem(item)

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))
        self._view.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self._view._zoom = 1.0

        trunc = "  (truncated: too many blocks)" if truncated else ""
        self._status.setText(
            f"{fn_name}  ·  {len(nodes)} blocks  ·  {len(edges)} edges{trunc}"
            f"  ·  scroll=zoom  drag=pan  click block=navigate"
        )

    def _navigate(self, addr: str) -> None:
        self.navigate_requested.emit(addr)

    # ------------------------------------------------------------------
    # Layout

    def _assign_layers(
        self,
        nodes: list[dict],
        edges: list[dict],
        entry: str,
        node_ids: set[str],
    ) -> dict[str, int]:
        succ: dict[str, list[str]] = {n["id"]: [] for n in nodes}
        for e in edges:
            s, d = e.get("from", ""), e.get("to", "")
            if s in succ and d in node_ids:
                succ[s].append(d)

        start = entry if entry in node_ids else (nodes[0]["id"] if nodes else "")
        layers: dict[str, int] = {}
        if not start:
            return layers

        queue = [start]
        layers[start] = 0
        visited = {start}
        while queue:
            curr = queue.pop(0)
            for nxt in succ.get(curr, []):
                if nxt not in visited:
                    layers[nxt] = layers[curr] + 1
                    visited.add(nxt)
                    queue.append(nxt)

        max_layer = max(layers.values(), default=0)
        for n in nodes:
            if n["id"] not in layers:
                max_layer += 1
                layers[n["id"]] = max_layer

        return layers

    def _compute_positions(
        self,
        nodes: list[dict],
        layers: dict[str, int],
    ) -> tuple[dict[str, tuple[float, float]], dict[str, float]]:
        node_h: dict[str, float] = {
            n["id"]: _node_height(n.get("total_insns", len(n.get("instructions", []))))
            for n in nodes
        }

        if not layers:
            return {}, node_h

        max_layer = max(layers.values())
        by_layer: list[list[str]] = [[] for _ in range(max_layer + 1)]
        for n in nodes:
            by_layer[layers.get(n["id"], max_layer)].append(n["id"])

        def _hex_key(addr: str) -> int:
            try:
                return int(addr.strip(), 16)
            except ValueError:
                return 0

        for layer in by_layer:
            layer.sort(key=_hex_key)

        y_pos: list[float] = [0.0] * (max_layer + 1)
        for i in range(1, max_layer + 1):
            prev_max_h = max(
                (node_h.get(nid, _HEADER_H + _PAD_BOTTOM) for nid in by_layer[i - 1]),
                default=80.0,
            )
            y_pos[i] = y_pos[i - 1] + prev_max_h + _ROW_GAP

        positions: dict[str, tuple[float, float]] = {}
        for i, layer in enumerate(by_layer):
            if not layer:
                continue
            total_w = len(layer) * _NODE_W + (len(layer) - 1) * _COL_GAP
            start_x = -total_w / 2.0
            for j, nid in enumerate(layer):
                x = start_x + j * (_NODE_W + _COL_GAP)
                positions[nid] = (x, y_pos[i])

        return positions, node_h

    # ------------------------------------------------------------------
    # Edge drawing

    def _draw_edge(
        self,
        src: str,
        dst: str,
        flow_type: str,
        positions: dict[str, tuple[float, float]],
        node_h: dict[str, float],
        pal: CfgPalette,
    ) -> None:
        sx, sy = positions[src]
        dx, dy = positions[dst]
        sh = node_h.get(src, 80.0)

        x1 = sx + _NODE_W / 2.0
        y1 = sy + sh
        x2 = dx + _NODE_W / 2.0
        y2 = dy

        color = self._edge_color(flow_type, pal)
        pen = QPen(color, 1.4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)

        path = QPainterPath()
        path.moveTo(x1, y1)

        if y2 > y1:
            mid_y = (y1 + y2) / 2.0
            path.cubicTo(x1, mid_y, x2, mid_y, x2, y2)
        else:
            offset = _NODE_W * 0.75
            path.cubicTo(x1 + offset, y1 + 50, x2 + offset, y2 - 50, x2, y2)

        edge_item = QGraphicsPathItem(path)
        edge_item.setPen(pen)
        self._scene.addItem(edge_item)

        size = 7.0
        pts = QPolygonF([
            QPointF(x2, y2),
            QPointF(x2 - size / 2.0, y2 - size),
            QPointF(x2 + size / 2.0, y2 - size),
        ])
        arrow = QGraphicsPolygonItem(pts)
        arrow.setBrush(QBrush(color))
        arrow.setPen(QPen(Qt.PenStyle.NoPen))
        self._scene.addItem(arrow)

    @staticmethod
    def _edge_color(flow_type: str, pal: CfgPalette) -> QColor:
        ft = flow_type.upper()
        if "CONDITIONAL" in ft:
            return QColor(pal.edge_cond)
        if "FALL" in ft:
            return QColor(pal.edge_fall)
        if "UNCONDITIONAL" in ft:
            return QColor(pal.edge_uncond)
        return QColor(pal.edge_other)
