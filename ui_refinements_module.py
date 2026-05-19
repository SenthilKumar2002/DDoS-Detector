"""
🎨 UI REFINEMENTS MODULE v1.0
Enterprise Dashboard Enhancements & Usability Improvements
Integrates with CYBERCORE DDoS MAINFRAME v4.0
"""

from dash import html, dcc, Input, Output, State
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json

# ============================================================================
# 🎨 ADVANCED THEME SYSTEM WITH MULTIPLE PRESETS
# ============================================================================

THEME_PRESETS = {
    "dark_blue": {
        "name": "Dark Blue (Default)",
        "bg_main": "#0f1419",
        "bg_card": "#1a1f2a",
        "bg_hover": "#242f3f",
        "border": "#2d3748",
        "text": "#e2e8f0",
        "text_secondary": "#cbd5e0",
        "muted": "#94a3b8",
        "cyan": "#06b6d4",
        "amber": "#f59e0b",
        "crimson": "#ef4444",
        "green": "#10b981",
        "blue": "#3b82f6",
        "purple": "#a855f7",
        "orange": "#f97316"
    },
    "dark_slate": {
        "name": "Dark Slate",
        "bg_main": "#0f172a",
        "bg_card": "#1e293b",
        "bg_hover": "#334155",
        "border": "#475569",
        "text": "#f1f5f9",
        "text_secondary": "#cbd5e0",
        "muted": "#94a3b8",
        "cyan": "#22d3ee",
        "amber": "#fbbf24",
        "crimson": "#f87171",
        "green": "#4ade80",
        "blue": "#60a5fa",
        "purple": "#d8b4fe",
        "orange": "#fb923c"
    },
    "high_contrast": {
        "name": "High Contrast (Accessibility)",
        "bg_main": "#000000",
        "bg_card": "#1a1a1a",
        "bg_hover": "#333333",
        "border": "#666666",
        "text": "#ffffff",
        "text_secondary": "#e0e0e0",
        "muted": "#999999",
        "cyan": "#00ffff",
        "amber": "#ffff00",
        "crimson": "#ff0000",
        "green": "#00ff00",
        "blue": "#0099ff",
        "purple": "#ff00ff",
        "orange": "#ff8800"
    },
    "corporate": {
        "name": "Corporate Blue",
        "bg_main": "#1a2332",
        "bg_card": "#2a3f5f",
        "bg_hover": "#3d5a80",
        "border": "#3d5a80",
        "text": "#ecf0f1",
        "text_secondary": "#bdc3c7",
        "muted": "#95a5a6",
        "cyan": "#1abc9c",
        "amber": "#f39c12",
        "crimson": "#e74c3c",
        "green": "#27ae60",
        "blue": "#2980b9",
        "purple": "#8e44ad",
        "orange": "#d35400"
    }
}

# ============================================================================
# 📊 ENHANCED CHART COMPONENTS
# ============================================================================

class EnhancedCharts:
    """Advanced chart generation with professional styling"""
    
    @staticmethod
    def create_timeline_chart(timeline_data: list, theme: dict) -> go.Figure:
        """
        Create professional timeline chart with multiple features
        
        Args:
            timeline_data: List of attack events with timestamp
            theme: Theme dictionary
        
        Returns:
            Plotly figure object
        """
        if not timeline_data:
            fig = go.Figure()
            fig.add_annotation(text="No attack data available", showarrow=False)
            return fig
        
        # Prepare data
        timestamps = [e["datetime"] for e in timeline_data]
        packet_rates = [e["pps"] for e in timeline_data]
        tools = [e["tool"] for e in timeline_data]
        risks = [e["risk"] for e in timeline_data]
        
        # Create scatter plot with color coding by risk
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=packet_rates,
            mode='markers+lines',
            name='Attack Rate',
            marker=dict(
                size=8,
                color=risks,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(
                    title="Risk Score",
                    thickness=15,
                    len=0.7
                ),
                line=dict(width=2, color=theme["border"])
            ),
            line=dict(color=theme["cyan"], width=2),
            hovertemplate='<b>%{customdata[0]}</b><br>' +
                         'Time: %{x}<br>' +
                         'Rate: %{y} pps<br>' +
                         'Risk: %{customdata[1]:.0f}<extra></extra>',
            customdata=[[tools[i], risks[i]] for i in range(len(tools))]
        ))
        
        fig.update_layout(
            title="Attack Timeline (Last 24 Hours)",
            xaxis_title="Time",
            yaxis_title="Packets/Second",
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font=dict(color=theme["text"], family="Monaco, monospace"),
            hovermode="x unified",
            margin=dict(l=60, r=60, t=60, b=60),
            height=400,
            xaxis=dict(showgrid=False, gridcolor=theme["border"]),
            yaxis=dict(showgrid=True, gridcolor=theme["border"])
        )
        
        return fig
    
    @staticmethod
    def create_heatmap_chart(hourly_data: dict, theme: dict) -> go.Figure:
        """
        Create heatmap of attack distribution across hours
        
        Args:
            hourly_data: Dictionary of hourly statistics
            theme: Theme dictionary
        
        Returns:
            Plotly figure object
        """
        if not hourly_data:
            fig = go.Figure()
            fig.add_annotation(text="No data available", showarrow=False)
            return fig
        
        # Prepare data for heatmap
        hours = sorted(hourly_data.keys())
        counts = [hourly_data[h]["count"] for h in hours]
        peaks = [hourly_data[h]["peak_pps"] for h in hours]
        
        fig = go.Figure(data=go.Heatmap(
            z=peaks,
            x=hours,
            y=["Peak PPS"],
            colorscale='Reds',
            colorbar=dict(title="PPS"),
            hovertemplate='<b>%{x}</b><br>Peak: %{z} pps<extra></extra>'
        ))
        
        fig.update_layout(
            title="Attack Activity Heatmap",
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font=dict(color=theme["text"]),
            margin=dict(l=60, r=60, t=60, b=60),
            height=200
        )
        
        return fig
    
    @staticmethod
    def create_session_duration_chart(sessions: list, theme: dict) -> go.Figure:
        """
        Create bar chart of attack session durations
        
        Args:
            sessions: List of session dictionaries
            theme: Theme dictionary
        
        Returns:
            Plotly figure object
        """
        if not sessions:
            fig = go.Figure()
            fig.add_annotation(text="No sessions", showarrow=False)
            return fig
        
        # Top 10 sessions by duration
        top_sessions = sorted(sessions, 
                             key=lambda x: x["duration_seconds"], 
                             reverse=True)[:10]
        
        labels = [f"{s['source_ip']} ({s['tool']})" for s in top_sessions]
        durations = [s["duration_seconds"] / 60 for s in top_sessions]  # Convert to minutes
        
        fig = go.Figure(data=[
            go.Bar(
                x=labels,
                y=durations,
                marker=dict(
                    color=durations,
                    colorscale='Reds',
                    showscale=False,
                    line=dict(color=theme["border"], width=2)
                ),
                text=[f"{d:.1f}m" for d in durations],
                textposition="auto",
                hovertemplate='<b>%{x}</b><br>Duration: %{y:.1f} minutes<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Top 10 Longest Attack Sessions",
            yaxis_title="Duration (Minutes)",
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font=dict(color=theme["text"]),
            margin=dict(l=60, r=60, t=60, b=100),
            height=350,
            xaxis_tickangle=-45,
            showlegend=False
        )
        
        return fig

# ============================================================================
# 🖼️ ENTERPRISE UI COMPONENTS
# ============================================================================

class EnterpriseUIComponents:
    """Professional UI components for enterprise dashboards"""
    
    @staticmethod
    def create_status_indicator(status: str, theme: dict) -> html.Div:
        """
        Create professional status indicator with animation
        
        Args:
            status: "secure", "warning", "critical"
            theme: Theme dictionary
        
        Returns:
            HTML div component
        """
        status_config = {
            "secure": {
                "icon": "✓",
                "color": theme["green"],
                "bg": "#0c211a",
                "text": "SECURE",
                "animation": "pulse"
            },
            "warning": {
                "icon": "!",
                "color": theme["amber"],
                "bg": "#332701",
                "text": "WARNING",
                "animation": "pulse-amber"
            },
            "critical": {
                "icon": "✕",
                "color": theme["crimson"],
                "bg": "#3f0f0f",
                "text": "CRITICAL",
                "animation": "pulse-critical"
            }
        }
        
        config = status_config.get(status, status_config["secure"])
        
        return html.Div([
            html.Style(f"""
                @keyframes pulse {{
                    0%, 100% {{ opacity: 1; }}
                    50% {{ opacity: 0.5; }}
                }}
                @keyframes pulse-amber {{
                    0%, 100% {{ box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7); }}
                    70% {{ box-shadow: 0 0 0 10px rgba(245, 158, 11, 0); }}
                }}
                @keyframes pulse-critical {{
                    0%, 100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
                    70% {{ box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }}
                }}
                .status-icon {{
                    animation: {config['animation']} 2s infinite;
                }}
            """),
            html.Div(
                style={
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "center",
                    "gap": "10px",
                    "padding": "12px 20px",
                    "borderRadius": "8px",
                    "backgroundColor": config["bg"],
                    "border": f"2px solid {config['color']}"
                },
                children=[
                    html.Div(
                        config["icon"],
                        className="status-icon",
                        style={
                            "fontSize": "24px",
                            "color": config["color"],
                            "fontWeight": "bold"
                        }
                    ),
                    html.Span(
                        config["text"],
                        style={
                            "color": config["color"],
                            "fontSize": "14px",
                            "fontWeight": "bold",
                            "letterSpacing": "1px"
                        }
                    )
                ]
            )
        ])
    
    @staticmethod
    def create_metric_card(label: str, value: str, unit: str = "", 
                          icon: str = "", trend: str = "", 
                          theme: dict = None) -> html.Div:
        """
        Create professional metric card with trending indicators
        
        Args:
            label: Metric label
            value: Metric value
            unit: Unit of measurement
            icon: Emoji or text icon
            trend: "up", "down", "stable"
            theme: Theme dictionary
        
        Returns:
            HTML div component
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        trend_config = {
            "up": {"icon": "↑", "color": theme["crimson"]},
            "down": {"icon": "↓", "color": theme["green"]},
            "stable": {"icon": "→", "color": theme["amber"]}
        }
        
        trend_info = trend_config.get(trend, {})
        
        return html.Div(
            style={
                "backgroundColor": theme["bg_card"],
                "border": f"1px solid {theme['border']}",
                "borderRadius": "8px",
                "padding": "20px",
                "marginBottom": "15px",
                "transition": "all 0.3s ease",
                "boxShadow": f"0 2px 8px rgba(0,0,0,0.2)"
            },
            children=[
                html.Div(
                    style={
                        "display": "flex",
                        "justifyContent": "space-between",
                        "alignItems": "flex-start",
                        "marginBottom": "12px"
                    },
                    children=[
                        html.Span(
                            label,
                            style={
                                "color": theme["muted"],
                                "fontSize": "12px",
                                "textTransform": "uppercase",
                                "letterSpacing": "0.5px",
                                "fontWeight": "600"
                            }
                        ),
                        html.Span(
                            f"{icon}",
                            style={"fontSize": "20px"}
                        ) if icon else None
                    ]
                ),
                html.Div(
                    style={
                        "display": "flex",
                        "alignItems": "baseline",
                        "gap": "8px"
                    },
                    children=[
                        html.Span(
                            value,
                            style={
                                "fontSize": "32px",
                                "fontWeight": "bold",
                                "color": theme["cyan"],
                                "fontFamily": "Monaco, monospace"
                            }
                        ),
                        html.Span(
                            unit,
                            style={
                                "fontSize": "14px",
                                "color": theme["muted"]
                            }
                        )
                    ]
                ),
                html.Div(
                    style={
                        "marginTop": "12px",
                        "display": "flex",
                        "alignItems": "center",
                        "gap": "6px"
                    },
                    children=[
                        html.Span(
                            trend_info.get("icon", ""),
                            style={
                                "color": trend_info.get("color", theme["muted"]),
                                "fontSize": "14px",
                                "fontWeight": "bold"
                            }
                        ) if trend else None
                    ]
                ) if trend else None
            ]
        )
    
    @staticmethod
    def create_info_panel(title: str, content: list, 
                         theme: dict = None, icon: str = "") -> html.Div:
        """
        Create professional information panel
        
        Args:
            title: Panel title
            content: List of content items
            theme: Theme dictionary
            icon: Emoji/icon for title
        
        Returns:
            HTML div component
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        return html.Div(
            style={
                "backgroundColor": theme["bg_card"],
                "border": f"1px solid {theme['border']}",
                "borderRadius": "8px",
                "padding": "20px",
                "marginBottom": "15px"
            },
            children=[
                html.H4(
                    f"{icon} {title}" if icon else title,
                    style={
                        "color": theme["cyan"],
                        "marginTop": "0",
                        "marginBottom": "15px",
                        "fontSize": "14px",
                        "fontWeight": "600",
                        "textTransform": "uppercase",
                        "letterSpacing": "0.5px"
                    }
                ),
                html.Div(
                    style={
                        "color": theme["text"],
                        "fontSize": "13px",
                        "lineHeight": "1.8"
                    },
                    children=[
                        html.P(item, style={"marginBottom": "8px"})
                        for item in content
                    ]
                )
            ]
        )

# ============================================================================
# 📋 DATA GRID / TABLE COMPONENTS
# ============================================================================

class DataGridComponent:
    """Professional data grid/table components"""
    
    @staticmethod
    def create_attack_table(attacks: list, theme: dict = None) -> html.Table:
        """
        Create professional attack data table
        
        Args:
            attacks: List of attack records
            theme: Theme dictionary
        
        Returns:
            HTML table component
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        if not attacks:
            return html.Div("No attacks recorded", 
                          style={"color": theme["muted"], "padding": "20px"})
        
        header_style = {
            "backgroundColor": theme["bg_hover"],
            "color": theme["cyan"],
            "padding": "12px",
            "textAlign": "left",
            "fontWeight": "bold",
            "fontSize": "12px",
            "textTransform": "uppercase",
            "letterSpacing": "0.5px",
            "borderBottom": f"2px solid {theme['border']}"
        }
        
        cell_style = {
            "padding": "12px",
            "borderBottom": f"1px solid {theme['border']}",
            "fontSize": "12px",
            "color": theme["text"]
        }
        
        return html.Table(
            style={
                "width": "100%",
                "borderCollapse": "collapse",
                "backgroundColor": theme["bg_card"]
            },
            children=[
                html.Thead(
                    html.Tr([
                        html.Th("Time", style=header_style),
                        html.Th("Source IP", style=header_style),
                        html.Th("Tool", style=header_style),
                        html.Th("PPS", style=header_style),
                        html.Th("Risk", style=header_style),
                        html.Th("Confidence", style=header_style)
                    ])
                ),
                html.Tbody([
                    html.Tr([
                        html.Td(attack.get("time_of_day", ""), style=cell_style),
                        html.Td(attack.get("source_ip", ""), style={
                            **cell_style,
                            "color": theme["amber"],
                            "fontFamily": "Monaco, monospace"
                        }),
                        html.Td(attack.get("tool", ""), style={
                            **cell_style,
                            "color": theme["cyan"]
                        }),
                        html.Td(f"{attack.get('pps', 0)} pps", style=cell_style),
                        html.Td(f"{attack.get('risk', 0):.0f}%", style={
                            **cell_style,
                            "color": theme["crimson"] if attack.get("risk", 0) > 70 else theme["amber"]
                        }),
                        html.Td(f"{attack.get('confidence', 0):.0f}%", style=cell_style)
                    ])
                    for attack in attacks[:20]  # Show top 20
                ])
            ]
        )

# ============================================================================
# 🎛️ CONTROL COMPONENTS
# ============================================================================

class ControlComponents:
    """Advanced control and input components"""
    
    @staticmethod
    def create_advanced_slider(label: str, min_val: float, max_val: float,
                              current_val: float, step: float = 0.1,
                              theme: dict = None) -> html.Div:
        """
        Create styled slider component
        
        Args:
            label: Slider label
            min_val: Minimum value
            max_val: Maximum value
            current_val: Current value
            step: Step size
            theme: Theme dictionary
        
        Returns:
            HTML div containing slider
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        return html.Div(
            style={
                "backgroundColor": theme["bg_card"],
                "border": f"1px solid {theme['border']}",
                "borderRadius": "8px",
                "padding": "20px",
                "marginBottom": "15px"
            },
            children=[
                html.Label(
                    label,
                    style={
                        "display": "block",
                        "color": theme["cyan"],
                        "fontSize": "12px",
                        "fontWeight": "600",
                        "marginBottom": "12px",
                        "textTransform": "uppercase",
                        "letterSpacing": "0.5px"
                    }
                ),
                dcc.Slider(
                    min=min_val,
                    max=max_val,
                    step=step,
                    value=current_val,
                    marks={i: str(i) for i in range(int(min_val), int(max_val)+1)},
                    tooltip={"placement": "bottom", "always_visible": True},
                    included=False,
                    updatemode='drag'
                ),
                html.Div(
                    id=f"{label}-explanation",
                    style={
                        "marginTop": "10px",
                        "fontSize": "11px",
                        "color": theme["muted"],
                        "fontStyle": "italic"
                    }
                )
            ]
        )

# ============================================================================
# 📱 RESPONSIVE LAYOUT HELPERS
# ============================================================================

class ResponsiveLayout:
    """Responsive layout utilities for various screen sizes"""
    
    @staticmethod
    def create_grid_layout(items: list, columns: int = 3, 
                          gap: int = 20) -> html.Div:
        """
        Create responsive grid layout
        
        Args:
            items: List of items to display
            columns: Number of columns
            gap: Gap between items in pixels
        
        Returns:
            HTML div with grid layout
        """
        return html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": f"repeat({columns}, 1fr)",
                "gap": f"{gap}px",
                "marginBottom": f"{gap}px"
            },
            children=items
        )
    
    @staticmethod
    def create_responsive_tabs(tabs_content: dict, theme: dict = None) -> dcc.Tabs:
        """
        Create styled responsive tabs
        
        Args:
            tabs_content: Dictionary of tab names and content
            theme: Theme dictionary
        
        Returns:
            Dash Tabs component
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        tabs = [
            dcc.Tab(
                label=name,
                value=idx,
                children=content,
                style={
                    "padding": "20px",
                    "backgroundColor": theme["bg_card"],
                    "color": theme["text"]
                },
                selected_style={
                    "padding": "20px",
                    "backgroundColor": theme["bg_card"],
                    "color": theme["cyan"],
                    "borderTop": f"3px solid {theme['cyan']}"
                }
            )
            for idx, (name, content) in enumerate(tabs_content.items())
        ]
        
        return dcc.Tabs(
            children=tabs,
            style={
                "backgroundColor": theme["bg_main"],
                "border": f"1px solid {theme['border']}"
            }
        )

# ============================================================================
# 🔔 NOTIFICATION SYSTEM
# ============================================================================

class NotificationSystem:
    """Advanced notification and alert components"""
    
    @staticmethod
    def create_notification(message: str, notification_type: str = "info",
                          theme: dict = None, dismissible: bool = True) -> html.Div:
        """
        Create styled notification/alert
        
        Args:
            message: Notification message
            notification_type: "info", "warning", "error", "success"
            theme: Theme dictionary
            dismissible: Can user dismiss notification
        
        Returns:
            HTML div component
        """
        if theme is None:
            theme = THEME_PRESETS["dark_blue"]
        
        type_config = {
            "info": {"bg": f"{theme['blue']}20", "border_color": theme["blue"], "icon": "ℹ"},
            "warning": {"bg": f"{theme['amber']}20", "border_color": theme["amber"], "icon": "⚠"},
            "error": {"bg": f"{theme['crimson']}20", "border_color": theme["crimson"], "icon": "✕"},
            "success": {"bg": f"{theme['green']}20", "border_color": theme["green"], "icon": "✓"}
        }
        
        config = type_config.get(notification_type, type_config["info"])
        
        return html.Div(
            style={
                "backgroundColor": config["bg"],
                "border": f"2px solid {config['border_color']}",
                "borderRadius": "6px",
                "padding": "15px",
                "marginBottom": "15px",
                "display": "flex",
                "alignItems": "center",
                "gap": "12px"
            },
            children=[
                html.Span(
                    config["icon"],
                    style={
                        "fontSize": "18px",
                        "fontWeight": "bold",
                        "color": config["border_color"]
                    }
                ),
                html.Span(
                    message,
                    style={
                        "color": theme["text"],
                        "fontSize": "13px",
                        "flex": 1
                    }
                ),
                html.Button(
                    "✕",
                    style={
                        "backgroundColor": "transparent",
                        "border": "none",
                        "color": config["border_color"],
                        "fontSize": "16px",
                        "cursor": "pointer"
                    }
                ) if dismissible else None
            ]
        )
