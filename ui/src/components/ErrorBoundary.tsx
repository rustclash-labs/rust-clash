import React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
  scope?: string;
  resetKey?: string;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Resilient React error boundary that isolates runtime render failures to the
 * failing panel (or root shell) instead of leaving users on a blank white screen.
 */
export class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error(
      `[RustClash UI ErrorBoundary:${this.props.scope ?? "root"}]`,
      error,
      info.componentStack,
    );
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps): void {
    if (
      this.state.error &&
      this.props.resetKey !== undefined &&
      prevProps.resetKey !== this.props.resetKey
    ) {
      this.setState({ error: null });
    }
  }

  private handleReset = (): void => {
    this.setState({ error: null });
  };

  private handleReload = (): void => {
    if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  render(): React.ReactNode {
    const { error } = this.state;
    if (!error) {
      return this.props.children;
    }

    const isZh =
      typeof document !== "undefined"
        ? !document.documentElement.lang.toLowerCase().startsWith("en")
        : true;

    return (
      <div
        role="alert"
        className="bento-card"
        style={{
          margin: this.props.scope === "app" ? "32px auto" : "12px 0",
          maxWidth: this.props.scope === "app" ? 560 : undefined,
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        <div
          style={{
            fontSize: 15,
            fontWeight: 700,
            color: "var(--accent-rose, #e11d48)",
          }}
        >
          {isZh ? "页面渲染遇到意外错误" : "Unexpected UI Rendering Error"}
        </div>
        <div
          style={{
            fontSize: 13,
            color: "var(--text-muted, #64748b)",
            lineHeight: 1.5,
          }}
        >
          {isZh
            ? "后台代理引擎仍在正常运行，你可以尝试重新渲染当前视图或刷新界面。"
            : "The underlying proxy core is unaffected. You can retry rendering this view or reload the UI."}
        </div>
        <pre
          className="mono"
          style={{
            margin: 0,
            padding: "10px 12px",
            borderRadius: 10,
            fontSize: 12,
            background: "var(--bg-subtle, rgba(148, 163, 184, 0.12))",
            overflowX: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {error.message || String(error)}
        </pre>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={this.handleReset}
          >
            {isZh ? "重试当前视图" : "Retry View"}
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={this.handleReload}
          >
            {isZh ? "刷新应用" : "Reload App"}
          </button>
        </div>
      </div>
    );
  }
}
