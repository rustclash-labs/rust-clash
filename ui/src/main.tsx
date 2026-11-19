import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider } from "./i18n";
import "./styles/index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <ErrorBoundary scope="app">
        <App />
      </ErrorBoundary>
    </I18nProvider>
  </React.StrictMode>,
);
