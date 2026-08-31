export const styles = `
:root { color: var(--xsec-text-primary); background: var(--xsec-surface-base); font-family: var(--xsec-font-family); color-scheme: var(--xsec-color-mode); }
* { box-sizing: border-box; }
body { margin: 0; background: var(--xsec-surface-base); }
button, input, select, textarea { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .56; }
.ad-app { min-height: 100vh; padding: 24px; color: var(--xsec-text-primary); background: var(--xsec-surface-base); }
.ad-header, .ad-toolbar, .ad-tab-row, .ad-console-header, .ad-section-title, .ad-actions, .ad-filter-row, .ad-form-actions { display: flex; align-items: center; gap: 10px; }
.ad-header, .ad-console-header { justify-content: space-between; align-items: flex-start; }
.ad-eyebrow { margin: 0 0 6px; color: var(--xsec-text-tertiary); font-size: 11px; font-weight: 700; letter-spacing: .08em; }
.ad-title { margin: 0; font-size: 24px; line-height: 1.25; letter-spacing: -.02em; }
.ad-description, .ad-muted { color: var(--xsec-text-secondary); }
.ad-description { margin: 7px 0 0; max-width: 720px; font-size: 13px; }
.ad-button, .ad-input, .ad-select, .ad-textarea { border: 1px solid var(--xsec-border); border-radius: var(--xsec-radius-md); color: var(--xsec-text-primary); background: var(--xsec-surface-container); }
.ad-button { min-height: var(--xsec-control-height); padding: 0 12px; font-weight: 650; }
.ad-button:hover:not(:disabled) { background: var(--xsec-surface-hover); }
.ad-button.primary { border-color: var(--xsec-accent); color: #fff; background: var(--xsec-accent); }
.ad-button.primary:hover:not(:disabled) { background: var(--xsec-accent-strong); }
.ad-button.danger { color: var(--xsec-status-error); }
.ad-button.text { border-color: transparent; background: transparent; color: var(--xsec-text-secondary); }
.ad-button.compact { min-height: 28px; padding: 0 8px; font-size: 12px; }
.ad-tab-row { margin-top: 24px; justify-content: space-between; border-bottom: 1px solid var(--xsec-border-subtle); }
.ad-tabs, .ad-kpis, .ad-status-tabs { display: flex; align-items: center; gap: 6px; }
.ad-tab { position: relative; border: 0; padding: 10px 8px; color: var(--xsec-text-secondary); background: transparent; font-weight: 650; }
.ad-tab.active { color: var(--xsec-text-primary); }
.ad-tab.active::after { position: absolute; right: 8px; bottom: -1px; left: 8px; height: 2px; content: ""; background: var(--xsec-accent); }
.ad-kpis { color: var(--xsec-text-secondary); font-size: 12px; }
.ad-kpis strong { color: var(--xsec-text-primary); }
.ad-runs, .ad-assets { margin-top: 18px; }
.ad-toolbar, .ad-filter-row { flex-wrap: wrap; margin-bottom: 14px; }
.ad-input, .ad-select { min-height: var(--xsec-control-height); padding: 0 10px; }
.ad-input.search { min-width: 260px; }
.ad-input:focus, .ad-select:focus, .ad-textarea:focus { outline: 2px solid var(--xsec-accent); outline-offset: 1px; }
.ad-status-tab { min-width: 72px; padding: 8px 10px; border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-md); color: var(--xsec-text-secondary); background: var(--xsec-surface-container); text-align: left; }
.ad-status-tab strong { display: block; margin-top: 2px; color: var(--xsec-text-primary); font-size: 16px; }
.ad-status-tab.active { border-color: var(--xsec-accent); background: var(--xsec-accent-soft); }
.ad-master-detail { display: grid; grid-template-columns: minmax(270px, 31%) minmax(0, 1fr); min-height: 560px; border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-lg); overflow: hidden; background: var(--xsec-surface-container); }
.ad-run-list { min-height: 0; border-right: 1px solid var(--xsec-border-subtle); overflow: auto; background: var(--xsec-surface-subtle); }
.ad-run-card { width: 100%; padding: 14px; border: 0; border-bottom: 1px solid var(--xsec-border-subtle); color: inherit; background: transparent; text-align: left; }
.ad-run-card:hover, .ad-run-card.active { background: var(--xsec-accent-soft); }
.ad-run-card-title, .ad-metadata { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.ad-run-card-title strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ad-run-card p { margin: 7px 0; overflow: hidden; color: var(--xsec-text-secondary); text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.ad-run-outcome { display: block; margin: 0 0 7px; overflow: hidden; color: var(--xsec-status-error); text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
.ad-metadata { color: var(--xsec-text-tertiary); font-size: 11px; }
.ad-status { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 99px; font-size: 11px; font-weight: 700; }
.ad-status.running { color: var(--xsec-status-info); background: var(--xsec-accent-soft); }
.ad-status.completed { color: var(--xsec-status-success); background: color-mix(in srgb, var(--xsec-status-success) 12%, transparent); }
.ad-status.failed, .ad-status.cancelled { color: var(--xsec-status-error); background: color-mix(in srgb, var(--xsec-status-error) 12%, transparent); }
.ad-status.other { color: var(--xsec-text-secondary); background: var(--xsec-surface-container); }
.ad-console { min-width: 0; overflow: auto; }
.ad-console-header { padding: 20px 20px 16px; border-bottom: 1px solid var(--xsec-border-subtle); }
.ad-console-header h2 { margin: 0; font-size: 18px; }
.ad-console-body { display: grid; gap: 16px; padding: 18px 20px 24px; }
.ad-flow { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
.ad-flow-card { min-height: 96px; padding: 11px; border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-md); background: var(--xsec-surface-subtle); }
.ad-flow-card.active { border-color: var(--xsec-status-info); }
.ad-flow-card.failed { border-color: var(--xsec-status-error); }
.ad-flow-card.done { border-color: var(--xsec-status-success); }
.ad-flow-card strong, .ad-flow-card small { display: block; }
.ad-flow-card small { margin-top: 8px; color: var(--xsec-text-secondary); font-size: 11px; line-height: 1.4; }
.ad-card, .ad-section { border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-md); background: var(--xsec-surface-container); }
.ad-section-title { justify-content: space-between; min-height: 42px; padding: 0 13px; border-bottom: 1px solid var(--xsec-border-subtle); font-size: 13px; }
.ad-section-body { padding: 13px; }
.ad-split { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(250px, .8fr); gap: 14px; }
.ad-code { max-height: 260px; margin: 0; overflow: auto; padding: 12px; border-radius: var(--xsec-radius-sm); color: var(--xsec-text-primary); background: var(--xsec-surface-subtle); font: 12px/1.55 var(--xsec-font-family); white-space: pre-wrap; word-break: break-word; }
.ad-process { display: grid; gap: 8px; max-height: 360px; overflow: auto; }
.ad-process-wrap { display: grid; gap: 9px; }
.ad-process-live { margin: 0; color: var(--xsec-status-info); font-size: 12px; }
.ad-new-records { justify-self: end; }
.ad-message, .ad-tool { padding: 10px; border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-sm); background: var(--xsec-surface-subtle); }
.ad-message header, .ad-tool summary { color: var(--xsec-text-secondary); font-size: 11px; font-weight: 700; }
.ad-message p { margin: 7px 0 0; white-space: pre-wrap; word-break: break-word; }
.ad-message pre { margin: 7px 0 0; overflow: auto; color: var(--xsec-text-primary); font: 12px/1.55 var(--xsec-font-family); white-space: pre-wrap; word-break: break-word; }
.ad-tool summary { cursor: pointer; }
.ad-tool .ad-code { margin-top: 8px; max-height: 180px; }
.ad-tool-value { margin-top: 10px; }
.ad-tool-value > strong { color: var(--xsec-text-tertiary); font-size: 11px; }
.ad-inspector { display: grid; grid-template-columns: 120px minmax(0, 1fr); margin: 0; }
.ad-inspector dt, .ad-inspector dd { margin: 0; padding: 8px 0; border-bottom: 1px solid var(--xsec-border-subtle); font-size: 12px; }
.ad-inspector dt { color: var(--xsec-text-tertiary); }
.ad-inspector dd { overflow: hidden; color: var(--xsec-text-secondary); text-overflow: ellipsis; }
.ad-table-wrap { overflow: auto; border: 1px solid var(--xsec-border-subtle); border-radius: var(--xsec-radius-md); }
.ad-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.ad-table th, .ad-table td { padding: 10px 12px; border-bottom: 1px solid var(--xsec-border-subtle); text-align: left; vertical-align: middle; }
.ad-table th { color: var(--xsec-text-tertiary); background: var(--xsec-surface-subtle); font-size: 11px; }
.ad-table td.ellipsis { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ad-pagination { display: flex; align-items: center; justify-content: flex-end; gap: 8px; margin-top: 14px; color: var(--xsec-text-secondary); font-size: 12px; }
.ad-empty, .ad-error { padding: 40px 24px; color: var(--xsec-text-secondary); text-align: center; }
.ad-error { color: var(--xsec-status-error); }
.ad-notice { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid var(--xsec-status-warning); border-radius: var(--xsec-radius-md); color: var(--xsec-text-primary); background: color-mix(in srgb, var(--xsec-status-warning) 12%, var(--xsec-surface-container)); }
.ad-modal-backdrop { position: fixed; z-index: 5; inset: 0; display: grid; place-items: center; padding: 18px; background: color-mix(in srgb, #000 52%, transparent); }
.ad-modal { width: min(680px, 100%); max-height: min(760px, 100%); overflow: auto; border: 1px solid var(--xsec-border); border-radius: var(--xsec-radius-lg); background: var(--xsec-surface-container); box-shadow: 0 18px 48px rgba(0, 0, 0, .32); }
.ad-modal header { padding: 17px 18px; border-bottom: 1px solid var(--xsec-border-subtle); font-size: 16px; font-weight: 700; }
.ad-modal main { padding: 18px; }
.ad-modal footer { display: flex; justify-content: flex-end; gap: 8px; padding: 14px 18px; border-top: 1px solid var(--xsec-border-subtle); }
.ad-field { display: grid; gap: 7px; margin-bottom: 15px; color: var(--xsec-text-secondary); font-size: 12px; font-weight: 650; }
.ad-field .ad-input, .ad-field .ad-select, .ad-field .ad-textarea { width: 100%; color: var(--xsec-text-primary); font-weight: 400; }
.ad-textarea { min-height: 142px; padding: 10px; resize: vertical; }
.ad-field-error { color: var(--xsec-status-error); font-weight: 500; }
.ad-confirm-detail { margin: 0; color: var(--xsec-text-secondary); line-height: 1.65; }
.ad-credential { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; align-items: center; margin: 9px 0; }
.ad-settings { max-width: 760px; }
@media (max-width: 900px) { .ad-master-detail, .ad-split { grid-template-columns: 1fr; } .ad-run-list { max-height: 300px; border-right: 0; border-bottom: 1px solid var(--xsec-border-subtle); } .ad-flow { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 620px) { .ad-app { padding: 16px; } .ad-header, .ad-tab-row, .ad-console-header { display: grid; } .ad-kpis { flex-wrap: wrap; } .ad-flow { grid-template-columns: 1fr; } .ad-credential { grid-template-columns: 1fr; } .ad-actions { flex-wrap: wrap; } }
`;
