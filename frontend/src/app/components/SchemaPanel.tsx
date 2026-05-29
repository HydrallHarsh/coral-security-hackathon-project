import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';

interface ColumnDef {
  column_name: string;
  data_type: string;
  is_required_filter?: boolean;
}

interface ToolDef {
  name: string;
  source: string;
  kind: string;
  purpose: string;
  available: boolean;
  columns: ColumnDef[];
  capabilities: string[];
}

interface SourceDef {
  available: boolean;
  configured: boolean;
  tools: string[];
}

interface CapabilitiesResponse {
  sources: Record<string, SourceDef>;
  tools: Record<string, ToolDef>;
}

interface SchemaPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SchemaPanel({ isOpen, onClose }: SchemaPanelProps) {
  const [data, setData] = useState<CapabilitiesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && !data) {
      setLoading(true);
      fetch('http://127.0.0.1:8000/agent/capabilities')
        .then((r) => r.json())
        .then((res) => {
          setData(res.capabilities);
          setLoading(false);
        })
        .catch((e) => {
          console.error(e);
          setLoading(false);
        });
    }
  }, [isOpen, data]);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            className="schema-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            className="schema-panel"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
          >
            <div className="schema-header">
              <h2>Coral Schema Intelligence</h2>
              <button className="schema-close" onClick={onClose}>×</button>
            </div>
            
            <div className="schema-body">
              <p className="schema-desc">
                HarborGuard automatically discovers the following tables and schemas from the local Coral SQL engine to plan its investigation.
              </p>

              {loading && <div className="schema-loading">Discovering schemas...</div>}
              
              {!loading && data && (
                <div className="schema-sources">
                  {Object.entries(data.sources).map(([sourceName, source]) => (
                    <div key={sourceName} className="schema-source-group">
                      <div className="schema-source-header">
                        <div className="schema-source-title">
                          <span className={`status-dot ${source.available ? 'online' : 'offline'}`} />
                          <span className="source-name">{sourceName}</span>
                        </div>
                        {source.available && <span className="badge success">Active</span>}
                        {!source.available && <span className="badge error">Unavailable</span>}
                      </div>

                      {source.available && (
                        <div className="schema-tools-list">
                          {source.tools.map((toolName) => {
                            const tool = data.tools[toolName];
                            if (!tool) return null;
                            const isExpanded = expandedTool === toolName;

                            return (
                              <div key={toolName} className="schema-tool-item">
                                <div 
                                  className="schema-tool-header"
                                  onClick={() => setExpandedTool(isExpanded ? null : toolName)}
                                >
                                  <div className="tool-info">
                                    <span className="tool-name">{tool.name}</span>
                                    <span className="tool-kind">{tool.kind.replace('_', ' ')}</span>
                                  </div>
                                  <div className="tool-toggle">{isExpanded ? '−' : '+'}</div>
                                </div>

                                <AnimatePresence>
                                  {isExpanded && (
                                    <motion.div 
                                      className="schema-tool-details"
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                    >
                                      <p className="tool-purpose">{tool.purpose}</p>
                                      
                                      <div className="tool-schema">
                                        <div className="schema-col-header">
                                          <span>Column</span>
                                          <span>Type</span>
                                        </div>
                                        {tool.columns?.map((col) => (
                                          <div key={col.column_name} className="schema-col-row">
                                            <span className="col-name">
                                              {col.column_name}
                                              {col.is_required_filter && <span className="col-req" title="Required Filter">*</span>}
                                            </span>
                                            <span className="col-type">{col.data_type}</span>
                                          </div>
                                        ))}
                                        {(!tool.columns || tool.columns.length === 0) && (
                                          <div className="schema-col-row empty">No columns discovered.</div>
                                        )}
                                      </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
