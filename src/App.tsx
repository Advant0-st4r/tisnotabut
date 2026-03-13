import React, { useState, useEffect } from 'react';
import { 
  LayoutDashboard, 
  Network, 
  BarChart3, 
  FileUp, 
  Download, 
  Settings, 
  ChevronRight, 
  Plus, 
  Search,
  Zap,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  Loader2,
  Image as ImageIcon,
  User as UserIcon
} from 'lucide-react';
import { 
  BrowserRouter as Router, 
  Routes, 
  Route, 
  Link, 
  useLocation,
  useNavigate
} from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  LineChart,
  Line,
  AreaChart,
  Area
} from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import Papa from 'papaparse';
import { generateMetrics, generateVisualization } from './services/geminiService';
import { User, Capability, Metric } from './types';
import { DemoProvider, useDemo } from './DemoContext';
import { useLanguage } from './LanguageContext';
import { validateCSVHeaders } from '../packages/validator/csv.js';

// --- Utility ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Components ---

const Sidebar = ({ user, onLogout }: { user: User | null, onLogout: () => void }) => {
  const location = useLocation();
  const { language, toggleLanguage, t } = useLanguage();
  
  const menuItems = [
    { id: 'dashboard', icon: LayoutDashboard, label: t('nav.dashboard'), path: '/' },
    { id: 'capabilities', icon: Network, label: t('nav.capabilities'), path: '/capabilities' },
    { id: 'processes', icon: BarChart3, label: t('nav.processes'), path: '/processes' },
    { id: 'visualization', icon: ImageIcon, label: t('nav.visualization'), path: '/visualization' },
    { id: 'upload', icon: FileUp, label: t('nav.upload'), path: '/upload' },
    { id: 'export', icon: Download, label: t('nav.export'), path: '/export' },
    { id: 'settings', icon: Settings, label: t('nav.settings'), path: '/settings' },
  ];

  return (
    <div className="w-64 bg-panel text-text-hi h-screen fixed start-0 top-0 flex flex-col border-e border-border">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 bg-amber flex items-center justify-center">
          <Zap className="w-5 h-5 text-black fill-current" />
        </div>
        <span className="font-display font-black uppercase tracking-widest text-2xl text-amber">Cap<span className="text-text-dim font-light">Map</span></span>
      </div>
      
      <nav className="flex-1 px-4 py-6 space-y-1">
        {menuItems.map((item) => (
          <Link
            key={item.path}
            id={`nav-${item.id}`}
            to={item.path}
            className={cn(
              "flex items-center gap-3 px-4 py-3 transition-all duration-200 group font-mono text-xs uppercase tracking-widest",
              location.pathname === item.path 
                ? "bg-amber text-black font-medium" 
                : "text-text-dim hover:text-text-hi hover:bg-white/5"
            )}
          >
            <item.icon className={cn("w-4 h-4", location.pathname === item.path ? "text-black" : "text-text-dim group-hover:text-text-hi")} />
            {item.label}
          </Link>
        ))}
      </nav>
      
      <div className="p-6 border-t border-border space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10-full bg-border flex items-center justify-center text-sm font-bold font-display uppercase tracking-wider">
            {user?.email[0].toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium truncate">{user?.email}</p>
            <p className="text-xs text-text-dim truncate capitalize">{user?.role}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={toggleLanguage}
            className="flex-1 bg-border/50 hover:bg-border text-text py-2 text-xs font-medium transition-colors border border-border"
          >
            {language === 'en' ? 'العربية' : 'English'}
          </button>
          <button 
            onClick={onLogout}
            className="flex-1 bg-red/10 hover:bg-red/20 text-red py-2 text-xs font-medium transition-colors border border-red/10"
          >
            {t('nav.logout')}
          </button>
        </div>
      </div>
    </div>
  );
};

const PageHeader = ({ title, description, actions }: { title: string; description?: string; actions?: React.ReactNode }) => (
  <div className="flex items-center justify-between mb-8">
    <div>
      <h1 className="text-5xl font-black font-display uppercase tracking-wide text-text-hi mb-2">{title}</h1>
      {description && <p className="text-text-dim">{description}</p>}
    </div>
    {actions && <div className="flex items-center gap-3">{actions}</div>}
  </div>
);

const Card = ({ children, className, id }: { children: React.ReactNode; className?: string; id?: string }) => (
  <div id={id} className={cn("bg-surface border border-border p-8 relative", className)}>
    {children}
  </div>
);

// --- Pages ---

const Dashboard = () => {
  const { t } = useLanguage();
  const [dashboardData, setDashboardData] = useState<any>(null);

  useEffect(() => {
    fetch('/api/dashboard')
      .then(res => res.json())
      .then(data => setDashboardData(data))
      .catch(err => console.error(err));
  }, []);

  const data = dashboardData?.charts?.maturityTrend || [
    { name: 'Q1', value: 0 },
    { name: 'Q2', value: 0 },
    { name: 'Q3', value: 0 },
    { name: 'Q4', value: 0 },
  ];

  const domainData = dashboardData?.charts?.domainDistribution || [];

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader 
        title={t('dashboard.title')} 
        description={t('dashboard.desc')}
      />
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="flex flex-col justify-between h-40">
          <span className="text-text-dim text-sm font-medium uppercase tracking-wider">{t('dashboard.total_cap')}</span>
          <div className="flex items-end justify-between">
            <span className="text-4xl font-bold font-display uppercase tracking-wider text-text-hi">{dashboardData?.metrics?.totalCapabilities || 0}</span>
            <div className="flex items-center text-amber text-sm font-medium">
              <ArrowUpRight className="w-4 h-4 me-1" />
              +12%
            </div>
          </div>
        </Card>
        <Card className="flex flex-col justify-between h-40">
          <span className="text-text-dim text-sm font-medium uppercase tracking-wider">{t('dashboard.maturity')}</span>
          <div className="flex items-end justify-between">
            <span className="text-4xl font-bold font-display uppercase tracking-wider text-text-hi">{dashboardData?.metrics?.avgMaturity || '0.0'}</span>
            <div className="flex items-center text-amber text-sm font-medium">
              <ArrowUpRight className="w-4 h-4 me-1" />
              +0.4
            </div>
          </div>
        </Card>
        <Card className="flex flex-col justify-between h-40">
          <span className="text-text-dim text-sm font-medium uppercase tracking-wider">{t('dashboard.ai_gen')}</span>
          <div className="flex items-end justify-between">
            <span className="text-4xl font-bold font-display uppercase tracking-wider text-text-hi">{dashboardData?.metrics?.totalSystems || 0}</span>
            <div className="flex items-center text-text-dim text-sm font-medium">
              {t('dashboard.daily_limit')}: 500
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="h-96">
          <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-6">{t('dashboard.growth')}</h3>
          <ResponsiveContainer width="100%" height="85%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#F0A500" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#F0A500" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A2F38" vertical={false} />
              <XAxis dataKey="name" stroke="#5A6070" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#5A6070" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#14171C', border: '1px solid #2A2F38', borderRadius: '0px' }}
                itemStyle={{ color: '#E8ECF2' }}
              />
              <Area type="monotone" dataKey="value" stroke="#F0A500" fillOpacity={1} fill="url(#colorValue)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>
        
        <Card className="h-96">
          <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-6">{t('dashboard.domain_dist')}</h3>
          <ResponsiveContainer width="100%" height="85%">
            <BarChart data={domainData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A2F38" vertical={false} />
              <XAxis dataKey="name" stroke="#5A6070" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#5A6070" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#14171C', border: '1px solid #2A2F38', borderRadius: '0px' }}
                itemStyle={{ color: '#E8ECF2' }}
              />
              <Bar dataKey="value" fill="#F0A500" radius={[0, 0, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>
    </motion.div>
  );
};

const Capabilities = ({ user }: { user: User }) => {
  const { t } = useLanguage();
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCap, setSelectedCap] = useState<Capability | null>(null);
  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    fetch('/api/capabilities')
      .then(res => res.json())
      .then(data => {
        setCapabilities(data);
        setLoading(false);
      });
  }, []);

  const handleGenerateMetrics = async (cap: Capability) => {
    setSelectedCap(cap);
    setGenerating(true);
    try {
      const result = await generateMetrics(cap.name, cap.domain, cap.id);
      setMetrics(result);
      // Log interaction
      fetch('/api/user/interactions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: user.id,
          eventType: 'metric_generation',
          entityType: 'capability',
          entityId: cap.id,
          metadata: { name: cap.name }
        })
      });
    } catch (error) {
      console.error(error);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <PageHeader 
        title={t('cap.title')} 
        description={t('cap.desc')}
        actions={
          <button className="bg-amber text-black px-4 py-2  font-medium flex items-center gap-2 hover:bg-[#FFB800] transition-colors">
            <Plus className="w-5 h-5" />
            {t('cap.new')}
          </button>
        }
      />

      {/* Capability Column Info Box */}
      <div className="border-s-2 border-amber bg-amber/5 px-5 py-4 space-y-3" id="capability-info-box">
        <p className="text-xs font-bold font-mono uppercase tracking-widest text-amber">Specify "Capabilities"</p>
        <p className="text-sm text-text-dim leading-relaxed">
          A clearly defined ability of a system, team, or process to consistently perform a specific function to a measurable standard.{' '}
          <span className="text-text-dim/60">This column is mandatory — it identifies <em>what must be done</em> before performance, maturity, or outcomes can be assessed.</span>
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-text-dim uppercase tracking-wider font-medium">Example:</span>
          <code className="bg-black/40 border border-border px-2 py-0.5 text-amber text-xs">Customer query resolution</code>
        </div>
        <div className="pt-1">
          <p className="text-xs text-text-dim uppercase tracking-wider font-medium mb-2">Sample metrics</p>
          <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1">
            {['Average resolution time', 'First-contact resolution rate', 'Error or rework rate', 'Customer satisfaction score (CSAT)', 'Escalation rate'].map(m => (
              <li key={m} className="flex items-center gap-2 text-xs text-text-dim">
                <span className="w-1 h-1 bg-amber/60 rounded-full flex-shrink-0" />
                {m}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <Card className="p-0 overflow-hidden" id="capability-list">
            <div className="p-4 border-b border-border flex items-center gap-3">
              <Search className="w-5 h-5 text-text-dim" />
              <input 
                type="text" 
                placeholder={t('cap.search')} 
                className="bg-transparent border-none outline-none text-text-hi flex-1 text-sm"
              />
            </div>
            <div className="divide-y divide-white/5">
              {loading ? (
                <div className="p-12 flex justify-center"><Loader2 className="w-8 h-8 animate-spin text-amber" /></div>
              ) : capabilities.length === 0 ? (
                <div className="p-12 text-center text-text-dim">{t('cap.empty')}</div>
              ) : capabilities.map(cap => (
                <div 
                  key={cap.id} 
                  className={cn(
                    "p-4 flex items-center justify-between hover:bg-white/5 transition-colors cursor-pointer group",
                    selectedCap?.id === cap.id && "bg-white/5"
                  )}
                  onClick={() => handleGenerateMetrics(cap)}
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10  bg-border flex items-center justify-center font-bold font-display uppercase tracking-wider text-amber">
                      {cap.maturity_level}
                    </div>
                    <div>
                      <h4 className="text-text-hi font-medium">{cap.name}</h4>
                      <p className="text-xs text-text-dim">{cap.domain}</p>
                    </div>
                  </div>
                  <ChevronRight className="w-5 h-5 text-text-dim group-hover:text-text-hi transition-colors" />
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          <AnimatePresence mode="wait">
            {selectedCap ? (
              <motion.div
                key={selectedCap.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
              >
                <Card className="sticky top-6" id="metrics-panel">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi">{t('cap.metrics_title')} {selectedCap.name}</h3>
                    {generating && <Loader2 className="w-5 h-5 animate-spin text-amber" />}
                  </div>
                  
                  <div className="space-y-4">
                    {generating ? (
                      Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="h-16 bg-border/50 animate-pulse " />
                      ))
                    ) : metrics.length > 0 ? (
                      metrics.map((m, i) => (
                        <div key={i} className="p-4 bg-border/30  border border-border flex items-center justify-between">
                          <div>
                            <p className="text-xs text-text-dim uppercase tracking-wider font-medium">{m.name}</p>
                            <p className="text-2xl font-bold font-display uppercase tracking-wider text-text-hi">{m.value}{m.unit}</p>
                          </div>
                          {m.trend === 'up' ? <ArrowUpRight className="text-amber" /> : 
                           m.trend === 'down' ? <ArrowDownRight className="text-red" /> : 
                           <Minus className="text-text-dim" />}
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12">
                        <BarChart3 className="w-12 h-12 text-border-hi mx-auto mb-4" />
                        <p className="text-text-dim text-sm">{t('cap.metrics_empty')}</p>
                      </div>
                    )}
                  </div>
                </Card>
              </motion.div>
            ) : (
              <Card className="h-full flex flex-col items-center justify-center text-center py-24">
                <Network className="w-16 h-16 text-border mb-6" />
                <h3 className="text-text-hi font-medium mb-2">{t('cap.no_selection')}</h3>
                <p className="text-text-dim text-sm max-w-[200px]">{t('cap.no_selection_desc')}</p>
              </Card>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
};

const Visualization = () => {
  const { t } = useLanguage();
  
  const VISUALIZATION_TEMPLATES = [
    {
      id: 'capability-map',
      name: t('viz.tpl.cap_map.name'),
      prompt: t('viz.tpl.cap_map.prompt')
    },
    {
      id: 'value-chain',
      name: t('viz.tpl.val_chain.name'),
      prompt: t('viz.tpl.val_chain.prompt')
    },
    {
      id: 'dependency-graph',
      name: t('viz.tpl.dep_graph.name'),
      prompt: t('viz.tpl.dep_graph.prompt')
    }
  ];

  const [selectedTemplate, setSelectedTemplate] = useState(VISUALIZATION_TEMPLATES[0].id);
  const [prompt, setPrompt] = useState(VISUALIZATION_TEMPLATES[0].prompt);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/visualizations')
      .then(res => res.json())
      .then(data => setHistory(data))
      .catch(err => console.error(err));
  }, []);

  // Update prompt when language changes
  useEffect(() => {
    const template = VISUALIZATION_TEMPLATES.find(t => t.id === selectedTemplate);
    if (template) {
      setPrompt(template.prompt);
    }
  }, [t, selectedTemplate]);

  const handleTemplateChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const templateId = e.target.value;
    setSelectedTemplate(templateId);
    const template = VISUALIZATION_TEMPLATES.find(t => t.id === templateId);
    if (template) {
      setPrompt(template.prompt);
    }
  };

  const handleGenerate = async () => {
    if (!prompt) return;
    setLoading(true);
    try {
      const url = await generateVisualization(prompt);
      setImageUrl(url);
      // Refresh history
      fetch('/api/visualizations')
        .then(res => res.json())
        .then(data => setHistory(data))
        .catch(err => console.error(err));
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <PageHeader 
        title={t('viz.title')} 
        description={t('viz.desc')}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1" id="viz-controls">
          <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-6">{t('viz.builder')}</h3>
          <div className="space-y-4">
            <div>
              <label className="text-xs text-text-dim uppercase font-bold font-display uppercase tracking-wider mb-2 block">{t('viz.type')}</label>
              <select 
                value={selectedTemplate}
                onChange={handleTemplateChange}
                className="w-full bg-panel border border-border  p-3 text-text-hi text-sm outline-none focus:border-amber transition-colors"
              >
                {VISUALIZATION_TEMPLATES.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-text-dim uppercase font-bold font-display uppercase tracking-wider mb-2 block">{t('viz.context')}</label>
              <textarea 
                id="viz-prompt"
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="e.g. A multi-layered capability map for a retail organization focusing on supply chain and logistics..."
                className="w-full bg-panel border border-border  p-3 text-text-hi text-sm outline-none focus:border-amber transition-colors h-32 resize-none"
              />
            </div>
            <button 
              id="viz-generate-btn"
              onClick={handleGenerate}
              disabled={loading || !prompt}
              className="w-full bg-amber text-black py-3  font-bold font-display uppercase tracking-wider flex items-center justify-center gap-2 hover:bg-[#FFB800] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5 fill-current" />}
              {t('viz.generate')}
            </button>
          </div>
        </Card>

        <Card className="lg:col-span-2 min-h-[500px] flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi">{t('viz.preview')}</h3>
            {imageUrl && (
              <button className="text-amber text-sm font-medium flex items-center gap-2 hover:underline">
                <Download className="w-4 h-4" />
                {t('viz.download')}
              </button>
            )}
          </div>
          
          <div className="flex-1 bg-black/20  border border-dashed border-border flex items-center justify-center relative overflow-hidden">
            {loading ? (
              <div className="text-center">
                <Loader2 className="w-12 h-12 animate-spin text-amber mx-auto mb-4" />
                <p className="text-text-dim">{t('viz.loading')}</p>
              </div>
            ) : imageUrl ? (
              <img src={imageUrl} alt="Generated Visualization" className="max-w-full max-h-full object-contain" referrerPolicy="no-referrer" />
            ) : (
              <div className="text-center">
                <ImageIcon className="w-16 h-16 text-border mx-auto mb-4" />
                <p className="text-text-dim">{t('viz.empty')}</p>
              </div>
            )}
          </div>
        </Card>
      </div>

      {history.length > 0 && (
        <Card>
          <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-6">History</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {history.map((item) => (
              <div key={item.id} className="bg-black/20 border border-border  p-4 cursor-pointer hover:border-amber transition-colors" onClick={() => setImageUrl(item.image_data)}>
                <img src={item.image_data} alt="History" className="w-full h-32 object-cover  mb-3" referrerPolicy="no-referrer" />
                <p className="text-xs text-text-dim truncate" title={item.prompt}>{item.prompt}</p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </motion.div>
  );
};

const Upload = () => {
  const { t } = useLanguage();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; rowsProcessed?: number; error?: string } | null>(null);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    
    // Pre-Validation
    if (!file.name.toLowerCase().endsWith('.csv')) {
      setResult({ success: false, error: 'File must be a .csv' });
      return;
    }
    if (file.size === 0) {
      setResult({ success: false, error: 'CSV is empty' });
      return;
    }

    setUploading(true);
    setResult(null);

    try {
      // Read file for pre-validation
      const text = await file.text();
      const parsed = Papa.parse(text, { header: true, skipEmptyLines: true });
      
      if (parsed.errors.length > 0 && parsed.errors[0].code !== 'TooFewFields') {
        setResult({ success: false, error: 'Invalid CSV format' });
        setUploading(false);
        return;
      }

      const validation = validateCSVHeaders(parsed.meta.fields || []);
      
      if (!validation.isValid) {
        setResult({ success: false, error: validation.error });
        setUploading(false);
        return;
      }

      const rows = parsed.data as any[];
      if (rows.length === 0) {
        setResult({ success: false, error: 'CSV must contain at least one row of data' });
        setUploading(false);
        return;
      }

      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/capabilities/bulk', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      
      if (!res.ok) {
        setResult({ success: false, error: data.error || 'Upload failed' });
      } else {
        setResult(data);
        setFile(null); // Clear file on success
      }
    } catch (error) {
      setResult({ success: false, error: 'Upload failed' });
    } finally {
      setUploading(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <PageHeader 
        title={t('upload.title')} 
        description={t('upload.desc')}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card className="h-full">
            <div 
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="border-2 border-dashed border-border  p-12 text-center hover:border-amber transition-colors cursor-pointer"
              onClick={() => document.getElementById('file-upload')?.click()}
            >
              <input 
                type="file" 
                id="file-upload" 
                className="hidden" 
                accept=".csv"
                onChange={(e) => e.target.files && setFile(e.target.files[0])}
              />
              <FileUp className="w-12 h-12 text-text-dim mx-auto mb-4" />
              <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-2">
                {file ? file.name : t('upload.drag')}
              </h3>
              <p className="text-text-dim text-sm">
                {file ? `${(file.size / 1024).toFixed(2)} KB` : t('upload.browse')}
              </p>
            </div>

            {result && (
              <div className={cn("mt-6 p-4  text-sm font-medium whitespace-pre-wrap", result.success ? "bg-amber-glow text-amber" : "bg-red/10 text-red")}>
                {result.success ? `${result.rowsProcessed} ${t('upload.processed')}` : result.error}
              </div>
            )}

            <div className="mt-8 flex items-center justify-between">
              <a 
                href="/sample.csv" 
                download="sample.csv"
                className="text-amber hover:text-amber text-sm font-medium transition-colors"
                id="download-sample-csv"
              >
                Download Sample CSV
              </a>
              <button 
                onClick={handleUpload}
                disabled={!file || uploading}
                className="bg-amber text-black px-6 py-3  font-bold font-display uppercase tracking-wider flex items-center gap-2 hover:bg-[#FFB800] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {uploading ? <Loader2 className="w-5 h-5 animate-spin" /> : <FileUp className="w-5 h-5" />}
                {t('upload.btn')}
              </button>
            </div>
          </Card>
        </div>

        <div className="lg:col-span-1">
          <Card className="h-full bg-surface/50 border-border">
            <h3 className="text-xl font-bold font-display uppercase tracking-wider text-text-hi mb-4">CSV Schema Requirements</h3>
            <div className="space-y-4 text-sm text-text-dim">
              <div>
                <p className="font-medium text-text mb-1">Minimum required column:</p>
                <code className="bg-black px-2 py-1 text-amber">Capability</code>
                <p className="text-xs mt-1">(or <code className="text-amber">name</code>)</p>
              </div>
              
              <div className="pt-4 border-t border-border">
                <p className="font-medium text-text mb-2">Optional but recommended columns:</p>
                <ul className="space-y-2">
                  <li><code className="bg-black px-2 py-1 text-text">IT System</code></li>
                  <li><code className="bg-black px-2 py-1 text-text">Business Process</code></li>
                  <li><code className="bg-black px-2 py-1 text-text">Owner</code></li>
                  <li><code className="bg-black px-2 py-1 text-text">Environment</code></li>
                </ul>
              </div>

              <div className="pt-4 border-t border-border">
                <p className="font-medium text-text mb-2">Validation Rules:</p>
                <ul className="list-disc list-inside space-y-1 text-xs">
                  <li>Header must exist in row 1</li>
                  <li>Header comparison is case-insensitive</li>
                  <li>Whitespace must be trimmed</li>
                </ul>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </motion.div>
  );
};

const Export = () => {
  const { t } = useLanguage();
  const [exporting, setExporting] = useState<string | null>(null);

  const handleExport = async (type: string) => {
    setExporting(type);
    try {
      const res = await fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      
      if (!res.ok) throw new Error('Export failed');
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `capmap_export.${type}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error(error);
    } finally {
      setExporting(null);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <PageHeader 
        title={t('export.title')} 
        description={t('export.desc')}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl">
        <Card className="flex flex-col items-center text-center p-8">
          <div className="w-16 h-16 bg-amber-glow  flex items-center justify-center mb-6">
            <Download className="w-8 h-8 text-amber" />
          </div>
          <h3 className="text-2xl font-black font-display uppercase tracking-wider text-text-hi mb-2">{t('export.csv.title')}</h3>
          <p className="text-text-dim text-sm mb-8">{t('export.csv.desc')}</p>
          <button 
            onClick={() => handleExport('csv')}
            disabled={exporting !== null}
            className="w-full bg-white/5 text-text-hi py-3  font-medium hover:bg-white/10 transition-colors flex items-center justify-center gap-2"
          >
            {exporting === 'csv' ? <Loader2 className="w-5 h-5 animate-spin" /> : t('export.csv.btn')}
          </button>
        </Card>

        <Card className="flex flex-col items-center text-center p-8">
          <div className="w-16 h-16 bg-amber-glow  flex items-center justify-center mb-6">
            <BarChart3 className="w-8 h-8 text-amber" />
          </div>
          <h3 className="text-2xl font-black font-display uppercase tracking-wider text-text-hi mb-2">{t('export.xlsx.title')}</h3>
          <p className="text-text-dim text-sm mb-8">{t('export.xlsx.desc')}</p>
          <button 
            onClick={() => handleExport('xlsx')}
            disabled={exporting !== null}
            className="w-full bg-amber text-black py-3  font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-colors flex items-center justify-center gap-2"
          >
            {exporting === 'xlsx' ? <Loader2 className="w-5 h-5 animate-spin" /> : t('export.xlsx.btn')}
          </button>
        </Card>
      </div>
    </motion.div>
  );
};

const Login = ({ onLogin }: { onLogin: (user: User) => void }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const { startDemo } = useDemo();
  const { language, toggleLanguage, t } = useLanguage();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const user = await res.json();
      onLogin(user);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDemo = () => {
    startDemo();
    onLogin({ id: 'demo_user', email: 'demo@capmap.ai', role: 'demo' });
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-6 relative">
      <div className="absolute top-6 end-6 flex items-center gap-4">
        <button 
          onClick={toggleLanguage}
          className="font-mono text-xs tracking-[0.1em] uppercase bg-transparent text-text-dim px-5 py-2.5 border border-border-hi font-medium hover:text-text-hi hover:border-text-dim transition-all"
        >
          {language === 'en' ? 'العربية' : 'English'}
        </button>
        <button 
          onClick={handleDemo}
          className="font-mono text-xs tracking-[0.1em] uppercase bg-transparent text-text-dim px-5 py-2.5 border border-border-hi font-medium hover:text-text-hi hover:border-text-dim transition-all flex items-center gap-2"
        >
          <Zap className="w-4 h-4 text-amber fill-current" />
          {t('login.demo')}
        </button>
      </div>
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }} 
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-md"
      >
        <div className="text-center mb-8">
          <div className="font-display font-black uppercase tracking-widest text-5xl text-amber mb-6">
            Cap<span className="text-text-dim font-light">Map</span>
          </div>
          <h1 className="text-4xl font-black font-display uppercase tracking-wider text-text-hi mb-2">{t('login.title')}</h1>
          <p className="text-text-dim">{t('login.subtitle')}</p>
        </div>
        
        <Card className="p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="text-xs text-text-dim uppercase font-mono tracking-widest mb-2 block">{t('login.email')}</label>
              <input 
                type="email" 
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full bg-panel border border-border p-4 text-text-hi outline-none focus:border-amber transition-all font-mono text-sm"
              />
            </div>
            <button 
              type="submit"
              disabled={loading}
              className="w-full font-mono text-xs tracking-[0.1em] uppercase bg-amber text-black py-4 font-medium hover:bg-[#FFB800] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading && <Loader2 className="w-5 h-5 animate-spin" />}
              {t('login.submit')}
            </button>
          </form>
        </Card>
        
        <p className="text-center mt-8 text-xs text-text-dim font-mono">
          {t('login.terms')}
        </p>
      </motion.div>
    </div>
  );
};

const Onboarding = () => {
  const [step, setStep] = useState(0);
  const [isVisible, setIsVisible] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useLanguage();

  const steps = [
    {
      title: t('onboarding.step1.title'),
      description: t('onboarding.step1.desc'),
      target: "nav-dashboard",
      action: t('onboarding.step1.btn'),
      path: "/"
    },
    {
      title: t('onboarding.step2.title'),
      description: t('onboarding.step2.desc'),
      target: "nav-upload",
      action: t('onboarding.step2.btn'),
      path: "/upload"
    },
    {
      title: t('onboarding.step3.title'),
      description: t('onboarding.step3.desc'),
      target: "nav-capabilities",
      action: t('onboarding.step3.btn'),
      path: "/capabilities"
    },
    {
      title: t('onboarding.step4.title'),
      description: t('onboarding.step4.desc'),
      target: "nav-visualization",
      action: t('onboarding.step4.btn'),
      path: "/visualization"
    },
    {
      title: t('onboarding.step5.title'),
      description: t('onboarding.step5.desc'),
      target: "nav-dashboard",
      action: t('onboarding.step5.btn'),
      path: "/"
    }
  ];

  useEffect(() => {
    const hasSeenTutorial = localStorage.getItem('capmap_tutorial_seen');
    if (hasSeenTutorial) setIsVisible(false);
  }, []);

  const handleNext = () => {
    if (step < steps.length - 1) {
      const nextStep = step + 1;
      setStep(nextStep);
      navigate(steps[nextStep].path);
    } else {
      setIsVisible(false);
      localStorage.setItem('capmap_tutorial_seen', 'true');
    }
  };

  if (!isVisible) return null;

  const currentStep = steps[step];
  const targetElement = document.getElementById(currentStep.target);
  const rect = targetElement?.getBoundingClientRect();

  return (
    <div className="fixed inset-0 z-[100] pointer-events-none">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm pointer-events-auto" />
      
      <AnimatePresence>
        <motion.div
          key={step}
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          className="absolute z-[110] pointer-events-auto"
          style={{
            top: rect ? rect.top + rect.height / 2 : '50%',
            left: rect ? rect.right + 20 : '50%',
            transform: rect ? 'translateY(-50%)' : 'translate(-50%, -50%)'
          }}
        >
          <div className="w-80 bg-surface border border-amber/30  p-6 shadow-2xl shadow-amber/10">
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-1">
                {steps.map((_, i) => (
                  <div 
                    key={i} 
                    className={cn(
                      "h-1-full transition-all duration-300",
                      i === step ? "w-6 bg-amber" : "w-2 bg-border"
                    )} 
                  />
                ))}
              </div>
              <span className="text-[10px] font-bold font-display uppercase tracking-wider text-text-dim uppercase tracking-widest">{t('onboarding.step')} {step + 1} {t('onboarding.of')} {steps.length}</span>
            </div>
            
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{currentStep.title}</h4>
            <p className="text-text-dim text-sm mb-6 leading-relaxed">{currentStep.description}</p>
            
            <div className="flex items-center justify-between">
              <button 
                onClick={() => { setIsVisible(false); localStorage.setItem('capmap_tutorial_seen', 'true'); }}
                className="text-text-dim text-xs font-medium hover:text-text-hi transition-colors"
              >
                {t('onboarding.skip')}
              </button>
              <button 
                onClick={handleNext}
                className="bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all flex items-center gap-2"
              >
                {currentStep.action}
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
          
          {/* Tooltip Arrow */}
          {rect && (
            <div className="absolute start-[-8px] top-1/2 -translate-y-1/2 w-4 h-4 bg-surface border-s border-b border-amber/30 rotate-45" />
          )}
        </motion.div>
      </AnimatePresence>

      {/* Highlight Target */}
      {rect && (
        <motion.div 
          initial={false}
          animate={{
            top: rect.top - 4,
            left: rect.left - 4,
            width: rect.width + 8,
            height: rect.height + 8,
          }}
          className="absolute border-2 border-amber  z-[105] pointer-events-none shadow-[0_0_20px_rgba(240,165,0,0.3)]"
        />
      )}
    </div>
  );
};

const DemoWalkthrough = () => {
  const { demoState, advanceStep, completeDemo, setDatasetLoaded } = useDemo();
  const navigate = useNavigate();
  const location = useLocation();
  const [loadingDataset, setLoadingDataset] = useState(false);
  const { t } = useLanguage();

  if (!demoState.isActive) return null;

  const handleLoadDataset = async () => {
    setLoadingDataset(true);
    try {
      await fetch('/api/demo/load', { method: 'POST' });
      setDatasetLoaded(true);
      advanceStep(2);
      navigate('/capabilities');
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDataset(false);
    }
  };

  const renderStepContent = () => {
    switch (demoState.step) {
      case 1:
        return (
          <>
            <div className="flex items-start gap-3 mb-4 bg-white/5 p-3  border border-border">
              <div className="w-8 h-8-full bg-amber/20 flex items-center justify-center shrink-0">
                <UserIcon className="w-4 h-4 text-amber" />
              </div>
              <p className="text-sm text-text italic">
                {t('demo.step1.quote')}
              </p>
            </div>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step1.title')}</h4>
            <p className="text-text-dim text-sm mb-6 leading-relaxed">
              {t('demo.step1.desc')}
            </p>
            <button 
              onClick={handleLoadDataset}
              disabled={loadingDataset}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all flex items-center justify-center gap-2"
            >
              {loadingDataset ? <Loader2 className="w-4 h-4 animate-spin" /> : t('demo.step1.btn')}
            </button>
          </>
        );
      case 2:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step2.title')}</h4>
            <p className="text-text-dim text-sm mb-4 leading-relaxed">
              {t('demo.step2.desc')}
            </p>
            <div className="bg-black/30 p-3  mb-6 border border-border text-xs text-text">
              <span className="text-amber font-bold font-display uppercase tracking-wider">{t('demo.step2.insight')}</span> {t('demo.step2.insight_text')}
            </div>
            <button 
              onClick={() => advanceStep(3)}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step2.btn')}
            </button>
          </>
        );
      case 3:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step3.title')}</h4>
            <p className="text-text-dim text-sm mb-4 leading-relaxed">
              {t('demo.step3.desc')}
            </p>
            <div className="bg-black/30 p-3  mb-6 border border-border text-xs text-text">
              <div className="flex justify-between mb-1"><span>{t('demo.step3.powered')}</span> <span className="text-text-hi">AWS Lambda</span></div>
              <div className="flex justify-between mb-1"><span>{t('demo.step3.auto_ratio')}</span> <span className="text-amber">98% {t('demo.step3.high')}</span></div>
              <div className="flex justify-between"><span>{t('demo.step3.op_eff')}</span> <span className="text-amber">92% {t('demo.step3.high')}</span></div>
            </div>
            <button 
              onClick={() => advanceStep(4)}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step3.btn')}
            </button>
          </>
        );
      case 4:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step4.title')}</h4>
            <p className="text-text-dim text-sm mb-4 leading-relaxed">
              {t('demo.step4.desc')}
            </p>
            <div className="bg-red/10 p-3  mb-6 border border-red/20 text-xs text-text">
              <div className="flex justify-between mb-1"><span>{t('demo.step4.coupling')}</span> <span className="text-red">0.82 {t('demo.step3.high')}</span></div>
              <div className="flex justify-between"><span>{t('demo.step4.priority')}</span> <span className="text-red">{t('demo.step4.high')}</span></div>
            </div>
            <button 
              onClick={() => advanceStep(5)}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step4.btn')}
            </button>
          </>
        );
      case 5:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step5.title')}</h4>
            <p className="text-text-dim text-sm mb-4 leading-relaxed">
              {t('demo.step5.desc')}
            </p>
            <div className="bg-black/30 p-3  mb-6 border border-border text-xs">
              <div className="text-text-dim mb-1 uppercase font-bold font-display uppercase tracking-wider text-[10px]">{t('demo.step5.current')}</div>
              <div className="text-text mb-2">{t('demo.step4.coupling')} <span className="text-red">0.82</span></div>
              
              <div className="text-text-dim mb-1 uppercase font-bold font-display uppercase tracking-wider text-[10px]">{t('demo.step5.action')}</div>
              <div className="text-text-hi font-medium mb-2">{t('demo.step5.action_text')}</div>

              <div className="text-text-dim mb-1 uppercase font-bold font-display uppercase tracking-wider text-[10px]">{t('demo.step5.outcome')}</div>
              <div className="text-text mb-1">{t('demo.step4.coupling')} <span className="text-amber">0.41</span></div>
              <div className="text-text">{t('demo.step3.op_eff')} <span className="text-amber">+27%</span></div>
            </div>
            <button 
              onClick={() => { advanceStep(6); navigate('/visualization'); }}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step5.btn')}
            </button>
          </>
        );
      case 6:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step6.title')}</h4>
            <p className="text-text-dim text-sm mb-6 leading-relaxed">
              {t('demo.step6.desc')}
            </p>
            <button 
              onClick={() => { advanceStep(7); navigate('/export'); }}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step6.btn')}
            </button>
          </>
        );
      case 7:
        return (
          <>
            <h4 className="text-text-hi font-bold font-display uppercase tracking-wider text-xl mb-2">{t('demo.step7.title')}</h4>
            <p className="text-text-dim text-sm mb-6 leading-relaxed">
              {t('demo.step7.desc')}
            </p>
            <button 
              onClick={() => { completeDemo(); navigate('/'); }}
              className="w-full bg-amber text-black px-4 py-2  text-sm font-bold font-display uppercase tracking-wider hover:bg-[#FFB800] transition-all"
            >
              {t('demo.step7.btn')}
            </button>
          </>
        );
      default:
        return null;
    }
  };

  return (
    <div className="fixed bottom-6 end-6 z-[200]">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-[360px] bg-surface border border-amber/50  p-6 shadow-2xl shadow-amber/20"
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber fill-current" />
            <span className="text-xs font-bold font-display uppercase tracking-wider text-amber uppercase tracking-widest">{t('demo.mode')}</span>
          </div>
          <button onClick={completeDemo} className="text-text-dim hover:text-text-hi text-xs">{t('demo.exit')}</button>
        </div>
        {renderStepContent()}
      </motion.div>
    </div>
  );
};

// --- Main App ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const { t } = useLanguage();

  if (!user) {
    return (
      <DemoProvider user={user}>
        <Login onLogin={setUser} />
      </DemoProvider>
    );
  }

  return (
    <DemoProvider user={user}>
      <Router>
        <Onboarding />
        <DemoWalkthrough />
        <div className="min-h-screen bg-black text-text flex">
        <Sidebar user={user} onLogout={() => setUser(null)} />
        
        <main className="flex-1 ms-64 p-8 lg:p-12 max-w-7xl mx-auto w-full">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/capabilities" element={<Capabilities user={user} />} />
            <Route path="/visualization" element={<Visualization />} />
            <Route path="/processes" element={
              <div className="text-center py-24">
                <BarChart3 className="w-16 h-16 text-border mx-auto mb-6" />
                <h2 className="text-3xl font-black font-display uppercase tracking-wider text-text-hi mb-2">{t('nav.processes')}</h2>
                <p className="text-text-dim">{t('coming_soon')}</p>
              </div>
            } />
            <Route path="/upload" element={<Upload />} />
            <Route path="/export" element={<Export />} />
            <Route path="/settings" element={
              <div className="text-center py-24">
                <Settings className="w-16 h-16 text-border mx-auto mb-6" />
                <h2 className="text-3xl font-black font-display uppercase tracking-wider text-text-hi mb-2">{t('nav.settings')}</h2>
                <p className="text-text-dim">{t('settings.desc')}</p>
              </div>
            } />
          </Routes>
        </main>
      </div>
    </Router>
    </DemoProvider>
  );
}